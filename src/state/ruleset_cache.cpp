module state.ruleset_cache;
import std;
import state.ruleset_storage;
import state.lock;

namespace state {
    namespace {
        auto valid_limits(RulesetCacheLimits limits) noexcept -> bool {
            return limits.max_entries && limits.max_entries <= max_rule_entries && limits.max_bytes;
        }

        auto resident(std::span<RulesetRow const> rows, RulesetMetadata const* incoming = nullptr) noexcept
            -> std::uint64_t {
            std::uint64_t bytes = incoming ? incoming->size_bytes : 0;
            for (std::size_t index = 0; index < rows.size(); ++index) {
                auto const& value = rows[index].metadata;
                if (incoming && incoming->content_blake3 == value.content_blake3) continue;
                if (std::ranges::none_of(rows.first(index), [&](auto const& row) {
                    return row.metadata.content_blake3 == value.content_blake3;
                })) bytes += value.size_bytes;
            }
            return bytes;
        }

        auto trim(RulesetIndex& index, RulesetCacheLimits limits, RulesetMetadata const* incoming = nullptr) -> bool {
            bool changed = false;
            while (index.rows.size() + (incoming ? 1 : 0) > limits.max_entries ||
                   resident(index.rows, incoming) > limits.max_bytes) {
                index.rows.erase(index.rows.begin());
                changed = true;
            }
            return changed;
        }

        auto discard_digest(InstanceLock const& lock, RulesetIndex& index, Fingerprint const& digest,
                            std::optional<StateError> preceding = {}) -> std::expected<void, StateError> {
            // Delete first so a real unlink error remains the reported failure.
            // A crash before the index update leaves a recoverable missing blob.
            auto removed = remove_rule_blob(lock.directory(), digest);
            if (!removed) {
                if (preceding) {
                    removed.error().preceding = preceding->stage;
                    removed.error().preceding_os = preceding->os;
                }
                return removed;
            }
            std::erase_if(index.rows, [&](auto const& row) { return row.metadata.content_blake3 == digest; });
            return save_rulesets(lock, index);
        }

        auto damaged(StateError const& error) noexcept -> bool {
            return error.stage == Stage::checksum || error.stage == Stage::format ||
                (error.stage == Stage::open && (error.os == std::errc::no_such_file_or_directory ||
                                               error.os == std::errc::too_many_symbolic_link_levels));
        }
    }

    auto RulesetCache::lookup(this RulesetCache const& self, RulesetKey const& key)
        -> std::expected<RulesetLookup, StateError> {
        if (!valid_limits(self.limits_) || !valid_rule_key(key)) return std::unexpected(StateError{Stage::validate});
        auto lock = InstanceLock::open_rulesets(self.root_);
        if (!lock) return std::unexpected(lock.error());
        auto index = load_rulesets(*lock);
        if (!index) return std::unexpected(index.error());
        if (trim(*index, self.limits_)) {
            auto saved = save_rulesets(*lock, *index);
            if (!saved) return std::unexpected(saved.error());
        }
        auto swept = sweep_rule_blobs(lock->directory(), index->rows);
        if (!swept) return std::unexpected(swept.error());
        auto row = std::ranges::find(index->rows, key, &RulesetRow::key);
        if (row == index->rows.end()) return RulesetLookup{index->epoch, {}};

        auto body = read_rule_blob(lock->directory(), row->metadata);
        if (body) return RulesetLookup{index->epoch, CachedRuleset{std::move(row->metadata), std::move(*body)}};
        if (!damaged(body.error())) return std::unexpected(body.error());
        auto digest = row->metadata.content_blake3;
        auto repaired = discard_digest(*lock, *index, digest, body.error());
        if (!repaired) return std::unexpected(repaired.error());
        return RulesetLookup{index->epoch, {}};
    }

    auto RulesetCache::store(this RulesetCache const& self, RulesetKey const& key,
                            std::uint64_t epoch, RulesetMetadata metadata, std::string_view body)
        -> std::expected<void, StateError> {
        if (!valid_limits(self.limits_) || !valid_rule_key(key) || body.empty())
            return std::unexpected(StateError{Stage::validate});
        if (body.size() > max_rule_blob || body.size() > self.limits_.max_bytes)
            return std::unexpected(StateError{Stage::capacity});
        metadata.size_bytes = static_cast<std::uint32_t>(body.size());
        if (!valid_rule_metadata(metadata)) return std::unexpected(StateError{Stage::validate});
        metadata.content_blake3 = rule_blake3(body);
        auto sha = rule_sha256(body);
        if (!sha) return std::unexpected(sha.error());
        metadata.content_sha256 = *sha;

        auto lock = InstanceLock::open_rulesets(self.root_);
        if (!lock) return std::unexpected(lock.error());
        auto index = load_rulesets(*lock);
        if (!index) return std::unexpected(index.error());
        if (index->epoch != epoch) return std::unexpected(StateError{Stage::stale_epoch});
        auto existing = std::ranges::find(index->rows, key, &RulesetRow::key);
        bool changed = existing != index->rows.end() &&
            existing->metadata.content_blake3 != metadata.content_blake3;
        if (existing != index->rows.end()) index->rows.erase(existing);
        changed |= trim(*index, self.limits_, &metadata);
        if (changed) {
            auto saved = save_rulesets(*lock, *index);
            if (!saved) return saved;
        }
        // Keep the incoming digest if already resident, including same-key
        // revalidation. The index refers to it only after blob verification.
        index->rows.push_back({key, std::move(metadata)});
        auto swept = sweep_rule_blobs(lock->directory(), index->rows);
        if (!swept) return swept;
        auto const& incoming = index->rows.back().metadata;
        auto checked = read_rule_blob(lock->directory(), incoming);
        if (!checked) {
            if (!damaged(checked.error())) return std::unexpected(checked.error());
            if (checked.error().os != std::errc::no_such_file_or_directory) {
                auto removed = remove_rule_blob(lock->directory(), incoming.content_blake3);
                if (!removed) return removed;
            }
            auto written = write_rule_blob(lock->directory(), incoming.content_blake3, body);
            if (!written) return written;
        }
        return save_rulesets(*lock, *index);
    }

    auto RulesetCache::discard(this RulesetCache const& self, RulesetKey const& key, std::uint64_t epoch,
                              Fingerprint const& content) -> std::expected<void, StateError> {
        auto lock = InstanceLock::open_rulesets(self.root_);
        if (!lock) return std::unexpected(lock.error());
        auto index = load_rulesets(*lock);
        if (!index) return std::unexpected(index.error());
        if (index->epoch != epoch) return std::unexpected(StateError{Stage::stale_epoch});
        auto row = std::ranges::find(index->rows, key, &RulesetRow::key);
        if (row == index->rows.end() || row->metadata.content_blake3 != content) return {};
        index->rows.erase(row);
        if (std::ranges::none_of(index->rows, [&](auto const& remaining) {
            return remaining.metadata.content_blake3 == content;
        })) return discard_digest(*lock, *index, content);
        auto saved = save_rulesets(*lock, *index);
        if (!saved) return saved;
        return sweep_rule_blobs(lock->directory(), index->rows);
    }

    auto RulesetCache::clear(this RulesetCache const& self) -> std::expected<void, StateError> {
        auto lock = InstanceLock::open_rulesets(self.root_);
        if (!lock) return std::unexpected(lock.error());
        auto index = load_rulesets(*lock);
        if (!index) return std::unexpected(index.error());
        ClearEpoch epoch(index->epoch);
        auto next = epoch.advance();
        if (!next) return std::unexpected(next.error());
        index->epoch = *next;
        index->rows.clear();
        auto saved = save_rulesets(*lock, *index);
        if (!saved) return saved;
        return sweep_rule_blobs(lock->directory(), index->rows);
    }
}
