module state.ruleset_storage;
import std;
import crypto;
import state.snapshot;
import state.file;

namespace state {
    namespace {
        const SnapshotSpec index_file{"index.state", ".index.next",
            {.magic={'N','X','R','S','0','1'}, .tier=Tier::cache, .max_payload=16 * 1024 * 1024}};

        auto safe_text(std::string_view value) noexcept -> bool {
            return std::ranges::none_of(value, [](unsigned char ch) { return ch < 0x20 || ch == 0x7f; });
        }

        auto append(Bytes& bytes, std::uint64_t value, std::size_t size) -> void {
            for (std::size_t i = 0; i < size; ++i) {
                bytes.push_back(static_cast<std::byte>(value & 0xff));
                value >>= 8;
            }
        }

        auto append(Bytes& bytes, std::string_view value) -> void {
            append(bytes, value.size(), 2);
            bytes.append_range(std::as_bytes(std::span(value)));
        }

        struct Reader {
            std::span<std::byte const> rest;
            bool bad = false;

            auto take(this Reader& self, std::size_t size) noexcept -> std::span<std::byte const> {
                if (size > self.rest.size()) {
                    self.bad = true;
                    return {};
                }
                auto part = self.rest.first(size);
                self.rest = self.rest.subspan(size);
                return part;
            }

            auto number(this Reader& self, std::size_t size) noexcept -> std::uint64_t {
                auto part = self.take(size);
                std::uint64_t value = 0;
                for (auto byte : part | std::views::reverse)
                    value = (value << 8) | std::to_integer<unsigned>(byte);
                return value;
            }

            auto text(this Reader& self) -> std::string {
                auto part = self.take(self.number(2));
                if (part.empty()) return {};
                return {reinterpret_cast<char const*>(part.data()), part.size()};
            }

            auto hash(this Reader& self) noexcept -> Fingerprint {
                Fingerprint result{};
                std::ranges::copy(self.take(result.size()), result.begin());
                return result;
            }
        };

        auto fresh_epoch() noexcept -> std::expected<std::uint64_t, StateError> {
            std::array<std::uint8_t, 8> raw{};
            if (!crypto::random_bytes(raw)) return std::unexpected(StateError{Stage::read, std::make_error_code(std::errc::io_error)});
            std::uint64_t value = 0;
            for (auto b : raw) value = (value << 8) | b;
            return (value & (std::numeric_limits<std::uint64_t>::max() >> 1)) | 1;
        }
    }

    auto valid_rule_key(RulesetKey const& key) noexcept -> bool {
        return key.parser_version != 0 && key.format >= RuleFormat::kdl && key.format <= RuleFormat::adguard &&
            key.canonical_url.starts_with("https://") && key.canonical_url.size() <= 2048 && safe_text(key.canonical_url);
    }

    auto valid_rule_metadata(RulesetMetadata const& value) noexcept -> bool {
        return value.etag.size() <= 512 && safe_text(value.etag) &&
            value.last_modified.size() <= 128 && safe_text(value.last_modified) &&
            value.response_target.starts_with('/') && value.response_target.size() <= 2048 &&
            safe_text(value.response_target) && value.fetched_at <= value.expires_at &&
            value.size_bytes > 0 && value.size_bytes <= max_rule_blob;
    }

    auto encode_rulesets(std::span<RulesetRow const> rows) -> Bytes {
        Bytes bytes;
        append(bytes, rows.size(), 2);
        for (auto const& [key, meta] : rows) {
            append(bytes, key.canonical_url);
            append(bytes, std::to_underlying(key.format), 1);
            append(bytes, key.parser_version, 4);
            bytes.append_range(key.scope);
            append(bytes, meta.etag);
            append(bytes, meta.last_modified);
            append(bytes, meta.response_target);
            bytes.append_range(meta.content_blake3);
            bytes.append_range(meta.content_sha256);
            append(bytes, meta.fetched_at, 8);
            append(bytes, meta.expires_at, 8);
            append(bytes, meta.size_bytes, 4);
        }
        return bytes;
    }

    auto decode_rulesets(std::span<std::byte const> bytes) -> std::expected<std::vector<RulesetRow>, StateError> {
        Reader source{bytes};
        auto size = source.number(2);
        if (size > max_rule_entries) return std::unexpected(StateError{Stage::format});
        std::vector<RulesetRow> rows;
        rows.reserve(size);
        struct RowKeyHash {
            std::vector<RulesetRow> const* rows;
            auto operator()(std::size_t i) const noexcept -> std::size_t {
                auto const& k = (*rows)[i].key;
                std::size_t h = std::hash<std::string_view>{}(k.canonical_url);
                h ^= (static_cast<std::size_t>(std::to_underlying(k.format)) << 32) ^ k.parser_version;
                std::uint64_t s0 = 0, s1 = 0;
                std::memcpy(&s0, k.scope.data(), 8);
                std::memcpy(&s1, k.scope.data() + 8, 8);
                return h ^ (static_cast<std::size_t>(s0) * 0x9e3779b97f4a7c15ull) ^ static_cast<std::size_t>(s1);
            }
        };
        struct RowKeyEq {
            std::vector<RulesetRow> const* rows;
            auto operator()(std::size_t a, std::size_t b) const noexcept -> bool { return (*rows)[a].key == (*rows)[b].key; }
        };
        std::unordered_set<std::size_t, RowKeyHash, RowKeyEq> seen(0, RowKeyHash{&rows}, RowKeyEq{&rows});
        seen.reserve(size);
        for (std::size_t n = 0; n < size; ++n) {
            RulesetKey key{source.text(), static_cast<RuleFormat>(source.number(1)),
                static_cast<std::uint32_t>(source.number(4)), source.hash()};
            RulesetMetadata meta{source.text(), source.text(), source.text(), source.hash(), source.hash(),
                source.number(8), source.number(8), static_cast<std::uint32_t>(source.number(4))};
            if (source.bad || !valid_rule_key(key) || !valid_rule_metadata(meta))
                return std::unexpected(StateError{Stage::format});
            rows.push_back({std::move(key), std::move(meta)});
            if (!seen.insert(n).second) return std::unexpected(StateError{Stage::format});
        }
        if (source.bad || !source.rest.empty()) return std::unexpected(StateError{Stage::format});
        return rows;
    }

    auto save_rulesets(InstanceLock const& directory, RulesetIndex& index) -> std::expected<void, StateError> {
        if (index.revision == std::numeric_limits<std::uint64_t>::max())
            return std::unexpected(StateError{Stage::revision});
        auto bytes = encode_rulesets(index.rows);
        auto receipt = commit_snapshot(directory, index_file, index.revision + 1, index.epoch, bytes);
        if (!receipt) return std::unexpected(receipt.error());
        if (receipt->error) return std::unexpected(*receipt->error);
        ++index.revision;
        return {};
    }

    auto inspect_rulesets(NativeHandle directory) -> std::expected<std::optional<std::size_t>,StateError> {
        auto loaded=inspect_snapshot(directory,index_file);
        if (!loaded) return std::unexpected(loaded.error());
        if (!*loaded) return std::nullopt;
        auto decoded=decode_rulesets((**loaded).payload);
        if (!decoded) return std::unexpected(decoded.error());
        return decoded->size();
    }

    auto load_rulesets(InstanceLock const& directory) -> std::expected<RulesetIndex, StateError> {
        auto loaded = load_snapshot(directory, index_file);
        std::optional<StateError> damaged;
        if (loaded && *loaded) {
            auto rows = decode_rulesets((**loaded).payload);
            if (rows && (**loaded).header.clear_epoch != 0)
                return RulesetIndex{(**loaded).header.revision, (**loaded).header.clear_epoch, std::move(*rows)};
            damaged = StateError{Stage::format};
        } else if (!loaded) {
            auto error = loaded.error();
            if (error.stage != Stage::format && error.stage != Stage::checksum && error.stage != Stage::version &&
                !(error.stage == Stage::open && error.os == std::errc::too_many_symbolic_link_levels))
                return std::unexpected(error);
            damaged = error;
        }
        if (damaged) {
            if (auto removed = unlink_dir_file(directory.directory(), index_file.name, Stage::remove_index); !removed) {
                auto error = removed.error();
                error.preceding = damaged->stage;
                error.preceding_os = damaged->os;
                return std::unexpected(error);
            }
        }
        auto epoch = fresh_epoch();
        if (!epoch) return std::unexpected(epoch.error());
        RulesetIndex index{0, *epoch, {}};
        auto saved = save_rulesets(directory, index);
        if (!saved) return std::unexpected(saved.error());
        return index;
    }
}
