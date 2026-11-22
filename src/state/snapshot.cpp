module state.snapshot;
import std;
import state.file;

namespace state {
    namespace {
        auto name_valid(std::string_view name) noexcept -> bool {
            return !name.empty() && name.size() <= 210 && name != "." && name != ".." &&
                name != "instance.lock" && !name.contains('/') && !name.contains('\\') && !name.contains('\0');
        }

        auto matches(std::span<std::byte const> bytes, Magic const& magic) noexcept -> bool {
            return bytes.size() >= magic.size() &&
                std::ranges::equal(bytes.first(magic.size()), std::as_bytes(std::span(magic)));
        }

        auto read_exact(NativeHandle fd, std::span<std::byte> bytes) -> std::expected<void, StateError> {
            auto got = read_handle(fd, bytes, Stage::read);
            if (!got) return std::unexpected(got.error());
            if (*got != bytes.size()) return std::unexpected(StateError{Stage::format});
            return {};
        }

        auto expect_eof(NativeHandle fd) -> std::expected<void, StateError> {
            std::byte probe{};
            auto got = read_handle(fd, std::span(&probe, 1), Stage::read);
            if (!got) return std::unexpected(got.error());
            if (*got != 0) return std::unexpected(StateError{Stage::format});
            return {};
        }

        auto read_snapshot(NativeHandle dir, SnapshotSpec const& spec)
            -> std::expected<std::optional<SnapshotData>, StateError> {
            auto fd = open_dir_read(dir, spec.name, true, Stage::open);
            if (!fd) {
                if (fd.error().os == std::errc::no_such_file_or_directory) return std::nullopt;
                return std::unexpected(fd.error());
            }
            auto size_opt = handle_size(fd->get(), Stage::open);
            if (!size_opt) return std::unexpected(size_opt.error());
            auto size = *size_opt;
            if (size < spec.envelope.magic.size() || size > std::uint64_t(spec.envelope.max_payload) + header_bytes)
                return std::unexpected(StateError{Stage::format});

            EncodedHeader prefix{};
            auto initial = std::span(prefix).first<6>();
            auto begun = read_exact(fd->get(), initial);
            if (!begun) return std::unexpected(begun.error());
            if (spec.legacy_magic && matches(initial, *spec.legacy_magic)) {
                if (size > spec.envelope.max_payload) return std::unexpected(StateError{Stage::format});
                Bytes legacy(static_cast<std::size_t>(size));
                std::ranges::copy(initial, legacy.begin());
                auto read = read_exact(fd->get(), std::span(legacy).subspan(initial.size()));
                if (!read) return std::unexpected(read.error());
                auto end = expect_eof(fd->get());
                if (!end) return std::unexpected(end.error());
                return SnapshotData{{}, std::move(legacy), true};
            }
            auto rest = read_exact(fd->get(), std::span(prefix).subspan(initial.size()));
            if (!rest) return std::unexpected(rest.error());
            auto header = decode_header(prefix, spec.envelope);
            if (!header) return std::unexpected(header.error());
            if (size != std::uint64_t(header->payload_bytes) + header_bytes)
                return std::unexpected(StateError{Stage::format});
            Bytes payload(header->payload_bytes);
            auto read = read_exact(fd->get(), payload);
            if (!read) return std::unexpected(read.error());
            auto end = expect_eof(fd->get());
            if (!end) return std::unexpected(end.error());
            auto checked = verify_payload(prefix, *header, payload, spec.envelope.fingerprint);
            if (!checked) return std::unexpected(checked.error());
            return SnapshotData{*header, std::move(payload)};
        }

        auto with_context(StateError error, StateError preceding) -> std::unexpected<StateError> {
            error.preceding = preceding.stage;
            error.preceding_os = preceding.os;
            return std::unexpected(error);
        }

        auto write_stage(NativeHandle fd, EncodedHeader const& header, std::span<std::byte const> payload)
            -> std::expected<void, StateError> {
            auto prefix = write_handle_all(fd, header, Stage::write);
            if (!prefix) return prefix;
            auto body = write_handle_all(fd, payload, Stage::write);
            if (!body) return body;
            return sync_handle(fd, Stage::sync_stage);
        }
    }

    auto validate_snapshot(SnapshotSpec const& spec) noexcept -> std::expected<void, StateError> {
        if (!name_valid(spec.name) || !name_valid(spec.staging_name) || spec.name == spec.staging_name ||
            spec.envelope.schema_version == 0 || spec.envelope.tier < Tier::authority ||
            spec.envelope.tier > Tier::secret || spec.legacy_magic == spec.envelope.magic)
            return std::unexpected(StateError{Stage::validate});
        return {};
    }

    auto inspect_snapshot(NativeHandle directory, SnapshotSpec const& spec)
        -> std::expected<std::optional<SnapshotData>, StateError> {
        auto valid = validate_snapshot(spec);
        if (!valid) return std::unexpected(valid.error());
        return read_snapshot(directory, spec);
    }

    auto load_snapshot(InstanceLock const& instance, SnapshotSpec const& spec, DamagePolicy policy)
        -> std::expected<std::optional<SnapshotData>, StateError> {
        auto valid = validate_snapshot(spec);
        if (!valid) return std::unexpected(valid.error());
        auto dir = instance.directory();
        auto result = read_snapshot(dir, spec);
        if (result || policy == DamagePolicy::preserve) return result;
        auto error = result.error();
        if (error.stage != Stage::format && error.stage != Stage::checksum &&
            !(error.stage == Stage::version && spec.envelope.tier == Tier::cache)) return result;

        auto now = std::chrono::system_clock::now().time_since_epoch();
        auto suffix = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
        auto destination = std::format("{}.corrupt.{}", spec.name, suffix);
        if (auto moved = rename_dir_file(dir, spec.name, destination, true, Stage::isolate); !moved)
            return with_context(moved.error(), error);
        error.replaced = true;
        if (auto synced = sync_handle(dir, Stage::sync_directory, true); !synced)
            return with_context(synced.error(), error);
        return std::unexpected(error);
    }

    auto commit_snapshot(InstanceLock const& instance, SnapshotSpec const& spec, std::uint64_t revision,
                         std::uint64_t epoch, std::span<std::byte const> payload, ClearEpoch* barrier,
                         std::optional<OnVisible> visible)
        -> std::expected<CommitReceipt, StateError> {
        auto valid = validate_snapshot(spec);
        if (!valid || payload.size() > spec.envelope.max_payload || revision == 0)
            return std::unexpected(StateError{Stage::validate});
        if (barrier && epoch != barrier->current()) return std::unexpected(StateError{Stage::stale_epoch});

        auto dir = instance.directory();
        {
            auto existing = read_snapshot(dir, spec);
            if (!existing) return std::unexpected(existing.error());
            if (*existing) {
                auto const& old = (**existing).header;
                if (epoch < old.clear_epoch) return std::unexpected(StateError{Stage::stale_epoch});
                if (revision <= old.revision) return std::unexpected(StateError{Stage::revision});
            }
        }
        auto prefix = encode_header({spec.envelope.magic, spec.envelope.schema_version, spec.envelope.tier,
            0, static_cast<std::uint32_t>(payload.size()), revision, epoch}, payload, spec.envelope.fingerprint);
        if (!prefix) return std::unexpected(prefix.error());

        auto cleared = unlink_dir_file(dir, spec.staging_name, Stage::remove_stage);
        if (!cleared) return std::unexpected(cleared.error());
        auto stage = open_dir_stage(dir, spec.staging_name, Stage::create_stage);
        if (!stage) return std::unexpected(stage.error());

        auto abort = [&](StateError error) -> std::unexpected<StateError> {
            auto cleanup = unlink_dir_file(dir, spec.staging_name, Stage::remove_stage);
            if (!cleanup) return with_context(cleanup.error(), error);
            return std::unexpected(error);
        };
        auto written = write_stage(stage->get(), *prefix, payload);
        auto closed = close_file(*stage, Stage::close_stage);
        if (!written) return abort(written.error());
        if (!closed) return abort(closed.error());

        auto publish = [&]() -> std::expected<void, StateError> {
            return rename_dir_file(dir, spec.staging_name, spec.name, false, Stage::replace);
        };
        auto published = barrier ? barrier->publish(epoch, publish) : publish();
        if (!published) return abort(published.error());
        if (visible) (*visible)();
        if (auto synced = sync_handle(dir, Stage::sync_directory, true); !synced)
            return CommitReceipt{CommitState::uncertain, synced.error()};
        return CommitReceipt{CommitState::committed, {}};
    }
}
