module;
#include <cerrno>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
module state.snapshot;
import std;
import state.file;

namespace state {
    namespace {
        auto name_valid(std::string_view name) noexcept -> bool {
            return !name.empty() && name.size() <= 210 && name != "." && name != ".." &&
                name != "instance.lock" && !name.contains('/') && !name.contains('\0');
        }

        auto matches(std::span<std::byte const> bytes, Magic const& magic) noexcept -> bool {
            return bytes.size() >= magic.size() &&
                std::ranges::equal(bytes.first(magic.size()), std::as_bytes(std::span(magic)));
        }

        auto read_exact(int fd, std::span<std::byte> bytes) -> std::expected<void, StateError> {
            while (!bytes.empty()) {
                auto count = ::read(fd, bytes.data(), bytes.size());
                if (count < 0 && errno == EINTR) continue;
                if (count < 0) return failure(Stage::read, errno);
                if (count == 0) return std::unexpected(StateError{Stage::format});
                bytes = bytes.subspan(static_cast<std::size_t>(count));
            }
            return {};
        }

        auto expect_eof(int fd) -> std::expected<void, StateError> {
            char probe;
            ssize_t count;
            do { count = ::read(fd, &probe, 1); } while (count < 0 && errno == EINTR);
            if (count < 0) return failure(Stage::read, errno);
            if (count != 0) return std::unexpected(StateError{Stage::format});
            return {};
        }

        auto read_snapshot(int dir, SnapshotSpec const& spec)
            -> std::expected<std::optional<SnapshotData>, StateError> {
            File fd(::openat(dir, spec.name.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC));
            if (fd.get() < 0) {
                if (errno == ENOENT) return std::nullopt;
                return failure(Stage::open, errno);
            }
            struct stat info{};
            if (::fstat(fd.get(), &info) < 0) return failure(Stage::open, errno);
            if (!private_regular(info)) return failure(Stage::open, EACCES);
            auto size = static_cast<std::uint64_t>(info.st_size);
            if (size < spec.envelope.magic.size() || size > std::uint64_t(spec.envelope.max_payload) + header_bytes)
                return std::unexpected(StateError{Stage::format});

            EncodedHeader prefix{};
            auto initial = std::span(prefix).first<6>();
            auto begun = read_exact(fd.get(), initial);
            if (!begun) return std::unexpected(begun.error());
            if (spec.legacy_magic && matches(initial, *spec.legacy_magic)) {
                if (size > spec.envelope.max_payload) return std::unexpected(StateError{Stage::format});
                Bytes legacy(static_cast<std::size_t>(size));
                std::ranges::copy(initial, legacy.begin());
                auto read = read_exact(fd.get(), std::span(legacy).subspan(initial.size()));
                if (!read) return std::unexpected(read.error());
                auto end = expect_eof(fd.get());
                if (!end) return std::unexpected(end.error());
                return SnapshotData{{}, std::move(legacy), true};
            }
            auto rest = read_exact(fd.get(), std::span(prefix).subspan(initial.size()));
            if (!rest) return std::unexpected(rest.error());
            auto header = decode_header(prefix, spec.envelope);
            if (!header) return std::unexpected(header.error());
            if (size != std::uint64_t(header->payload_bytes) + header_bytes)
                return std::unexpected(StateError{Stage::format});
            Bytes payload(header->payload_bytes);
            auto read = read_exact(fd.get(), payload);
            if (!read) return std::unexpected(read.error());
            auto end = expect_eof(fd.get());
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

        auto remove_stage(int dir, std::string const& name) -> std::expected<void, StateError> {
            if (::unlinkat(dir, name.c_str(), 0) < 0 && errno != ENOENT)
                return failure(Stage::remove_stage, errno);
            return {};
        }

        auto write_all(int fd, std::span<std::byte const> bytes) noexcept -> std::expected<void, StateError> {
            while (!bytes.empty()) {
                auto count = ::write(fd, bytes.data(), bytes.size());
                if (count < 0 && errno == EINTR) continue;
                if (count <= 0) return failure(Stage::write, count == 0 ? EIO : errno);
                bytes = bytes.subspan(static_cast<std::size_t>(count));
            }
            return {};
        }

        auto write_stage(int fd, EncodedHeader const& header, std::span<std::byte const> payload)
            -> std::expected<void, StateError> {
            if (::fchmod(fd, 0600) < 0) return failure(Stage::create_stage, errno);
            auto prefix = write_all(fd, header);
            if (!prefix) return prefix;
            auto body = write_all(fd, payload);
            if (!body) return body;
            if (sync_file(fd) < 0) return failure(Stage::sync_stage, errno);
            return {};
        }
    }

    auto validate_snapshot(SnapshotSpec const& spec) noexcept -> std::expected<void, StateError> {
        if (!name_valid(spec.name) || !name_valid(spec.staging_name) || spec.name == spec.staging_name ||
            spec.envelope.schema_version == 0 || spec.envelope.tier < Tier::authority ||
            spec.envelope.tier > Tier::secret || spec.legacy_magic == spec.envelope.magic)
            return std::unexpected(StateError{Stage::validate});
        return {};
    }

    auto inspect_snapshot(int directory, SnapshotSpec const& spec)
        -> std::expected<std::optional<SnapshotData>, StateError> {
        auto valid=validate_snapshot(spec);
        if (!valid) return std::unexpected(valid.error());
        return read_snapshot(directory,spec);
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
        if (::renameat2(dir, spec.name.c_str(), dir, destination.c_str(), RENAME_NOREPLACE) < 0)
            return with_context(failure(Stage::isolate, errno).error(), error);
        error.replaced = true;
        if (sync_file(dir) < 0)
            return with_context(failure(Stage::sync_directory, errno, true).error(), error);
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

        auto cleared = remove_stage(dir, spec.staging_name);
        if (!cleared) return std::unexpected(cleared.error());
        File stage(::openat(dir, spec.staging_name.c_str(),
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
        if (stage.get() < 0) return failure(Stage::create_stage, errno);

        auto abort = [&](StateError error) -> std::unexpected<StateError> {
            auto cleanup = remove_stage(dir, spec.staging_name);
            if (!cleanup) return with_context(cleanup.error(), error);
            return std::unexpected(error);
        };
        auto written = write_stage(stage.get(), *prefix, payload);
        auto closed = ::close(stage.release());
        if (!written) return abort(written.error());
        if (closed < 0) return abort(failure(Stage::close_stage, errno).error());

        auto publish = [&]() -> std::expected<void, StateError> {
            if (::renameat(dir, spec.staging_name.c_str(), dir, spec.name.c_str()) < 0)
                return failure(Stage::replace, errno);
            return {};
        };
        auto published = barrier ? barrier->publish(epoch, publish) : publish();
        if (!published) return abort(published.error());
        if (visible) (*visible)();
        if (sync_file(dir) < 0)
            return CommitReceipt{CommitState::uncertain, failure(Stage::sync_directory, errno, true).error()};
        return CommitReceipt{CommitState::committed, {}};
    }
}
