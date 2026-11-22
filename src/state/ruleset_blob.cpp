module;
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
module state.ruleset_storage;
import std;
import state.file;
import crypto;
import nexus.thirdparty.blake3;

namespace state {
    namespace {
        constexpr char staging[] = ".blob.next";

        auto blob_name(Fingerprint const& hash) -> std::string {
            std::string name;
            name.reserve(69);
            constexpr std::string_view hex = "0123456789abcdef";
            for (auto byte : hash) {
                auto value = std::to_integer<unsigned>(byte);
                name += hex[value >> 4];
                name += hex[value & 0xf];
            }
            name += ".blob";
            return name;
        }

        auto blob_filename(std::string_view name) noexcept -> bool {
            return name.size() == 69 && name.ends_with(".blob") &&
                std::ranges::all_of(name.substr(0, 64), [](char ch) {
                    return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
                });
        }

        auto remove(int directory, char const* name, Stage stage) -> std::expected<void, StateError> {
            if (::unlinkat(directory, name, 0) < 0 && errno != ENOENT) return failure(stage, errno);
            return {};
        }

        auto write_blob(int fd, std::string_view body) -> std::expected<void, StateError> {
            if (::fchmod(fd, 0600) < 0) return failure(Stage::create_stage, errno);
            while (!body.empty()) {
                auto count = ::write(fd, body.data(), body.size());
                if (count < 0 && errno == EINTR) continue;
                if (count <= 0) return failure(Stage::write, count < 0 ? errno : EIO);
                body.remove_prefix(static_cast<std::size_t>(count));
            }
            if (sync_file(fd) < 0) return failure(Stage::sync_stage, errno);
            return {};
        }
    }

    auto rule_blake3(std::string_view body) noexcept -> Fingerprint {
        nex::blake3::blake3_hasher state;
        nex::blake3::blake3_hasher_init(&state);
        nex::blake3::blake3_hasher_update(&state, body.data(), body.size());
        Fingerprint hash;
        nex::blake3::blake3_hasher_finalize(&state, reinterpret_cast<std::uint8_t*>(hash.data()), hash.size());
        return hash;
    }

    auto rule_sha256(std::string_view body) -> std::expected<Fingerprint, StateError> {
        auto bytes = std::span(reinterpret_cast<std::uint8_t const*>(body.data()), body.size());
        auto hash = ::crypto::digest(::crypto::Hash::sha256, bytes);
        Fingerprint result{};
        if (!hash || hash->size() != result.size()) return std::unexpected(StateError{Stage::digest});
        std::ranges::copy(std::as_bytes(std::span(*hash)), result.begin());
        return result;
    }

    auto read_rule_blob(int directory, RulesetMetadata const& metadata) -> std::expected<std::string, StateError> {
        auto name = blob_name(metadata.content_blake3);
        File fd(::openat(directory, name.c_str(), O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC));
        if (fd.get() < 0) return failure(Stage::open, errno);
        struct stat info{};
        if (::fstat(fd.get(), &info) < 0) return failure(Stage::read, errno);
        if (!private_regular(info) || info.st_size != metadata.size_bytes)
            return std::unexpected(StateError{Stage::format});
        std::string body(metadata.size_bytes, '\0');
        auto unread = std::span(body);
        while (!unread.empty()) {
            auto count = ::read(fd.get(), unread.data(), unread.size());
            if (count < 0 && errno == EINTR) continue;
            if (count < 0) return failure(Stage::read, errno);
            if (count == 0) return std::unexpected(StateError{Stage::format});
            unread = unread.subspan(static_cast<std::size_t>(count));
        }
        char extra;
        ssize_t count;
        do { count = ::read(fd.get(), &extra, 1); } while (count < 0 && errno == EINTR);
        if (count < 0) return failure(Stage::read, errno);
        if (count != 0 || rule_blake3(body) != metadata.content_blake3)
            return std::unexpected(StateError{Stage::checksum});
        auto sha = rule_sha256(body);
        if (!sha) return std::unexpected(sha.error());
        if (*sha != metadata.content_sha256) return std::unexpected(StateError{Stage::checksum});
        return body;
    }

    auto remove_rule_blob(int directory, Fingerprint const& hash) -> std::expected<void, StateError> {
        return remove(directory, blob_name(hash).c_str(), Stage::remove_blob);
    }

    auto write_rule_blob(int directory, Fingerprint const& hash, std::string_view body) -> std::expected<void, StateError> {
        auto name = blob_name(hash);
        auto cleared = remove(directory, staging, Stage::remove_stage);
        if (!cleared) return cleared;
        File file(::openat(directory, staging, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
        if (file.get() < 0) return failure(Stage::create_stage, errno);
        auto abort = [&](StateError error) -> std::unexpected<StateError> {
            auto deleted = remove(directory, staging, Stage::remove_stage);
            if (deleted) return std::unexpected(error);
            auto failure = deleted.error();
            failure.preceding = error.stage;
            failure.preceding_os = error.os;
            return std::unexpected(failure);
        };
        auto written = write_blob(file.get(), body);
        auto closed = ::close(file.release());
        if (!written) return abort(written.error());
        if (closed < 0) return abort(failure(Stage::close_stage, errno).error());
        if (::renameat(directory, staging, directory, name.c_str()) < 0)
            return abort(failure(Stage::replace, errno).error());
        if (sync_file(directory) < 0) return failure(Stage::sync_directory, errno, true);
        return {};
    }

    auto sweep_rule_blobs(int directory, std::span<RulesetRow const> rows) -> std::expected<void, StateError> {
        File fd(::openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        if (fd.get() < 0) return failure(Stage::scan, errno);
        auto* stream = ::fdopendir(fd.get());
        if (!stream) return failure(Stage::scan, errno);
        (void)fd.release();
        std::unique_ptr<DIR, decltype(&::closedir)> entries(stream, ::closedir);
        std::vector<std::string> retained;
        for (auto const& row : rows) retained.push_back(blob_name(row.metadata.content_blake3));
        bool changed = false;
        for (;;) {
            errno = 0;
            auto* entry = ::readdir(stream);
            if (!entry) {
                if (errno != 0) return failure(Stage::scan, errno);
                break;
            }
            std::string_view name(entry->d_name);
            if (name != staging && (!blob_filename(name) || std::ranges::find(retained, name) != retained.end()))
                continue;
            auto deleted = remove(directory, entry->d_name, Stage::remove_blob);
            if (!deleted) return deleted;
            changed = true;
        }
        if (changed && sync_file(directory) < 0) return failure(Stage::sync_directory, errno, true);
        return {};
    }
}
