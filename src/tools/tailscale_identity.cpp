module;
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
module cli.tailscale_identity;
import std;
import crypto;

namespace cli::tailscale_identity {
    namespace {
        constexpr char file_name[] = "identity";
        constexpr std::array<std::uint8_t,8> magic{'N','X','T','A','I','L',1,0};
        using Record = std::array<std::uint8_t,72>;

        struct Fd {
            int value;
            ~Fd() { if (value >= 0) ::close(value); }
        };

        auto load_record(int dir, Record& record) -> std::expected<bool,std::string> {
            Fd file{::openat(dir, file_name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)};
            if (file.value < 0) {
                if (errno == ENOENT) return false;
                return std::unexpected("cannot open Tailscale identity");
            }
            struct stat stat{};
            if (::fstat(file.value, &stat) || !S_ISREG(stat.st_mode) || (stat.st_mode & 07777) != 0600 ||
                stat.st_uid != ::geteuid() || stat.st_nlink != 1 || stat.st_size != static_cast<off_t>(record.size()))
                return std::unexpected("invalid Tailscale identity permissions or size");
            auto remaining = std::span(record);
            std::span<std::uint8_t> input = remaining;
            while (!input.empty()) {
                auto count = ::read(file.value,input.data(),input.size());
                if (count < 0 && errno == EINTR) continue;
                if (count <= 0) return std::unexpected("cannot read complete Tailscale identity");
                input = input.subspan(static_cast<std::size_t>(count));
            }
            std::uint8_t extra{};
            ssize_t excess;
            do { excess = ::read(file.value, &extra, 1); } while (excess < 0 && errno == EINTR);
            if (excess || !std::ranges::equal(remaining.first(magic.size()),magic))
                return std::unexpected("invalid Tailscale identity record");
            return true;
        }

        auto store(int directory, Record const& record) -> bool {
            constexpr char staging[] = ".identity-new";
            if (::unlinkat(directory, staging, 0) && errno != ENOENT) return false;
            Fd file{::openat(directory, staging, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600)};
            if (file.value < 0) return false;
            auto remaining = std::span<const std::uint8_t>(record);
            while (!remaining.empty()) {
                auto count = ::write(file.value,remaining.data(),remaining.size());
                if (count < 0 && errno == EINTR) continue;
                if (count <= 0) break;
                remaining = remaining.subspan(static_cast<std::size_t>(count));
            }
            if (remaining.empty() && ::fsync(file.value) == 0 &&
                ::renameat(directory, staging, directory, file_name) == 0) return ::fsync(directory) == 0;
            (void)::unlinkat(directory, staging, 0);
            return false;
        }
    }

    Keys::Keys(Keys&& other) noexcept
        : machine(std::move(other.machine)), node(std::move(other.node)), directory(std::exchange(other.directory,-1)) {}
    Keys::~Keys() { if (directory >= 0) ::close(directory); }

    auto load(std::string_view state_dir, bool ephemeral, bool check) -> std::expected<Keys,std::string> {
        Keys keys;
        Record record{};
        struct Wipe { Record& bytes; ~Wipe() { crypto::cleanse(bytes); } } wipe{record};
        bool existing = false;
        if (!ephemeral) {
            auto path = std::string(state_dir);
            keys.directory = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (keys.directory < 0) return std::unexpected("cannot open Tailscale state-dir");
            struct stat stat{};
            if (::fstat(keys.directory, &stat) || stat.st_uid != ::geteuid() || (stat.st_mode & 07777) != 0700)
                return std::unexpected("Tailscale state-dir requires owner and mode 0700");
            if (::flock(keys.directory, (check ? LOCK_SH : LOCK_EX) | LOCK_NB))
                return std::unexpected("Tailscale state-dir is locked");
            auto loaded = load_record(keys.directory, record);
            if (!loaded) return std::unexpected(loaded.error());
            existing = *loaded;
        }
        if (!existing) {
            if (check) return keys;
            std::ranges::copy(magic,record.begin());
            if (!crypto::random_bytes(std::span(record).subspan(magic.size())))
                return std::unexpected("cannot generate Tailscale identity");
            if (!ephemeral && !store(keys.directory, record)) return std::unexpected("cannot persist Tailscale identity");
        }
        auto payload = std::span(record).subspan(magic.size());
        auto nonzero = [](auto bytes) { return std::ranges::any_of(bytes, [](auto byte) { return byte != 0; }); };
        if (!nonzero(payload.first(32)) || !nonzero(payload.last(32)) ||
            crypto::constant_time_equal(payload.first(32),payload.last(32)))
            return std::unexpected("invalid Tailscale identity keys");
        std::ranges::copy(payload.first(32),keys.machine.writable().begin());
        std::ranges::copy(payload.last(32),keys.node.writable().begin());
        return keys;
    }
}
