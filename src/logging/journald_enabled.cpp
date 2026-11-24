module;
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
module logging.sink;
import std;
import proxy.v4;
import logging.core;

namespace logging {
    namespace {
        constexpr std::string_view kJournalSocketPath = "/run/systemd/journal/socket";

        auto append_text_or_binary(char*& out, char* limit, std::string_view key,
            std::string_view value) noexcept -> bool {
            bool const multiline = value.find('\n') != value.npos || value.find('\0') != value.npos;
            std::size_t const need = key.size() + 1 + (multiline ? 8 : 0) + value.size() + 1;
            if (static_cast<std::size_t>(limit - out) < need) return false;
            std::memcpy(out, key.data(), key.size());
            out += key.size();
            if (!multiline) {
                *out++ = '=';
            } else {
                *out++ = '\n';
                std::uint64_t len = value.size();
                for (unsigned i = 0; i < 8; ++i) {
                    *out++ = static_cast<char>((len >> (i * 8)) & 0xFFu);
                }
            }
            if (!value.empty()) {
                std::memcpy(out, value.data(), value.size());
                out += value.size();
            }
            *out++ = '\n';
            return true;
        }

        template<class T>
        auto append_uint_field(char*& out, char* limit, std::string_view key, T value) noexcept -> bool {
            std::array<char, 32> buf{};
            auto res = std::to_chars(buf.data(), buf.data() + buf.size(), value);
            if (res.ec != std::errc{}) return false;
            return append_text_or_binary(out, limit, key,
                std::string_view(buf.data(), static_cast<std::size_t>(res.ptr - buf.data())));
        }

        struct JournalSink {
            int fd_ = -1;

            JournalSink() noexcept = default;
            JournalSink(JournalSink const&) = delete;
            auto operator=(JournalSink const&) -> JournalSink& = delete;
            JournalSink(JournalSink&& other) noexcept : fd_(std::exchange(other.fd_, -1)) {}
            auto operator=(JournalSink&& other) noexcept -> JournalSink& {
                if (this != &other) {
                    if (fd_ >= 0) ::close(fd_);
                    fd_ = std::exchange(other.fd_, -1);
                }
                return *this;
            }
            ~JournalSink() {
                if (fd_ >= 0) ::close(fd_);
            }

            auto ensure_socket() noexcept -> int {
                if (fd_ >= 0) return 0;
                fd_ = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
                return fd_ >= 0 ? 0 : errno;
            }

            auto write(this JournalSink& self, std::span<SinkRecord const> records) noexcept -> SinkResult {
                std::error_code failure;
                if (int err = self.ensure_socket(); err != 0) {
                    return std::unexpected(std::error_code{err, std::generic_category()});
                }
                sockaddr_un addr{};
                addr.sun_family = AF_UNIX;
                std::memcpy(addr.sun_path, kJournalSocketPath.data(), kJournalSocketPath.size() + 1);
                auto const addr_len = static_cast<socklen_t>(
                    offsetof(sockaddr_un, sun_path) + kJournalSocketPath.size() + 1);
#ifdef MSG_NOSIGNAL
                constexpr int kFlags = MSG_NOSIGNAL;
#else
                constexpr int kFlags = 0;
#endif
                for (auto const& record : records) {
                    constexpr std::array priorities{"7", "7", "6", "4", "3", "2"};
                    auto line = record.line;
                    if (line.ends_with('\n')) line.remove_suffix(1);
                    if (line.size() > 4096) line = line.substr(0, 4096);
                    std::array<char, 8192> packet{};
                    char* out = packet.data();
                    char* const limit = packet.data() + packet.size();
                    bool const encoded =
                        append_text_or_binary(out, limit, "MESSAGE", line) &&
                        append_text_or_binary(out, limit, "PRIORITY",
                            priorities[std::to_underlying(record.level)]) &&
                        append_text_or_binary(out, limit, "NEXUS_DOMAIN", name(record.domain)) &&
                        append_uint_field(out, limit, "NEXUS_EVENT", record.event_code) &&
                        append_uint_field(out, limit, "NEXUS_GEN", record.context.generation) &&
                        append_uint_field(out, limit, "NEXUS_WORKER", record.context.worker_id) &&
                        append_uint_field(out, limit, "NEXUS_SESSION", record.context.session_id);
                    if (!encoded) {
                        if (!failure) failure = {EMSGSIZE, std::generic_category()};
                        continue;
                    }
                    auto const used = static_cast<std::size_t>(out - packet.data());
                    for (;;) {
                        auto sent = ::sendto(self.fd_, packet.data(), used, kFlags,
                            reinterpret_cast<sockaddr const*>(&addr), addr_len);
                        if (sent == static_cast<ssize_t>(used)) break;
                        if (sent < 0 && errno == EINTR) continue;
                        if (!failure) failure = {sent < 0 ? errno : EMSGSIZE, std::generic_category()};
                        break;
                    }
                }
                if (failure) return std::unexpected(failure);
                return {};
            }
            auto reopen(this JournalSink&) noexcept -> SinkResult { return {}; }
        };
    }

    auto journald_available() noexcept -> bool { return true; }
    auto journald_sink() -> Sink { return pro::make_proxy<SinkFacade, JournalSink>(); }
}
