module;
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <sddl.h>

module cli.control;
import std;
import platform.os_fs;

namespace cli {
    namespace {
        constexpr std::size_t kMaxRequest = 4096;
        constexpr std::size_t kMaxReply = 65536;
        constexpr std::size_t kMaxArgs = 16;

        struct PipeHandle {
            HANDLE handle = INVALID_HANDLE_VALUE;
            explicit PipeHandle(HANDLE h = INVALID_HANDLE_VALUE) noexcept : handle(h) {}
            ~PipeHandle() { reset(); }
            PipeHandle(PipeHandle const&) = delete;
            auto operator=(PipeHandle const&) -> PipeHandle& = delete;
            PipeHandle(PipeHandle&& o) noexcept : handle(std::exchange(o.handle, INVALID_HANDLE_VALUE)) {}
            auto operator=(PipeHandle&& o) noexcept -> PipeHandle& {
                if (this != &o) { reset(); handle = std::exchange(o.handle, INVALID_HANDLE_VALUE); }
                return *this;
            }
            auto reset() noexcept -> void {
                if (handle != INVALID_HANDLE_VALUE && handle != nullptr)
                    ::CloseHandle(std::exchange(handle, INVALID_HANDLE_VALUE));
            }
            explicit operator bool() const noexcept { return handle != INVALID_HANDLE_VALUE && handle != nullptr; }
        };

        auto to_wide(std::string_view utf8) -> std::wstring {
            if (utf8.empty()) return {};
            int len = ::MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
            std::wstring out(static_cast<std::size_t>(std::max(len, 0)), L'\0');
            if (len > 0) ::MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), out.data(), len);
            return out;
        }

        auto create_owner_pipe(std::wstring const& pipe_name, bool first_instance) -> PipeHandle {
            PSECURITY_DESCRIPTOR sd = nullptr;
            if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;OW)", SDDL_REVISION_1, &sd, nullptr))
                return {};
            SECURITY_ATTRIBUTES sa{sizeof(SECURITY_ATTRIBUTES), sd, FALSE};
            DWORD open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | (first_instance ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0);
            HANDLE raw = ::CreateNamedPipeW(
                pipe_name.c_str(), open_mode,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                4, static_cast<DWORD>(kMaxReply), static_cast<DWORD>(kMaxRequest), 0, &sa);
            ::LocalFree(sd);
            return PipeHandle(raw);
        }

        auto read_pipe_overlapped(HANDLE pipe, void* dst, DWORD cap, DWORD& got, DWORD timeout_ms) noexcept -> bool {
            got = 0;
            PipeHandle ev(::CreateEventW(nullptr, TRUE, FALSE, nullptr));
            if (!ev) return false;
            OVERLAPPED ol{};
            ol.hEvent = ev.handle;
            if (::ReadFile(pipe, dst, cap, &got, &ol)) return true;
            if (::GetLastError() != ERROR_IO_PENDING) return false;
            if (::WaitForSingleObject(ev.handle, timeout_ms) != WAIT_OBJECT_0) {
                (void)::CancelIoEx(pipe, &ol);
                (void)::GetOverlappedResult(pipe, &ol, &got, TRUE);
                return false;
            }
            return ::GetOverlappedResult(pipe, &ol, &got, FALSE) != 0;
        }

        auto write_pipe_overlapped(HANDLE pipe, void const* src, DWORD len, DWORD& wrote, DWORD timeout_ms) noexcept -> bool {
            wrote = 0;
            PipeHandle ev(::CreateEventW(nullptr, TRUE, FALSE, nullptr));
            if (!ev) return false;
            OVERLAPPED ol{};
            ol.hEvent = ev.handle;
            if (::WriteFile(pipe, src, len, &wrote, &ol)) return true;
            if (::GetLastError() != ERROR_IO_PENDING) return false;
            if (::WaitForSingleObject(ev.handle, timeout_ms) != WAIT_OBJECT_0) {
                (void)::CancelIoEx(pipe, &ol);
                (void)::GetOverlappedResult(pipe, &ol, &wrote, TRUE);
                return false;
            }
            return ::GetOverlappedResult(pipe, &ol, &wrote, FALSE) != 0;
        }

        auto dispatch_wire(std::string_view req, ControlHandler handler) -> std::string {
            auto format = [](std::string_view tag, std::string_view msg) {
                std::string out("NEXUS/1 ");
                out += tag;
                out += '\n';
                out += msg;
                if (!out.ends_with('\n')) out += '\n';
                if (out.size() > kMaxReply) return std::string("NEXUS/1 ERROR\ncontrol reply too large\n");
                return out;
            };
            if (!req.starts_with("NEXUS/1 ") || req.size() <= 8) return format("ERROR", "unsupported control frame");
            std::array<std::string_view, kMaxArgs> args{};
            std::size_t count = 0;
            auto rest = req.substr(8);
            while (!rest.empty() && count < kMaxArgs) {
                auto end = rest.find('\0');
                auto tok = end == std::string_view::npos ? rest : rest.substr(0, end);
                if (tok.empty()) return format("ERROR", "empty control argument");
                args[count++] = tok;
                if (end == std::string_view::npos) break;
                rest.remove_prefix(end + 1);
            }
            if (count == 0) return format("ERROR", "empty control request");
            auto res = handler(ControlRole::administrator, std::span(args.data(), count));
            return res ? format("OK", *res) : format("ERROR", res.error());
        }

        auto send_pipe_once(std::string_view pipe_utf8, std::span<std::string const> tokens)
            -> std::expected<std::string, std::pair<int, std::string>> {
            std::string req("NEXUS/1");
            for (std::size_t i = 0; i < tokens.size(); ++i) {
                if (tokens[i].empty() || req.size() + tokens[i].size() + 1 > kMaxRequest)
                    return std::unexpected(std::pair{2, std::string("invalid control argument")});
                req += (i == 0 ? ' ' : '\0');
                req += tokens[i];
            }
            auto wname = to_wide(pipe_utf8);
            std::array<char, kMaxReply> reply{};
            DWORD got = 0;
            if (!::CallNamedPipeW(wname.c_str(), req.data(), static_cast<DWORD>(req.size()),
                    reply.data(), static_cast<DWORD>(reply.size()), &got, 3000)) {
                return std::unexpected(std::pair{1, std::string("call control named pipe failed")});
            }
            std::string_view wire(reply.data(), got);
            if (wire.starts_with("NEXUS/1 OK\n")) return std::string(wire.substr(11));
            if (wire.starts_with("NEXUS/1 ERROR\n")) return std::unexpected(std::pair{1, std::string(wire.substr(14))});
            return std::unexpected(std::pair{1, std::string("unsupported control reply")});
        }
    }

    struct LocalControl::Impl {
        std::string pipe_utf8;
        std::wstring pipe_wide;
        PipeHandle listener;
        PipeHandle event;
        OVERLAPPED ol{};
        bool pending_connect = false;
        ControlDiagnostics diag;
    };

    LocalControl::LocalControl() noexcept = default;
    LocalControl::~LocalControl() { stop(); }

    auto LocalControl::start(std::string_view path, std::optional<std::uint32_t>) -> std::expected<void, std::string> {
        stop();
        auto norm = platform::normalize_windows_pipe_name(path);
        if (!norm) return std::unexpected("invalid Windows control pipe name");
        auto wide = to_wide(*norm);
        auto listener = create_owner_pipe(wide, true);
        if (!listener) return std::unexpected("create control named pipe failed");
        PipeHandle ev(::CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (!ev) return std::unexpected("create pipe event failed");
        auto impl = std::make_unique<Impl>();
        impl->pipe_utf8 = std::move(*norm);
        impl->pipe_wide = std::move(wide);
        impl->listener = std::move(listener);
        impl->event = std::move(ev);
        impl->ol.hEvent = impl->event.handle;
        if (::ConnectNamedPipe(impl->listener.handle, &impl->ol)) {
            ::SetEvent(impl->event.handle);
        } else if (::GetLastError() == ERROR_PIPE_CONNECTED) {
            ::SetEvent(impl->event.handle);
        } else if (::GetLastError() == ERROR_IO_PENDING) {
            impl->pending_connect = true;
        } else {
            return std::unexpected("listen control named pipe failed");
        }
        impl_ = std::move(impl);
        return {};
    }

    auto LocalControl::poll(ControlHandler handler) -> void {
        if (!impl_ || !impl_->listener) return;
        for (int iter = 0; iter < 16; ++iter) {
            if (impl_->pending_connect) {
                DWORD dummy = 0;
                if (!::GetOverlappedResult(impl_->listener.handle, &impl_->ol, &dummy, FALSE)) break;
                impl_->pending_connect = false;
            }
            std::array<char, kMaxRequest + 1> buf{};
            DWORD got = 0;
            bool read_ok = read_pipe_overlapped(impl_->listener.handle, buf.data(), static_cast<DWORD>(buf.size()), got, 2000);
            if (read_ok && got > 0 && got <= kMaxRequest) {
                ++impl_->diag.authorized;
                auto reply = dispatch_wire(std::string_view(buf.data(), got), handler);
                DWORD wrote = 0;
                if (!write_pipe_overlapped(impl_->listener.handle, reply.data(), static_cast<DWORD>(reply.size()), wrote, 2000) ||
                    wrote != reply.size())
                    ++impl_->diag.reply_failed;
                (void)::FlushFileBuffers(impl_->listener.handle);
            }
            (void)::DisconnectNamedPipe(impl_->listener.handle);
            ::ResetEvent(impl_->event.handle);
            impl_->ol = OVERLAPPED{};
            impl_->ol.hEvent = impl_->event.handle;
            if (::ConnectNamedPipe(impl_->listener.handle, &impl_->ol) || ::GetLastError() == ERROR_PIPE_CONNECTED) {
                ::SetEvent(impl_->event.handle);
            } else if (::GetLastError() == ERROR_IO_PENDING) {
                impl_->pending_connect = true;
                break;
            } else {
                break;
            }
        }
    }

    auto LocalControl::stop() noexcept -> void {
        if (impl_ && impl_->listener) {
            (void)::CancelIoEx(impl_->listener.handle, nullptr);
            if (impl_->pending_connect) {
                DWORD dummy = 0;
                (void)::GetOverlappedResult(impl_->listener.handle, &impl_->ol, &dummy, TRUE);
                impl_->pending_connect = false;
            }
        }
        impl_.reset();
    }

    auto LocalControl::active() const noexcept -> bool { return impl_ && impl_->listener; }
    auto LocalControl::listen_native_fd() const noexcept -> int { return -1; }
    auto LocalControl::next_poll_delay() const noexcept -> std::optional<std::chrono::milliseconds> {
        return std::nullopt;
    }
    auto LocalControl::instance() const noexcept -> std::string_view { return impl_ ? std::string_view(impl_->pipe_utf8) : std::string_view{}; }
    auto LocalControl::diagnostics() const noexcept -> ControlDiagnostics { return impl_ ? impl_->diag : ControlDiagnostics{}; }

    auto run_control(int argc, char** argv) -> int {
        if (argc < 3 || (argc == 2 && std::string_view(argv[1]) == "--help")) {
            std::cerr << "usage: nexus control <pipe> status|mode|connections|connection show <id>|close|close-any|close-all|select|probe|group-health|user-usage|reload|clear-cache|network-change|operation|events|diagnostics|log-level|logs [arguments]\n";
            return argc == 2 && std::string_view(argv[1]) == "--help" ? 0 : 2;
        }
        auto pipe = platform::normalize_windows_pipe_name(argv[1]);
        if (!pipe) {
            std::cerr << "invalid Windows control pipe name\n";
            return 2;
        }
        int first = 2;
        if (std::string_view(argv[2]) == "--server-uid") {
            if (argc < 5) { std::cerr << "expected --server-uid UID followed by a command\n"; return 2; }
            first = 4;
        }
        std::vector<std::string> tokens;
        auto cmd = std::string_view(argv[first]);
        if (cmd == "connection" && first + 2 < argc && std::string_view(argv[first + 1]) == "show" && first + 3 == argc) {
            tokens = {"connection", argv[first + 2]};
        } else {
            for (int i = first; i < argc; ++i) tokens.emplace_back(argv[i]);
        }
        auto res = send_pipe_once(*pipe, tokens);
        if (!res) {
            std::cerr << res.error().second << (res.error().second.ends_with('\n') ? "" : "\n");
            return res.error().first;
        }
        std::cout << *res;
        return 0;
    }
}
