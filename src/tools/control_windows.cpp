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
        constexpr std::size_t kPipeSlots = 4;

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
                static_cast<DWORD>(kPipeSlots), static_cast<DWORD>(kAsyncPipeMaxReply),
                static_cast<DWORD>(kAsyncPipeMaxRequest), 0, &sa);
            ::LocalFree(sd);
            return PipeHandle(raw);
        }

        struct WinPipeSlotHw {
            PipeHandle pipe;
            PipeHandle event;
            OVERLAPPED ol{};
        };

        struct WinPipeOps {
            std::array<WinPipeSlotHw, kPipeSlots> slots{};

            static auto classify_error(DWORD err, DWORD transferred) noexcept -> AsyncPipeIoResult {
                if (err == ERROR_IO_PENDING || err == ERROR_IO_INCOMPLETE) return {AsyncPipeIoStatus::pending, 0};
                if (err == ERROR_MORE_DATA) return {AsyncPipeIoStatus::more_data, static_cast<std::size_t>(transferred)};
                if (err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED || err == ERROR_NO_DATA)
                    return {AsyncPipeIoStatus::broken, 0};
                return {AsyncPipeIoStatus::failed, 0};
            }

            auto prepare(WinPipeSlotHw& s) noexcept -> void {
                ::ResetEvent(s.event.handle);
                s.ol = OVERLAPPED{};
                s.ol.hEvent = s.event.handle;
            }

            auto start_connect(std::size_t idx) noexcept -> AsyncPipeIoStatus {
                auto& s = slots[idx];
                for (int attempt = 0; attempt < 2; ++attempt) {
                    prepare(s);
                    if (::ConnectNamedPipe(s.pipe.handle, &s.ol)) return AsyncPipeIoStatus::completed;
                    DWORD const err = ::GetLastError();
                    if (err == ERROR_PIPE_CONNECTED) return AsyncPipeIoStatus::completed;
                    if (err == ERROR_IO_PENDING) return AsyncPipeIoStatus::pending;
                    if (err == ERROR_NO_DATA && attempt == 0) {
                        (void)::DisconnectNamedPipe(s.pipe.handle);
                        continue;
                    }
                    return AsyncPipeIoStatus::failed;
                }
                return AsyncPipeIoStatus::failed;
            }

            auto start_read(std::size_t idx, std::span<char> buf) noexcept -> AsyncPipeIoResult {
                auto& s = slots[idx];
                prepare(s);
                DWORD got = 0;
                if (::ReadFile(s.pipe.handle, buf.data(), static_cast<DWORD>(buf.size()), &got, &s.ol))
                    return {AsyncPipeIoStatus::completed, static_cast<std::size_t>(got)};
                return classify_error(::GetLastError(), got);
            }

            auto start_write(std::size_t idx, std::span<char const> buf) noexcept -> AsyncPipeIoResult {
                auto& s = slots[idx];
                prepare(s);
                DWORD wrote = 0;
                if (::WriteFile(s.pipe.handle, buf.data(), static_cast<DWORD>(buf.size()), &wrote, &s.ol))
                    return {AsyncPipeIoStatus::completed, static_cast<std::size_t>(wrote)};
                return classify_error(::GetLastError(), wrote);
            }

            auto start_drain(std::size_t idx, char& sink) noexcept -> AsyncPipeIoResult {
                return start_read(idx, std::span<char>(&sink, 1));
            }

            auto poll_io(std::size_t idx) noexcept -> AsyncPipeIoResult {
                auto& s = slots[idx];
                DWORD transferred = 0;
                if (::GetOverlappedResult(s.pipe.handle, &s.ol, &transferred, FALSE))
                    return {AsyncPipeIoStatus::completed, static_cast<std::size_t>(transferred)};
                return classify_error(::GetLastError(), transferred);
            }

            [[nodiscard]] auto has_ready_io(std::size_t idx) const noexcept -> bool {
                return HasOverlappedIoCompleted(&slots[idx].ol);
            }

            auto cancel_io(std::size_t idx) noexcept -> void {
                auto& s = slots[idx];
                if (s.pipe) (void)::CancelIoEx(s.pipe.handle, &s.ol);
            }

            auto disconnect(std::size_t idx) noexcept -> void {
                auto& s = slots[idx];
                if (s.pipe) (void)::DisconnectNamedPipe(s.pipe.handle);
            }
        };

        auto send_pipe_once(std::string_view pipe_utf8, std::span<std::string const> tokens)
            -> std::expected<std::string, std::pair<int, std::string>> {
            std::string req("NEXUS/1");
            for (std::size_t i = 0; i < tokens.size(); ++i) {
                if (tokens[i].empty() || req.size() + tokens[i].size() + 1 > kAsyncPipeMaxRequest)
                    return std::unexpected(std::pair{2, std::string("invalid control argument")});
                req += (i == 0 ? ' ' : '\0');
                req += tokens[i];
            }
            auto wname = to_wide(pipe_utf8);
            std::array<char, kAsyncPipeMaxReply> reply{};
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
        std::string instance;
        std::wstring pipe_wide;
        WinPipeOps ops;
        AsyncPipeEngine engine{kPipeSlots, std::chrono::milliseconds(2000)};

        ~Impl() { cancel_and_drain(); }

        auto cancel_and_drain() noexcept -> void {
            for (std::size_t i = 0; i < kPipeSlots; ++i) {
                auto& s = ops.slots[i];
                if (!s.pipe) continue;
                (void)::CancelIoEx(s.pipe.handle, nullptr);
                if (engine.slot_pending(i)) {
                    DWORD dummy = 0;
                    (void)::GetOverlappedResult(s.pipe.handle, &s.ol, &dummy, TRUE);
                }
                (void)::DisconnectNamedPipe(s.pipe.handle);
                s.pipe.reset();
                s.event.reset();
            }
        }
    };

    LocalControl::LocalControl() noexcept = default;
    LocalControl::~LocalControl() { stop(); }

    auto LocalControl::start(std::string_view path, std::optional<std::uint32_t>) -> std::expected<void, std::string> {
        stop();
        auto norm = platform::normalize_windows_pipe_name(path);
        if (!norm) return std::unexpected("invalid Windows control pipe name");
        auto wide = to_wide(*norm);
        auto impl = std::make_unique<Impl>();
        impl->pipe_utf8 = std::move(*norm);
        impl->instance = generate_control_instance_id(static_cast<std::uint64_t>(::GetCurrentProcessId()));
        impl->pipe_wide = std::move(wide);
        for (std::size_t i = 0; i < kPipeSlots; ++i) {
            impl->ops.slots[i].pipe = create_owner_pipe(impl->pipe_wide, i == 0);
            if (!impl->ops.slots[i].pipe) return std::unexpected("create control named pipe failed");
            impl->ops.slots[i].event = PipeHandle(::CreateEventW(nullptr, TRUE, FALSE, nullptr));
            if (!impl->ops.slots[i].event) return std::unexpected("create pipe event failed");
        }
        if (!impl->engine.init(impl->ops)) return std::unexpected("listen control named pipe failed");
        impl_ = std::move(impl);
        return {};
    }

    auto LocalControl::poll(ControlHandler handler) -> void {
        if (!impl_) return;
        impl_->engine.poll(impl_->ops, AsyncPipeEngine::Clock::now(), handler);
    }

    auto LocalControl::stop() noexcept -> void {
        impl_.reset();
    }

    auto LocalControl::active() const noexcept -> bool { return impl_ && impl_->ops.slots[0].pipe; }
    auto LocalControl::listen_native_fd() const noexcept -> int { return -1; }
    auto LocalControl::next_poll_delay() const noexcept -> std::optional<std::chrono::milliseconds> {
        return impl_ ? impl_->engine.next_poll_delay(impl_->ops) : std::nullopt;
    }
    auto LocalControl::instance() const noexcept -> std::string_view { return impl_ ? std::string_view(impl_->instance) : std::string_view{}; }
    auto LocalControl::diagnostics() const noexcept -> ControlDiagnostics { return impl_ ? impl_->engine.diagnostics() : ControlDiagnostics{}; }

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
