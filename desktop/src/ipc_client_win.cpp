module;

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

module desktop.ipc_client;

import std;

namespace desktop {
    namespace {
        class UniqueHandle {
            HANDLE handle_ = INVALID_HANDLE_VALUE;
        public:
            explicit UniqueHandle(HANDLE h) noexcept : handle_(h) {}
            ~UniqueHandle() { if (handle_ != INVALID_HANDLE_VALUE) ::CloseHandle(handle_); }
            UniqueHandle(UniqueHandle const&) = delete;
            auto operator=(UniqueHandle const&) -> UniqueHandle& = delete;
            [[nodiscard]] auto get(this UniqueHandle const& self) noexcept -> HANDLE { return self.handle_; }
        };

        auto utf8_to_wide(std::string_view input) -> std::wstring {
            if (input.empty()) return {};
            int len = ::MultiByteToWideChar(CP_UTF8, 0, input.data(), static_cast<int>(input.size()), nullptr, 0);
            if (len <= 0) return {};
            std::wstring out(static_cast<std::size_t>(len), L'\0');
            ::MultiByteToWideChar(CP_UTF8, 0, input.data(), static_cast<int>(input.size()), out.data(), len);
            return out;
        }
    }

    auto IpcClient::request(this IpcClient const& self, std::span<std::string_view const> tokens)
        -> IpcReply {
        auto frame = build_nexus1_frame(tokens);
        if (!frame) return {false, "invalid NEXUS/1 request"};

        auto pipe_name = utf8_to_wide(self.endpoint_);
        if (pipe_name.empty()) return {false, "empty Named Pipe endpoint"};

        if (!::WaitNamedPipeW(pipe_name.c_str(), static_cast<DWORD>(self.timeout_.count()))) {
            return {false, "control pipe unavailable"};
        }

        UniqueHandle pipe(::CreateFileW(
            pipe_name.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            nullptr));
        if (pipe.get() == INVALID_HANDLE_VALUE) {
            return {false, "failed to open control pipe"};
        }

        DWORD written = 0;
        if (!::WriteFile(pipe.get(), frame->data(), static_cast<DWORD>(frame->size()), &written, nullptr) ||
            written != frame->size()) {
            return {false, "pipe write failed"};
        }

        std::string reply;
        char buf[4096];
        for (;;) {
            DWORD read_bytes = 0;
            BOOL ok = ::ReadFile(pipe.get(), buf, sizeof(buf), &read_bytes, nullptr);
            if (read_bytes > 0) {
                if (reply.size() + read_bytes > 65536) return {false, "reply exceeds 64 KiB limit"};
                reply.append(buf, read_bytes);
            }
            if (!ok) {
                auto err = ::GetLastError();
                if (err == ERROR_BROKEN_PIPE || err == ERROR_MORE_DATA) {
                    if (err == ERROR_BROKEN_PIPE) break;
                    continue;
                }
                return {false, "pipe read failed"};
            }
            if (read_bytes == 0) break;
        }
        return {!reply.empty(), std::move(reply)};
    }
}
