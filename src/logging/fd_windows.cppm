module;
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
export module logging.fd;
import std;
import logging.sink;

namespace logging {
    namespace win32 {
        inline auto close_handle(void* h) noexcept -> void {
            if (h && h != INVALID_HANDLE_VALUE) ::CloseHandle(static_cast<HANDLE>(h));
        }

        inline auto write_all(void* handle, char const* data, std::size_t size) noexcept -> DWORD {
            HANDLE h = static_cast<HANDLE>(handle);
            while (size > 0) {
                DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(size, 1u << 20));
                DWORD wrote = 0;
                if (!::WriteFile(h, data, chunk, &wrote, nullptr)) return ::GetLastError();
                if (wrote == 0) return ERROR_WRITE_FAULT;
                data += wrote;
                size -= wrote;
            }
            return ERROR_SUCCESS;
        }
    }

    export class FileDescriptor {
        void* handle_;
    public:
        explicit FileDescriptor(void* handle = nullptr) noexcept : handle_(handle) {}
        FileDescriptor(FileDescriptor&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}
        auto operator=(this FileDescriptor& self, FileDescriptor&& other) noexcept -> FileDescriptor& {
            std::swap(self.handle_, other.handle_);
            return self;
        }
        ~FileDescriptor() { win32::close_handle(handle_); }
        auto get(this FileDescriptor const& self) noexcept -> void* { return self.handle_; }
        auto release(this FileDescriptor& self) noexcept -> void* { return std::exchange(self.handle_, nullptr); }
        auto reset(this FileDescriptor& self, void* next = nullptr) noexcept -> void {
            win32::close_handle(std::exchange(self.handle_, next));
        }
    };

    export auto system_error(int error) noexcept -> std::error_code {
        return {error, std::system_category()};
    }

    export auto write_lines(void* handle, std::span<SinkRecord const> lines) noexcept -> SinkResult {
        for (auto const& record : lines) {
            if (record.line.empty()) continue;
            if (DWORD err = win32::write_all(handle, record.line.data(), record.line.size()); err != ERROR_SUCCESS)
                return std::unexpected(system_error(static_cast<int>(err)));
        }
        return {};
    }
}
