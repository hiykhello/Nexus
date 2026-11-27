module;
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <io.h>
module logging.sink;
import std;
import proxy.v4;
import logging.fd;

namespace logging {
    namespace win32_sink {
        inline auto dup_handle(int crt_fd) noexcept -> void* {
            HANDLE src = reinterpret_cast<HANDLE>(::_get_osfhandle(crt_fd));
            if (!src || src == INVALID_HANDLE_VALUE) return nullptr;
            HANDLE dup = nullptr;
            if (!::DuplicateHandle(::GetCurrentProcess(), src, ::GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS))
                return nullptr;
            return dup;
        }

        inline auto open_append_file(std::filesystem::path const& path, bool exclusive,
            std::uint64_t& size_out, DWORD& err_out) noexcept -> void* {
            DWORD disp = exclusive ? CREATE_NEW : OPEN_ALWAYS;
            DWORD flags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT;
            HANDLE h = ::CreateFileW(path.c_str(), FILE_APPEND_DATA | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, disp, flags, nullptr);
            if (h == INVALID_HANDLE_VALUE) { err_out = ::GetLastError(); return nullptr; }
            BY_HANDLE_FILE_INFORMATION info{};
            if (!::GetFileInformationByHandle(h, &info) ||
                (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
                info.nNumberOfLinks != 1) {
                err_out = ERROR_ACCESS_DENIED;
                ::CloseHandle(h);
                return nullptr;
            }
            LARGE_INTEGER sz{};
            sz.HighPart = static_cast<LONG>(info.nFileSizeHigh);
            sz.LowPart = info.nFileSizeLow;
            size_out = static_cast<std::uint64_t>(sz.QuadPart);
            err_out = ERROR_SUCCESS;
            return h;
        }

        struct Win32RotateOps {
            static auto ok() noexcept -> DWORD { return ERROR_SUCCESS; }
            static auto invalid_arg() noexcept -> DWORD { return ERROR_INVALID_PARAMETER; }
            static auto is_not_found(DWORD e) noexcept -> bool { return e == ERROR_FILE_NOT_FOUND; }
            static auto open_append(std::filesystem::path const& path, bool exclusive,
                std::uint64_t& size_out, DWORD& err_out) noexcept -> void* {
                return open_append_file(path, exclusive, size_out, err_out);
            }
            static auto close(void* h) noexcept -> void { ::CloseHandle(static_cast<HANDLE>(h)); }
            static auto remove(std::filesystem::path const& path) noexcept -> void { ::DeleteFileW(path.c_str()); }
            static auto move_replace(std::filesystem::path const& src, std::filesystem::path const& dst,
                DWORD& err_out) noexcept -> bool {
                if (::MoveFileExW(src.c_str(), dst.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                    err_out = ERROR_SUCCESS;
                    return true;
                }
                err_out = ::GetLastError();
                return false;
            }
        };

        inline auto rotate_file(std::filesystem::path const& dir, std::span<std::string const> names,
            std::string const& temp_name, void*& active_handle, std::uint64_t& active_size) noexcept -> DWORD {
            return rotate_file_ops<void*, DWORD>(dir, names, temp_name, active_handle, active_size, Win32RotateOps{});
        }
    }

    namespace {
        struct StderrSink {
            FileDescriptor file;
            auto write(this StderrSink& self, std::span<SinkRecord const> lines) noexcept -> SinkResult {
                return write_lines(self.file.get(), lines);
            }
            auto reopen(this StderrSink&) noexcept -> SinkResult {
                return std::unexpected(std::make_error_code(std::errc::operation_not_supported));
            }
        };

        struct FileSink {
            std::filesystem::path directory;
            FileDescriptor file;
            std::vector<std::string> names;
            std::string temporary;
            std::uint64_t size = 0;
            std::uint64_t max_size = 0;

            auto reopen(this FileSink& self) noexcept -> SinkResult {
                DWORD err = ERROR_SUCCESS;
                std::uint64_t sz = 0;
                void* next = win32_sink::open_append_file(self.directory / self.names.front(), false, sz, err);
                if (!next) return std::unexpected(system_error(static_cast<int>(err)));
                self.file.reset(next);
                self.size = sz;
                return {};
            }

            auto write(this FileSink& self, std::span<SinkRecord const> lines) noexcept -> SinkResult {
                while (!lines.empty()) {
                    if (!self.file.get()) {
                        if (auto r = self.reopen(); !r) return r;
                    }
                    if (self.max_size && self.size &&
                        lines.front().line.size() > self.max_size - std::min(self.size, self.max_size)) {
                        void* handle = self.file.release();
                        DWORD rerr = win32_sink::rotate_file(self.directory, self.names, self.temporary, handle, self.size);
                        self.file.reset(handle);
                        if (rerr != ERROR_SUCCESS) return std::unexpected(system_error(static_cast<int>(rerr)));
                    }
                    auto res = write_lines(self.file.get(), lines.first(1));
                    if (!res) return res;
                    self.size += lines.front().line.size();
                    lines = lines.subspan(1);
                }
                return {};
            }
        };
    }

    auto off_sink() noexcept -> Sink { return {}; }

    auto stderr_sink(int fd) -> std::expected<Sink, std::error_code> {
        void* dup = win32_sink::dup_handle(fd);
        if (!dup) return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
        return pro::make_proxy<SinkFacade, StderrSink>(FileDescriptor(dup));
    }

    auto file_sink(FileOptions options) -> std::expected<Sink, std::error_code> {
        auto basename = options.path.filename().string();
        if (basename.empty() || basename == "." || basename == ".." ||
            options.max_files == 0 || options.max_files > 128)
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        auto parent = options.path.parent_path();
        if (parent.empty()) parent = ".";
        std::vector<std::string> names;
        names.reserve(options.max_size_bytes ? options.max_files : 1);
        names.push_back(basename);
        if (options.max_size_bytes) {
            for (std::size_t idx = 1; idx < options.max_files; ++idx)
                names.push_back(basename + "." + std::to_string(idx));
        }
        DWORD err = ERROR_SUCCESS;
        std::uint64_t sz = 0;
        void* h = win32_sink::open_append_file(parent / basename, false, sz, err);
        if (!h) return std::unexpected(system_error(static_cast<int>(err)));
        return pro::make_proxy<SinkFacade, FileSink>(
            parent, FileDescriptor(h), std::move(names), basename + ".rotate", sz, options.max_size_bytes);
    }

    auto write_batch(Sink& sink, std::span<SinkRecord const> lines) noexcept -> SinkResult {
        return sink ? sink->write(lines) : SinkResult{};
    }

    auto write_batch(Sink& sink, std::span<std::string_view const> lines) noexcept -> SinkResult {
        std::array<SinkRecord, batch_capacity> records;
        while (!lines.empty()) {
            auto count = std::min(lines.size(), records.size());
            for (std::size_t index = 0; index < count; ++index) records[index].line = lines[index];
            auto result = write_batch(sink, std::span(records).first(count));
            if (!result) return result;
            lines = lines.subspan(count);
        }
        return {};
    }

    auto reopen_sink(Sink& sink) noexcept -> SinkResult {
        if (sink) return sink->reopen();
        return std::unexpected(std::make_error_code(std::errc::operation_not_supported));
    }
}
