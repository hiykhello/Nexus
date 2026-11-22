module;
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

module rulefile;
import std;
import rules;
import platform.os_fs;

namespace rulefile {
    namespace {
        constexpr std::size_t private_file_capacity = 1048577;

        auto win_error(std::string_view action, DWORD err = ::GetLastError()) -> std::unexpected<std::string> {
            return std::unexpected(std::format("{}: {}", action, std::system_category().message(static_cast<int>(err))));
        }

        struct WinHandle {
            HANDLE value = INVALID_HANDLE_VALUE;
            explicit WinHandle(HANDLE h = INVALID_HANDLE_VALUE) noexcept : value(h) {}
            WinHandle(WinHandle const&) = delete;
            auto operator=(WinHandle const&) -> WinHandle& = delete;
            ~WinHandle() { if (value != INVALID_HANDLE_VALUE) ::CloseHandle(value); }
            auto close_checked() noexcept -> bool {
                auto h = std::exchange(value, INVALID_HANDLE_VALUE);
                return h == INVALID_HANDLE_VALUE || ::CloseHandle(h) != 0;
            }
        };

        auto is_regular_non_reparse(HANDLE h) noexcept -> bool {
            BY_HANDLE_FILE_INFORMATION info{};
            return ::GetFileInformationByHandle(h, &info) != 0 &&
                (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0;
        }

        auto is_absolute_win_path(std::string_view path) noexcept -> bool {
            if (path.empty() || path.find('\0') != path.npos) return false;
            std::filesystem::path p{std::string(path)};
            return p.is_absolute();
        }
    }

    auto read_regular_file(std::string_view path) -> std::expected<std::string, std::string> {
        if (path.find('\0') != std::string_view::npos) return std::unexpected("invalid input path");
        std::filesystem::path p{std::string(path)};
        if (auto sym = platform::is_reparse_or_symlink(p); sym && *sym)
            return std::unexpected("input must be a regular file");
        WinHandle input(::CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (input.value == INVALID_HANDLE_VALUE) return win_error("open input");
        if (!is_regular_non_reparse(input.value)) return std::unexpected("input must be a regular file");
        LARGE_INTEGER sz{};
        if (!::GetFileSizeEx(input.value, &sz)) return win_error("inspect input");
        if (sz.QuadPart > static_cast<LONGLONG>(::rules::max_input_bytes))
            return std::unexpected("input exceeds 1 MiB");
        std::string data;
        char buffer[8192];
        for (;;) {
            DWORD n = 0;
            if (!::ReadFile(input.value, buffer, sizeof(buffer), &n, nullptr)) return win_error("read input");
            if (n == 0) return data;
            if (static_cast<std::size_t>(n) > ::rules::max_input_bytes - data.size())
                return std::unexpected("input exceeds 1 MiB");
            data.append(buffer, static_cast<std::size_t>(n));
        }
    }

    PrivateFile::PrivateFile(std::unique_ptr<char[]>&& data, std::size_t size) noexcept
        : data_(std::move(data)), size_(size) {}
    PrivateFile::~PrivateFile() { if (data_) ::SecureZeroMemory(data_.get(), private_file_capacity); }
    PrivateFile::PrivateFile(PrivateFile&& other) noexcept
        : data_(std::move(other.data_)), size_(std::exchange(other.size_, 0)) {}
    auto PrivateFile::operator=(PrivateFile&& other) noexcept -> PrivateFile& {
        if (this != &other) {
            if (data_) ::SecureZeroMemory(data_.get(), private_file_capacity);
            data_ = std::move(other.data_);
            size_ = std::exchange(other.size_, 0);
        }
        return *this;
    }

    auto read_private_file(std::string_view path) -> std::expected<PrivateFile, std::string> {
        if (!is_absolute_win_path(path)) return std::unexpected("private file path must be absolute");
        std::filesystem::path p{std::string(path)};
        if (auto sym = platform::is_reparse_or_symlink(p); sym && *sym)
            return std::unexpected("private file must be a private regular file owned by the current user");
        WinHandle input(::CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (input.value == INVALID_HANDLE_VALUE) return win_error("open private file");
        if (!is_regular_non_reparse(input.value))
            return std::unexpected("private file must be a private regular file owned by the current user");
        LARGE_INTEGER sz{};
        if (!::GetFileSizeEx(input.value, &sz)) return win_error("inspect private file");
        if (sz.QuadPart > 1048576) return std::unexpected("private file exceeds 1 MiB");
        PrivateFile data(std::make_unique_for_overwrite<char[]>(private_file_capacity), 0);
        while (data.size_ < private_file_capacity) {
            DWORD n = 0;
            DWORD chunk = static_cast<DWORD>(private_file_capacity - data.size_);
            if (!::ReadFile(input.value, data.data_.get() + data.size_, chunk, &n, nullptr))
                return win_error("read private file");
            if (n == 0) break;
            data.size_ += static_cast<std::size_t>(n);
        }
        if (!data.size_ || data.size_ > 1048576)
            return std::unexpected("private file must contain 1..1048576 bytes");
        return data;
    }

    auto read_password_file(std::string_view path) -> std::expected<std::string, std::string> {
        if (!is_absolute_win_path(path)) return std::unexpected("password path must be absolute");
        std::filesystem::path p{std::string(path)};
        WinHandle input(::CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (input.value == INVALID_HANDLE_VALUE) return win_error("open password file");
        if (!is_regular_non_reparse(input.value))
            return std::unexpected("password file must be a private regular file owned by the current user");
        std::array<char, 257> data{};
        struct WipeBuffer {
            std::array<char, 257>& bytes;
            ~WipeBuffer() { ::SecureZeroMemory(bytes.data(), bytes.size()); }
        } wipe{data};
        std::size_t size = 0;
        while (size < data.size()) {
            DWORD n = 0;
            if (!::ReadFile(input.value, data.data() + size, static_cast<DWORD>(data.size() - size), &n, nullptr))
                return win_error("read password file");
            if (n == 0) break;
            size += static_cast<std::size_t>(n);
        }
        if (size && data[size - 1] == '\n') --size;
        if (size && data[size - 1] == '\r') --size;
        if (size == 0 || size > 255 || !std::all_of(data.begin(), data.begin() + size,
            [](unsigned char c) { return c >= 32 && c <= 126; }))
            return std::unexpected("password must be 1..255 printable ASCII bytes with at most one trailing newline");
        return std::string(data.data(), size);
    }

    static auto publish(std::string_view path, std::string_view data, bool replace) -> std::expected<void, std::string> {
        if (path.find('\0') != std::string_view::npos) return std::unexpected("invalid output path");
        std::filesystem::path output{std::string(path)};
        auto filename = output.filename().string();
        if (filename.empty() || filename == "." || filename == "..") return std::unexpected("invalid output filename");
        auto parent_path = output.parent_path().empty() ? std::filesystem::path(".") : output.parent_path();
        if (!replace) {
            WinHandle direct(::CreateFileW(output.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            if (direct.value == INVALID_HANDLE_VALUE)
                return win_error("publish output (existing files are never overwritten)");
            std::size_t written = 0;
            while (written < data.size()) {
                DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(data.size() - written, 0x7fffffff));
                DWORD n = 0;
                if (!::WriteFile(direct.value, data.data() + written, chunk, &n, nullptr) || n == 0) {
                    DWORD err = ::GetLastError();
                    direct.close_checked();
                    ::DeleteFileW(output.c_str());
                    return win_error("write output", err);
                }
                written += n;
            }
            if (!direct.close_checked()) return win_error("close output");
            return {};
        }
        auto tmp = parent_path / (".nexus-tmp-" + std::to_string(::GetCurrentProcessId()) + "-" + filename);
        ::DeleteFileW(tmp.c_str());
        WinHandle file(::CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (file.value == INVALID_HANDLE_VALUE) return win_error("create temporary file");
        std::size_t written = 0;
        while (written < data.size()) {
            DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(data.size() - written, 0x7fffffff));
            DWORD n = 0;
            if (!::WriteFile(file.value, data.data() + written, chunk, &n, nullptr) || n == 0) {
                DWORD err = ::GetLastError();
                file.close_checked();
                ::DeleteFileW(tmp.c_str());
                return win_error("write temporary file", err);
            }
            written += n;
        }
        if (platform::sync_native_handle(reinterpret_cast<std::uintptr_t>(file.value)) < 0) {
            file.close_checked();
            ::DeleteFileW(tmp.c_str());
            return win_error("synchronize temporary file");
        }
        if (!file.close_checked()) { ::DeleteFileW(tmp.c_str()); return win_error("close temporary file"); }
        if (auto ec = platform::atomic_replace_path(tmp, output)) {
            ::DeleteFileW(tmp.c_str());
            return std::unexpected("replace output: " + ec.message());
        }
        return {};
    }

    auto publish_new_file(std::string_view path, std::string_view data) -> std::expected<void, std::string> {
        return publish(path, data, false);
    }
    auto replace_file(std::string_view path, std::string_view data) -> std::expected<void, std::string> {
        return publish(path, data, true);
    }
}
