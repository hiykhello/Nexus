module;
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
module state.file;
import std;
import nexus.compat;

namespace state {
    namespace win32 {
        inline auto close_handle_raw(void* h) noexcept -> bool {
            if (!h || h == INVALID_HANDLE_VALUE) return true;
            return ::CloseHandle(static_cast<HANDLE>(h)) != 0;
        }
        inline auto open_dir_handle(std::filesystem::path const& path, DWORD& err) noexcept -> void* {
            HANDLE h = ::CreateFileW(path.c_str(), FILE_LIST_DIRECTORY | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            if (h == INVALID_HANDLE_VALUE) { err = ::GetLastError(); return nullptr; }
            BY_HANDLE_FILE_INFORMATION info{};
            if (!::GetFileInformationByHandle(h, &info) ||
                (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
                (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
                err = ERROR_ACCESS_DENIED;
                ::CloseHandle(h);
                return nullptr;
            }
            err = ERROR_SUCCESS;
            return h;
        }
        inline auto path_from_handle(void* dir_handle) -> std::optional<std::filesystem::path> {
            if (!dir_handle || dir_handle == INVALID_HANDLE_VALUE) return std::nullopt;
            std::wstring buf(512, L'\0');
            DWORD got = ::GetFinalPathNameByHandleW(static_cast<HANDLE>(dir_handle), buf.data(),
                static_cast<DWORD>(buf.size()), FILE_NAME_NORMALIZED);
            if (got == 0 || got >= buf.size()) return std::nullopt;
            buf.resize(got);
            return std::filesystem::path(buf);
        }
        inline auto child_path(void* dir, std::string_view name) -> std::optional<std::filesystem::path> {
            auto base = path_from_handle(dir);
            if (!base || name.empty() || name.contains('\0') || name.contains('/') || name.contains('\\'))
                return std::nullopt;
            return *base / std::filesystem::path(name);
        }
        inline auto verify_regular_handle(HANDLE h) noexcept -> bool {
            BY_HANDLE_FILE_INFORMATION info{};
            return ::GetFileInformationByHandle(h, &info) != 0 &&
                (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0;
        }
    }

    File::~File() { (void)win32::close_handle_raw(handle_); }

    auto open_directory(std::filesystem::path const& path) -> std::expected<File, StateError> {
        if (path.empty()) return failure(Stage::directory, ERROR_INVALID_PARAMETER);
        DWORD err = ERROR_SUCCESS;
        void* h = win32::open_dir_handle(path, err);
        if (!h) return failure(Stage::directory, static_cast<int>(err));
        return File(h);
    }

    auto open_private_directory(std::filesystem::path const& path) -> std::expected<File, StateError> {
        return open_directory(path);
    }

    auto ensure_private_directory(std::filesystem::path const& path) -> std::expected<void, StateError> {
        if (auto existing = open_private_directory(path)) return {};
        std::error_code ec;
        if (!std::filesystem::create_directories(path, ec) && ec)
            return std::unexpected(StateError{Stage::directory, ec, false});
        auto created = open_private_directory(path);
        if (!created) return std::unexpected(created.error());
        return {};
    }

    auto directory_entries(NativeHandle directory, nexus::function_ref<bool(std::string_view)> accept)
        -> std::expected<std::vector<DirectoryEntry>, StateError> {
        auto base = win32::path_from_handle(directory);
        if (!base) return failure(Stage::scan, ERROR_INVALID_HANDLE);
        std::vector<DirectoryEntry> result;
        std::error_code ec;
        for (auto const& ent : std::filesystem::directory_iterator(*base, ec)) {
            auto name = ent.path().filename().string();
            if (!accept(name)) continue;
            bool ok_reg = ent.is_regular_file(ec) && !ent.is_symlink(ec);
            std::uint64_t sz = ok_reg ? ent.file_size(ec) : 0;
            if (result.size() == 4096) return std::unexpected(StateError{Stage::capacity});
            result.push_back({std::move(name), sz, ok_reg});
        }
        if (ec) return std::unexpected(StateError{Stage::scan, ec, false});
        return result;
    }

    auto open_dir_read(NativeHandle dir, std::string_view name, bool, Stage stage) -> std::expected<File, StateError> {
        auto full = win32::child_path(dir, name);
        if (!full) return failure(stage, ERROR_INVALID_PARAMETER);
        HANDLE h = ::CreateFileW(full->c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (h == INVALID_HANDLE_VALUE) return failure(stage, static_cast<int>(::GetLastError()));
        if (!win32::verify_regular_handle(h)) { ::CloseHandle(h); return failure(stage, ERROR_ACCESS_DENIED); }
        return File(h);
    }

    auto open_dir_append(NativeHandle dir, std::string_view name, Stage stage) -> std::expected<File, StateError> {
        auto full = win32::child_path(dir, name);
        if (!full) return failure(stage, ERROR_INVALID_PARAMETER);
        constexpr DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
        HANDLE h = ::CreateFileW(full->c_str(), GENERIC_READ | FILE_APPEND_DATA, share, nullptr, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (h == INVALID_HANDLE_VALUE && ::GetLastError() == ERROR_FILE_NOT_FOUND) {
            h = ::CreateFileW(full->c_str(), GENERIC_READ | FILE_APPEND_DATA, share, nullptr, CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            if (h == INVALID_HANDLE_VALUE) return failure(stage, static_cast<int>(::GetLastError()));
            if (sync_file(h) < 0) { ::CloseHandle(h); return failure(Stage::sync_directory, static_cast<int>(::GetLastError())); }
        }
        if (h == INVALID_HANDLE_VALUE) return failure(stage, static_cast<int>(::GetLastError()));
        if (!win32::verify_regular_handle(h)) { ::CloseHandle(h); return failure(stage, ERROR_ACCESS_DENIED); }
        return File(h);
    }

    auto open_dir_stage(NativeHandle dir, std::string_view name, Stage stage) -> std::expected<File, StateError> {
        auto full = win32::child_path(dir, name);
        if (!full) return failure(stage, ERROR_INVALID_PARAMETER);
        HANDLE h = ::CreateFileW(full->c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (h == INVALID_HANDLE_VALUE) return failure(stage, static_cast<int>(::GetLastError()));
        return File(h);
    }

    auto dir_entry_exists(NativeHandle dir, std::string_view name, Stage stage) -> std::expected<bool, StateError> {
        auto full = win32::child_path(dir, name);
        if (!full) return failure(stage, ERROR_INVALID_PARAMETER);
        DWORD attrs = ::GetFileAttributesW(full->c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES) return true;
        DWORD err = ::GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) return false;
        return failure(stage, static_cast<int>(err));
    }

    auto handle_size(NativeHandle handle, Stage stage) -> std::expected<std::uint64_t, StateError> {
        LARGE_INTEGER sz{};
        if (!::GetFileSizeEx(static_cast<HANDLE>(handle), &sz) || sz.QuadPart < 0)
            return failure(stage, static_cast<int>(::GetLastError()));
        return static_cast<std::uint64_t>(sz.QuadPart);
    }

    auto read_handle(NativeHandle handle, std::span<std::byte> out, Stage stage) -> std::expected<std::size_t, StateError> {
        std::size_t total = 0;
        while (total < out.size()) {
            DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(out.size() - total, 0x7fffffff));
            DWORD got = 0;
            if (!::ReadFile(static_cast<HANDLE>(handle), out.data() + total, chunk, &got, nullptr))
                return failure(stage, static_cast<int>(::GetLastError()));
            if (got == 0) break;
            total += got;
        }
        return total;
    }

    auto read_handle_at(NativeHandle handle, std::uint64_t offset, std::span<std::byte> out, Stage stage)
        -> std::expected<std::size_t, StateError> {
        std::size_t total = 0;
        while (total < out.size()) {
            std::uint64_t pos = offset + total;
            OVERLAPPED ov{};
            ov.Offset = static_cast<DWORD>(pos & 0xffffffffu);
            ov.OffsetHigh = static_cast<DWORD>(pos >> 32);
            DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(out.size() - total, 0x7fffffff));
            DWORD got = 0;
            if (!::ReadFile(static_cast<HANDLE>(handle), out.data() + total, chunk, &got, &ov)) {
                if (::GetLastError() == ERROR_HANDLE_EOF) break;
                return failure(stage, static_cast<int>(::GetLastError()));
            }
            if (got == 0) break;
            total += got;
        }
        return total;
    }

    auto write_handle_all(NativeHandle handle, std::span<std::byte const> data, Stage stage)
        -> std::expected<void, StateError> {
        std::size_t sent = 0;
        while (sent < data.size()) {
            DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(data.size() - sent, 0x7fffffff));
            DWORD wrote = 0;
            if (!::WriteFile(static_cast<HANDLE>(handle), data.data() + sent, chunk, &wrote, nullptr) || wrote == 0)
                return failure(stage, static_cast<int>(::GetLastError()));
            sent += wrote;
        }
        return {};
    }

    auto truncate_handle(NativeHandle handle, std::uint64_t size, Stage stage) -> std::expected<void, StateError> {
        LARGE_INTEGER li{};
        li.QuadPart = static_cast<LONGLONG>(size);
        if (!::SetFilePointerEx(static_cast<HANDLE>(handle), li, nullptr, FILE_BEGIN) ||
            !::SetEndOfFile(static_cast<HANDLE>(handle)) || sync_file(handle) < 0)
            return failure(stage, static_cast<int>(::GetLastError()));
        return {};
    }

    auto close_file(File& file, Stage stage) -> std::expected<void, StateError> {
        if (!win32::close_handle_raw(file.release())) return failure(stage, static_cast<int>(::GetLastError()));
        return {};
    }

    auto unlink_dir_file(NativeHandle dir, std::string_view name, Stage stage) -> std::expected<void, StateError> {
        auto full = win32::child_path(dir, name);
        if (!full) return failure(stage, ERROR_INVALID_PARAMETER);
        if (!::DeleteFileW(full->c_str())) {
            DWORD err = ::GetLastError();
            if (err != ERROR_FILE_NOT_FOUND && err != ERROR_PATH_NOT_FOUND) return failure(stage, static_cast<int>(err));
        }
        return {};
    }

    auto rename_dir_file(NativeHandle dir, std::string_view from, std::string_view to, bool noreplace, Stage stage)
        -> std::expected<void, StateError> {
        auto pfrom = win32::child_path(dir, from);
        auto pto = win32::child_path(dir, to);
        if (!pfrom || !pto) return failure(stage, ERROR_INVALID_PARAMETER);
        DWORD flags = noreplace ? MOVEFILE_WRITE_THROUGH : (MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
        if (!::MoveFileExW(pfrom->c_str(), pto->c_str(), flags))
            return failure(stage, static_cast<int>(::GetLastError()));
        return {};
    }

    auto same_directory_entry(NativeHandle held_dir, NativeHandle parent_dir, std::string_view name)
        -> std::expected<bool, StateError> {
        auto full = win32::child_path(parent_dir, name);
        if (!full) return failure(Stage::directory, ERROR_INVALID_PARAMETER);
        DWORD err = ERROR_SUCCESS;
        void* named = win32::open_dir_handle(*full, err);
        if (!named) return failure(Stage::directory, static_cast<int>(err));
        BY_HANDLE_FILE_INFORMATION a{}, b{};
        bool ok = ::GetFileInformationByHandle(static_cast<HANDLE>(held_dir), &a) &&
                  ::GetFileInformationByHandle(static_cast<HANDLE>(named), &b);
        ::CloseHandle(static_cast<HANDLE>(named));
        if (!ok) return failure(Stage::directory, static_cast<int>(::GetLastError()));
        return a.dwVolumeSerialNumber == b.dwVolumeSerialNumber &&
               a.nFileIndexHigh == b.nFileIndexHigh && a.nFileIndexLow == b.nFileIndexLow;
    }

    auto sync_handle(NativeHandle handle, Stage stage, bool replaced) noexcept -> std::expected<void, StateError> {
        if (sync_file(handle) < 0) return failure(stage, static_cast<int>(::GetLastError()), replaced);
        return {};
    }

    auto read_dir_file(NativeHandle dir, std::string_view name, std::size_t max_bytes, bool require_private)
        -> std::expected<std::vector<std::byte>, StateError> {
        auto fd = open_dir_read(dir, name, require_private, Stage::open);
        if (!fd) return std::unexpected(fd.error());
        auto sz = handle_size(fd->get(), Stage::read);
        if (!sz) return std::unexpected(sz.error());
        if (*sz > max_bytes) return std::unexpected(StateError{Stage::format});
        std::vector<std::byte> out(static_cast<std::size_t>(*sz));
        auto got = read_handle(fd->get(), out, Stage::read);
        if (!got) return std::unexpected(got.error());
        if (*got != out.size()) return std::unexpected(StateError{Stage::format});
        std::byte probe{};
        auto extra = read_handle(fd->get(), std::span(&probe, 1), Stage::read);
        if (!extra) return std::unexpected(extra.error());
        if (*extra != 0) return std::unexpected(StateError{Stage::format});
        return out;
    }

    auto write_dir_file_atomic(NativeHandle dir, std::string_view name, std::string_view tmp_prefix,
                               std::span<std::byte const> data, Stage stage) -> std::expected<void, StateError> {
        auto cleared = unlink_dir_file(dir, tmp_prefix, Stage::remove_stage);
        if (!cleared) return cleared;
        auto staged = open_dir_stage(dir, tmp_prefix, Stage::create_stage);
        if (!staged) return std::unexpected(staged.error());
        auto written = write_handle_all(staged->get(), data, Stage::write);
        if (written && sync_file(staged->get()) < 0) written = failure(Stage::sync_stage, static_cast<int>(::GetLastError()));
        auto closed = close_file(*staged, Stage::close_stage);
        if (!written) { (void)unlink_dir_file(dir, tmp_prefix, Stage::remove_stage); return written; }
        if (!closed) { (void)unlink_dir_file(dir, tmp_prefix, Stage::remove_stage); return closed; }
        auto moved = rename_dir_file(dir, tmp_prefix, name, false, stage);
        if (!moved) { (void)unlink_dir_file(dir, tmp_prefix, Stage::remove_stage); return moved; }
        return {};
    }
}
