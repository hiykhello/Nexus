module;
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
module state.file;
import std;

namespace state {
    namespace win32 {
        inline auto close_handle(void* h) noexcept -> void {
            if (h && h != INVALID_HANDLE_VALUE) ::CloseHandle(static_cast<HANDLE>(h));
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
    }

    File::~File() { win32::close_handle(handle_); }

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
        auto existing = open_private_directory(path);
        if (existing) return {};
        std::error_code ec;
        if (!std::filesystem::create_directories(path, ec) && ec)
            return std::unexpected(StateError{Stage::directory, ec, false});
        auto created = open_private_directory(path);
        if (!created) return std::unexpected(created.error());
        return {};
    }

    auto directory_entries(void* directory, std::function_ref<bool(std::string_view)> accept)
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
}
