module;
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
module state.lock;
import std;
import state.core;
import state.file;

namespace state {
    namespace win32_lock {
        inline auto valid_handle_type(HANDLE h, bool expect_dir) noexcept -> bool {
            BY_HANDLE_FILE_INFORMATION fi{};
            if (!::GetFileInformationByHandle(h, &fi)) return false;
            if ((fi.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) return false;
            bool is_dir = (fi.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            return is_dir == expect_dir;
        }

        inline auto lock_dir_and_file(std::filesystem::path const& dir_path, DWORD& err) noexcept
            -> std::pair<void*, void*> {
            HANDLE dir_h = ::CreateFileW(dir_path.c_str(), FILE_LIST_DIRECTORY | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            if (dir_h == INVALID_HANDLE_VALUE) { err = ::GetLastError(); return {nullptr, nullptr}; }
            if (!valid_handle_type(dir_h, true)) {
                err = ERROR_ACCESS_DENIED;
                ::CloseHandle(dir_h);
                return {nullptr, nullptr};
            }
            auto lock_path = dir_path / "instance.lock";
            HANDLE lock_h = ::CreateFileW(lock_path.c_str(), GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            if (lock_h == INVALID_HANDLE_VALUE) {
                err = ::GetLastError();
                ::CloseHandle(dir_h);
                return {nullptr, nullptr};
            }
            if (!valid_handle_type(lock_h, false)) {
                err = ERROR_ACCESS_DENIED;
                ::CloseHandle(lock_h);
                ::CloseHandle(dir_h);
                return {nullptr, nullptr};
            }
            bool locked = false;
            for (int attempt = 0; attempt < 20; ++attempt) {
                OVERLAPPED ol{};
                if (::LockFileEx(lock_h, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, MAXDWORD, MAXDWORD, &ol)) {
                    locked = true;
                    break;
                }
                err = ::GetLastError();
                if (err != ERROR_LOCK_VIOLATION) break;
                if (attempt + 1 < 20) std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            if (!locked) {
                ::CloseHandle(lock_h);
                ::CloseHandle(dir_h);
                return {nullptr, nullptr};
            }
            err = ERROR_SUCCESS;
            return {dir_h, lock_h};
        }
    }

    InstanceLock::InstanceLock(InstanceLock&& other) noexcept
        : directory_(std::exchange(other.directory_, nullptr)), lock_(std::exchange(other.lock_, nullptr)) {}
    InstanceLock::~InstanceLock() {
        if (lock_) ::CloseHandle(static_cast<HANDLE>(lock_));
        if (directory_) ::CloseHandle(static_cast<HANDLE>(directory_));
    }

    auto InstanceLock::open(std::filesystem::path const& path) -> std::expected<InstanceLock, StateError> {
        DWORD err = ERROR_SUCCESS;
        auto [dir_h, lock_h] = win32_lock::lock_dir_and_file(path, err);
        if (!dir_h || !lock_h) return failure(Stage::lock, static_cast<int>(err));
        return InstanceLock(dir_h, lock_h);
    }

    auto InstanceLock::open_rulesets(std::filesystem::path const& root) -> std::expected<InstanceLock, StateError> {
        return open_child(root, "rulesets");
    }

    auto InstanceLock::open_child(std::filesystem::path const& root, std::string const& name)
        -> std::expected<InstanceLock, StateError> {
        if (name.empty() || name == "." || name == ".." || name.contains('/') || name.contains('\\'))
            return failure(Stage::directory, ERROR_INVALID_PARAMETER);
        auto child = root / name;
        auto ens = ensure_private_directory(child);
        if (!ens) return std::unexpected(ens.error());
        return open(child);
    }
}
