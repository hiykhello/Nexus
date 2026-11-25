// Privileged binary staging & restricted DACL helpers for desktop/src/tun_helper_win.cpp.
// Included only inside tun_helper_win.cpp under #ifdef _WIN32.
#pragma once

namespace {
    inline auto apply_privileged_dacl(std::filesystem::path const& target) -> bool {
        PSECURITY_DESCRIPTOR sd = nullptr;
        auto sddl_w = utf8_to_wide(desktop::kWinTunHelperStageDirSddl);
        if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl_w.c_str(), SDDL_REVISION_1, &sd, nullptr) || !sd) {
            return false;
        }
        BOOL dacl_present = FALSE, dacl_defaulted = FALSE;
        PACL dacl = nullptr;
        bool ok = ::GetSecurityDescriptorDacl(sd, &dacl_present, &dacl, &dacl_defaulted) != FALSE && dacl_present && dacl != nullptr;
        if (ok) {
            std::wstring path_w = target.wstring();
            DWORD rc = ::SetNamedSecurityInfoW(
                path_w.data(), SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                nullptr, nullptr, dacl, nullptr);
            ok = (rc == ERROR_SUCCESS);
        }
        ::LocalFree(sd);
        return ok;
    }

    inline auto is_reparse_point_win(std::filesystem::path const& p) -> bool {
        DWORD attr = ::GetFileAttributesW(p.c_str());
        return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
    }

    inline auto resolve_win_stage_dir() -> std::filesystem::path {
        wchar_t buf[MAX_PATH]{};
        DWORD len = ::GetEnvironmentVariableW(L"ProgramData", buf, MAX_PATH);
        std::filesystem::path base = (len > 0 && len < MAX_PATH) ? std::filesystem::path(buf) : std::filesystem::path(L"C:\\ProgramData");
        return base / L"Nexus" / L"helper";
    }

    inline auto ensure_privileged_stage_dir(std::filesystem::path const& stage_dir) -> bool {
        std::error_code ec;
        auto parent = stage_dir.parent_path();
        if (is_reparse_point_win(parent) || is_reparse_point_win(stage_dir)) return false;
        std::filesystem::create_directories(stage_dir, ec);
        if (ec) return false;
        if (is_reparse_point_win(parent) || is_reparse_point_win(stage_dir)) return false;
        return apply_privileged_dacl(parent) && apply_privileged_dacl(stage_dir);
    }

    inline auto stage_file_atomic_win(std::filesystem::path const& src, std::filesystem::path const& dest) -> bool {
        std::error_code ec;
        if (!std::filesystem::is_regular_file(src, ec)) return false;
        if (std::filesystem::exists(dest, ec) && !ec) {
            if (is_reparse_point_win(dest)) return false;
            if (std::filesystem::equivalent(src, dest, ec) && !ec) {
                return apply_privileged_dacl(dest);
            }
        }
        auto tmp = dest;
        tmp += L".tmp";
        if (is_reparse_point_win(tmp)) return false;
        if (!::CopyFileW(src.c_str(), tmp.c_str(), FALSE)) return false;
        if (!apply_privileged_dacl(tmp)) {
            (void)::DeleteFileW(tmp.c_str());
            return false;
        }
        if (!::MoveFileExW(tmp.c_str(), dest.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            (void)::DeleteFileW(tmp.c_str());
            return false;
        }
        return apply_privileged_dacl(dest);
    }

    inline auto cleanup_win_stage_dir(std::filesystem::path const& stage_dir) -> void {
        if (is_reparse_point_win(stage_dir)) return;
        for (wchar_t const* name : {L"nexus.exe", L"wintun.dll", L"nexus-tun-helper.exe"}) {
            auto p = stage_dir / name;
            if (!::DeleteFileW(p.c_str()) && ::GetLastError() != ERROR_FILE_NOT_FOUND) {
                (void)::MoveFileExW(p.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
            }
        }
        (void)::RemoveDirectoryW(stage_dir.c_str());
    }

    inline auto write_reg_sz(HKEY key, wchar_t const* name, std::string_view val) -> bool {
        auto w = utf8_to_wide(val);
        DWORD bytes = static_cast<DWORD>((w.size() + 1) * sizeof(wchar_t));
        return ::RegSetValueExW(key, name, 0, REG_SZ, reinterpret_cast<BYTE const*>(w.c_str()), bytes) == ERROR_SUCCESS;
    }

    inline auto read_reg_sz(HKEY key, wchar_t const* name) -> std::optional<std::string> {
        DWORD type = 0, bytes = 0;
        if (::RegQueryValueExW(key, name, nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS ||
            type != REG_SZ || bytes < sizeof(wchar_t) || bytes > 32768) {
            return std::nullopt;
        }
        std::wstring buf(bytes / sizeof(wchar_t), L'\0');
        if (::RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<LPBYTE>(buf.data()), &bytes) != ERROR_SUCCESS) {
            return std::nullopt;
        }
        while (!buf.empty() && buf.back() == L'\0') buf.pop_back();
        return wide_to_utf8(buf);
    }

    inline auto load_pinned_config_from_hklm() -> std::expected<desktop::TunHelperPinnedConfig, std::string> {
        HKEY key = nullptr;
        auto subkey = utf8_to_wide(desktop::kWinTunHelperRegSubkey);
        if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) {
            return std::unexpected("failed to open HKLM pinned config");
        }
        auto bin = read_reg_sz(key, L"Binary");
        auto staged = read_reg_sz(key, L"StagedBinary");
        auto sha = read_reg_sz(key, L"Sha256");
        auto cfg = read_reg_sz(key, L"Config");
        auto wd = read_reg_sz(key, L"Workdir");
        auto sid = read_reg_sz(key, L"OwnerSid");
        ::RegCloseKey(key);
        if (!bin || !staged || staged->empty() || !sha || !cfg || !sid) return std::unexpected("incomplete HKLM pinned config");
        if (!desktop::is_valid_sha256_hex(*sha)) return std::unexpected("invalid pinned SHA-256");
        if (!desktop::validate_windows_sid(*sid)) return std::unexpected("invalid pinned owner SID");
        for (char& c : *sha) if (c >= 'A' && c <= 'F') c = static_cast<char>(c - 'A' + 'a');
        return desktop::TunHelperPinnedConfig{std::move(*bin), std::move(*sha), std::move(*cfg), wd.value_or(std::string{}), std::move(*sid), std::move(*staged)};
    }

    inline auto save_pinned_config_to_hklm(desktop::TunHelperPinnedConfig const& cfg) -> bool {
        HKEY key = nullptr;
        auto subkey = utf8_to_wide(desktop::kWinTunHelperRegSubkey);
        if (::RegCreateKeyExW(HKEY_LOCAL_MACHINE, subkey.c_str(), 0, nullptr, 0,
                              KEY_WRITE | KEY_WOW64_64KEY, nullptr, &key, nullptr) != ERROR_SUCCESS) {
            return false;
        }
        bool ok = write_reg_sz(key, L"Binary", cfg.binary)
               && write_reg_sz(key, L"StagedBinary", cfg.staged_binary)
               && write_reg_sz(key, L"Sha256", cfg.sha256)
               && write_reg_sz(key, L"Config", cfg.config)
               && write_reg_sz(key, L"Workdir", cfg.workdir)
               && write_reg_sz(key, L"OwnerSid", cfg.owner);
        ::RegCloseKey(key);
        return ok;
    }
}
