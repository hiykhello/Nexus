module;
#ifndef _WIN32
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
module desktop.profile_store;

import std;

namespace desktop {
    namespace {
        auto atomic_write_file(std::filesystem::path const& target,
                               std::string_view content,
                               bool private_mode) -> bool {
            std::error_code ec;
            auto parent = target.parent_path();
            if (!parent.empty()) std::filesystem::create_directories(parent, ec);
#ifndef _WIN32
            auto tmp = parent / std::format(".{}.{}.tmp", target.filename().string(), ::getpid());
            if (private_mode) {
                int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
                if (fd < 0) return false;
                (void)::fchmod(fd, 0600);
                std::size_t off = 0;
                bool ok = true;
                while (off < content.size()) {
                    auto n = ::write(fd, content.data() + off, content.size() - off);
                    if (n < 0 && errno == EINTR) continue;
                    if (n <= 0) { ok = false; break; }
                    off += static_cast<std::size_t>(n);
                }
                if (::close(fd) != 0) ok = false;
                if (!ok) {
                    ::unlink(tmp.c_str());
                    return false;
                }
            } else {
                std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
                if (!out) return false;
                out.write(content.data(), static_cast<std::streamsize>(content.size()));
                if (!out.good()) {
                    out.close();
                    std::filesystem::remove(tmp, ec);
                    return false;
                }
            }
#else
            (void)private_mode;
            auto tmp = parent / ("." + target.filename().string() + ".tmp");
            {
                std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
                if (!out) return false;
                out.write(content.data(), static_cast<std::streamsize>(content.size()));
                if (!out.good()) {
                    out.close();
                    std::filesystem::remove(tmp, ec);
                    return false;
                }
            }
#endif
            std::filesystem::rename(tmp, target, ec);
            if (ec) {
                std::filesystem::remove(tmp, ec);
                return false;
            }
            return true;
        }
    }

    ProfileStore::ProfileStore(std::filesystem::path root)
        : root_(std::move(root)),
          profiles_dir_(root_ / "profiles"),
          secrets_dir_(root_ / "secrets") {
        std::error_code ec;
        std::filesystem::create_directories(profiles_dir_, ec);
        std::filesystem::create_directories(secrets_dir_, ec);
#ifndef _WIN32
        (void)::chmod(secrets_dir_.c_str(), 0700);
#endif
    }

    auto ProfileStore::sanitize_id(std::string_view raw) -> std::string {
        std::string out;
        out.reserve(std::min<std::size_t>(raw.size(), 64));
        for (unsigned char c : raw) {
            if (out.size() >= 64) break;
            if (std::isalnum(c) || c == '.' || c == '_' || c == '-') out.push_back(static_cast<char>(c));
            else if (!out.empty() && out.back() != '-') out.push_back('-');
        }
        while (!out.empty() && (out.front() == '-' || out.front() == '.')) out.erase(out.begin());
        while (!out.empty() && out.back() == '-') out.pop_back();
        return out.empty() ? "profile" : out;
    }

    auto ProfileStore::list(this ProfileStore const& self) -> std::vector<ProfileEntry> {
        std::vector<ProfileEntry> entries;
        std::error_code ec;
        for (auto const& item : std::filesystem::directory_iterator(self.profiles_dir_, ec)) {
            if (!item.is_regular_file(ec)) continue;
            auto path = item.path();
            if (path.extension() != ".kdl") continue;
            auto id = path.stem().string();
            auto ftime = item.last_write_time(ec);
            auto secs = std::chrono::duration_cast<std::chrono::seconds>(ftime.time_since_epoch()).count();
            entries.push_back({id, id, path, static_cast<std::int64_t>(secs)});
        }
        std::ranges::sort(entries, {}, &ProfileEntry::id);
        return entries;
    }

    auto ProfileStore::active_id(this ProfileStore const& self) -> std::string {
        std::ifstream in(self.root_ / ".active_profile");
        std::string line;
        if (std::getline(in, line)) {
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n' || line.back() == ' ')) {
                line.pop_back();
            }
            return line;
        }
        return {};
    }

    auto ProfileStore::set_active(this ProfileStore const& self, std::string_view id) -> bool {
        auto clean = sanitize_id(id);
        return atomic_write_file(self.root_ / ".active_profile", clean + "\n", false);
    }

    auto ProfileStore::save_profile(this ProfileStore const& self,
                                    std::string_view name,
                                    std::string_view kdl_content) -> std::optional<ProfileEntry> {
        auto id = sanitize_id(name);
        auto path = self.profiles_dir_ / (id + ".kdl");
        if (!atomic_write_file(path, kdl_content, false)) return std::nullopt;
        std::error_code ec;
        auto ftime = std::filesystem::last_write_time(path, ec);
        auto secs = std::chrono::duration_cast<std::chrono::seconds>(ftime.time_since_epoch()).count();
        return ProfileEntry{id, id, path, static_cast<std::int64_t>(secs)};
    }

    auto ProfileStore::remove_profile(this ProfileStore const& self, std::string_view id) -> bool {
        auto safe = sanitize_id(id);
        std::error_code ec;
        bool removed = std::filesystem::remove(self.profiles_dir_ / (safe + ".kdl"), ec);
        if (removed && self.active_id() == safe) {
            std::filesystem::remove(self.root_ / ".active_profile", ec);
        }
        return removed;
    }

    auto ProfileStore::write_secret(this ProfileStore const& self,
                                    std::string_view tag,
                                    std::string_view secret) -> std::optional<std::filesystem::path> {
        auto path = self.secrets_dir_ / (sanitize_id(tag) + ".secret");
        std::string payload(secret);
        if (!payload.empty() && payload.back() != '\n') payload.push_back('\n');
        if (!atomic_write_file(path, payload, true)) return std::nullopt;
        return path;
    }
}
