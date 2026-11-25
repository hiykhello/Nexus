module;

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wininet.h>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

module desktop.workspace_sync;

import std;

#include "webdav_http_detail.hpp"

namespace desktop {
    namespace {
        auto resolve_remote_envelope_urls(std::string_view validated_url) -> std::pair<std::string, std::string> {
            auto q = validated_url.find_first_of("?#");
            std::string base(q == std::string_view::npos ? validated_url : validated_url.substr(0, q));
            if (base.ends_with(".enc")) {
                auto slash = base.rfind('/');
                return {slash != std::string::npos ? base.substr(0, slash + 1) : std::string{}, base};
            }
            if (!base.ends_with('/')) base.push_back('/');
            return {base, base + "nexus-workspace-v1.enc"};
        }

        auto prune_old_backups(std::filesystem::path const& backups_dir, std::size_t max_keep) -> void {
            if (max_keep == 0 || backups_dir.empty()) return;
            std::error_code ec;
            std::vector<std::filesystem::path> files;
            for (auto const& ent : std::filesystem::directory_iterator(backups_dir, ec)) {
                if (ec || !ent.is_regular_file(ec)) continue;
                auto fn = ent.path().filename().string();
                if (fn.starts_with("workspace-backup-") && fn.ends_with(".json")) files.push_back(ent.path());
            }
            if (files.size() <= max_keep) return;
            std::ranges::sort(files, [](auto const& a, auto const& b) {
                return a.filename().string() < b.filename().string();
            });
            for (std::size_t i = 0; i + max_keep < files.size(); ++i) {
                std::filesystem::remove(files[i], ec);
            }
        }

        auto write_backup_0600(
            std::filesystem::path const& src,
            std::filesystem::path const& backups_dir,
            std::size_t max_keep,
            bool& had_source) -> std::string {
            had_source = false;
            std::error_code ec;
            if (!std::filesystem::is_regular_file(src, ec)) return {};
            std::ifstream in(src, std::ios::binary);
            if (!in) return {};
            std::ostringstream ss;
            ss << in.rdbuf();
            auto data = ss.str();
            if (data.empty()) return {};
            had_source = true;
            std::filesystem::create_directories(backups_dir, ec);
#ifndef _WIN32
            (void)::chmod(backups_dir.c_str(), 0700);
#endif
            static std::atomic<std::uint64_t> bseq{0};
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            auto dst = backups_dir / std::format("workspace-backup-{:016d}-{:06d}.json", ms, bseq.fetch_add(1, std::memory_order_relaxed));
#ifdef _WIN32
            HANDLE hf = ::CreateFileW(dst.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hf == INVALID_HANDLE_VALUE) return {};
            std::size_t off = 0;
            bool ok = true;
            while (off < data.size()) {
                DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(data.size() - off, 1u << 20));
                DWORD w = 0;
                if (!::WriteFile(hf, data.data() + off, chunk, &w, nullptr) || w == 0) { ok = false; break; }
                off += w;
            }
            ::CloseHandle(hf);
            if (!ok) { std::filesystem::remove(dst, ec); return {}; }
#else
            int fd = ::open(dst.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
            if (fd < 0) return {};
            if (::fchmod(fd, 0600) != 0) { ::close(fd); ::unlink(dst.c_str()); return {}; }
            std::size_t off = 0;
            while (off < data.size()) {
                auto w = ::write(fd, data.data() + off, data.size() - off);
                if (w < 0 && errno == EINTR) continue;
                if (w <= 0) { ::close(fd); ::unlink(dst.c_str()); return {}; }
                off += static_cast<std::size_t>(w);
            }
            if (::close(fd) != 0) return {};
#endif
            prune_old_backups(backups_dir, max_keep);
            auto u8 = dst.u8string();
            return std::string(reinterpret_cast<char const*>(u8.data()), u8.size());
        }
    }

    auto backup_workspace_file_0600(
        std::filesystem::path const& local_workspace_path,
        std::filesystem::path const& backups_dir,
        std::size_t max_keep) -> std::string {
        bool had_src = false;
        return write_backup_0600(local_workspace_path, backups_dir, max_keep, had_src);
    }

    auto validate_webdav_url(std::string_view url) -> std::expected<std::string, std::string> {
        auto parsed = webdav_detail::parse_dav_url(url);
        if (!parsed) return std::unexpected(parsed.error());
        return std::string(webdav_detail::trim(url));
    }

    auto webdav_request(
        std::string_view method,
        std::string_view url,
        std::string_view username,
        std::string_view password,
        std::span<std::pair<std::string, std::string> const> extra_headers,
        std::string_view body) -> WebDavResponse {
        WebDavResponse err{};
        if (method.empty() || webdav_detail::has_ctl(method) ||
            webdav_detail::has_ctl(username) || webdav_detail::has_ctl(password)) {
            err.error = "invalid WebDAV method or credentials";
            return err;
        }
        for (auto const& [k, v] : extra_headers) {
            if (k.empty() || webdav_detail::has_ctl(k) || webdav_detail::has_ctl(v)) {
                err.error = "invalid WebDAV header";
                return err;
            }
        }
        auto parsed = webdav_detail::parse_dav_url(url);
        if (!parsed) { err.error = parsed.error(); return err; }
        return webdav_detail::execute_http(*parsed, method, webdav_detail::trim(url), username, password, extra_headers, body);
    }

    auto webdav_push_envelope(
        WebDavConfig const& cfg,
        std::string_view envelope_json,
        std::int64_t local_revision,
        bool force_overwrite) -> WebDavSyncOutcome {
        WebDavSyncOutcome out{};
        auto vurl = validate_webdav_url(cfg.url);
        if (!vurl) { out.message = vurl.error(); return out; }
        auto [dir_url, file_url] = resolve_remote_envelope_urls(*vurl);

        auto head = webdav_request("HEAD", file_url, cfg.username, cfg.password);
        if (!head.transport_ok) { out.message = head.error.empty() ? "WebDAV HEAD failed" : head.error; return out; }
        if (head.status_code == 401 || head.status_code == 403) {
            out.message = std::format("WebDAV authentication failed (HTTP {})", head.status_code);
            return out;
        }

        std::vector<std::pair<std::string, std::string>> put_hdrs{{"Content-Type", "application/json"}};
        if (head.status_code == 404) {
            if (!dir_url.empty()) (void)webdav_request("MKCOL", dir_url, cfg.username, cfg.password);
            if (!force_overwrite) put_hdrs.emplace_back("If-None-Match", "*");
        } else if (head.status_code >= 200 && head.status_code < 300) {
            if (!force_overwrite) {
                bool const etag_mismatch = cfg.last_etag.empty() || head.etag != cfg.last_etag;
                if (etag_mismatch || head.etag.empty()) {
                    auto get = webdav_request("GET", file_url, cfg.username, cfg.password);
                    if (!get.transport_ok || get.status_code < 200 || get.status_code >= 300) {
                        out.status = WebDavSyncStatus::error;
                        out.message = !get.transport_ok
                            ? (get.error.empty() ? "WebDAV GET failed during conflict check" : get.error)
                            : std::format("WebDAV GET failed during conflict check (HTTP {})", get.status_code);
                        return out;
                    }
                    auto meta = parse_sync_envelope_meta(get.body);
                    if (!meta.valid || etag_mismatch || meta.revision != cfg.last_revision) {
                        out.status = WebDavSyncStatus::conflict;
                        out.remote_etag = !get.etag.empty() ? get.etag : head.etag;
                        out.remote_revision = meta.valid ? meta.revision : 0;
                        out.remote_updated_at_ms = meta.valid ? meta.updated_at_ms : 0;
                        out.remote_device_label = meta.valid ? meta.device_label : std::string("unknown");
                        out.message = meta.valid
                            ? std::format("Remote sync conflict (remote rev {}, local rev {})", meta.revision, local_revision)
                            : "Remote snapshot is corrupt or unrecognized; inspect remote or force overwrite";
                        return out;
                    }
                }
                if (!head.etag.empty()) put_hdrs.emplace_back("If-Match", head.etag);
            }
        } else {
            out.message = std::format("WebDAV HEAD returned HTTP {}", head.status_code);
            return out;
        }

        auto put = webdav_request("PUT", file_url, cfg.username, cfg.password, put_hdrs, envelope_json);
        if (!put.transport_ok) { out.message = put.error.empty() ? "WebDAV PUT failed" : put.error; return out; }
        if (put.status_code == 412) {
            auto get = webdav_request("GET", file_url, cfg.username, cfg.password);
            out.status = WebDavSyncStatus::conflict;
            if (get.transport_ok && get.status_code >= 200 && get.status_code < 300) {
                auto meta = parse_sync_envelope_meta(get.body);
                out.remote_etag = get.etag;
                if (meta.valid) {
                    out.remote_revision = meta.revision;
                    out.remote_updated_at_ms = meta.updated_at_ms;
                    out.remote_device_label = meta.device_label;
                }
            }
            out.message = "Remote snapshot changed concurrently (HTTP 412)";
            return out;
        }
        if (put.status_code < 200 || put.status_code >= 300) {
            out.message = std::format("WebDAV PUT failed (HTTP {})", put.status_code);
            return out;
        }
        out.status = WebDavSyncStatus::ok;
        out.remote_etag = put.etag;
        if (out.remote_etag.empty()) {
            auto h2 = webdav_request("HEAD", file_url, cfg.username, cfg.password);
            if (h2.transport_ok) out.remote_etag = h2.etag;
        }
        out.remote_revision = local_revision;
        out.message = "Encrypted snapshot uploaded";
        return out;
    }

    auto webdav_pull_envelope(
        WebDavConfig const& cfg,
        std::filesystem::path const& local_workspace_path,
        std::filesystem::path const& backups_dir,
        std::int64_t local_revision,
        bool force_pull) -> WebDavSyncOutcome {
        WebDavSyncOutcome out{};
        auto vurl = validate_webdav_url(cfg.url);
        if (!vurl) { out.message = vurl.error(); return out; }
        auto [_, file_url] = resolve_remote_envelope_urls(*vurl);

        auto get = webdav_request("GET", file_url, cfg.username, cfg.password);
        if (!get.transport_ok) { out.message = get.error.empty() ? "WebDAV GET failed" : get.error; return out; }
        if (get.status_code == 404) { out.status = WebDavSyncStatus::not_found; out.message = "No remote snapshot found"; return out; }
        if (get.status_code < 200 || get.status_code >= 300) {
            out.message = std::format("WebDAV GET failed (HTTP {})", get.status_code);
            return out;
        }
        auto meta = parse_sync_envelope_meta(get.body);
        if (!meta.valid) { out.message = "Remote file is not a valid nexus-sync-v1 envelope"; return out; }

        out.remote_etag = get.etag;
        out.remote_revision = meta.revision;
        out.remote_updated_at_ms = meta.updated_at_ms;
        out.remote_device_label = meta.device_label;
        bool const pull_conflict =
            (cfg.last_revision > 0 && local_revision > cfg.last_revision) ||
            (cfg.last_revision == 0 && local_revision > 1) ||
            (local_revision > 1 && meta.revision < local_revision);
        if (!force_pull && pull_conflict) {
            out.status = WebDavSyncStatus::conflict;
            out.message = std::format("Local workspace has unsynced edits or newer revision (local rev {}, remote rev {})",
                                      local_revision, meta.revision);
            return out;
        }
        if (!local_workspace_path.empty() && !backups_dir.empty()) {
            bool had_src = false;
            out.backup_path = write_backup_0600(local_workspace_path, backups_dir, 5, had_src);
            if (had_src && out.backup_path.empty()) {
                out.message = "Failed to create pre-pull local workspace backup; pull aborted";
                return out;
            }
        }
        out.status = WebDavSyncStatus::ok;
        out.envelope_json = std::move(get.body);
        out.message = "Remote encrypted snapshot downloaded";
        return out;
    }
}
