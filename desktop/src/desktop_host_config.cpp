module;

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

module desktop.desktop_host_config;

import std;
import desktop.mini_json;

namespace desktop {
    namespace {
        auto path_to_utf8_host(std::filesystem::path const& p) -> std::string {
            auto u8 = p.u8string();
            return std::string(reinterpret_cast<char const*>(u8.data()), u8.size());
        }

        auto is_loopback_listen(std::string_view spec) noexcept -> bool {
            return spec.starts_with("127.0.0.1:") || spec.starts_with("[::1]:") || spec.starts_with("localhost:");
        }

        auto write_file_atomic_host(std::filesystem::path const& path, std::string_view content) -> bool {
            std::error_code ec;
            if (!path.parent_path().empty()) std::filesystem::create_directories(path.parent_path(), ec);
#ifdef _WIN32
            static std::atomic<std::uint64_t> seq{0};
            auto tmp = path;
            tmp += std::format(".tmp.{}.{}", ::GetCurrentProcessId(), seq.fetch_add(1, std::memory_order_relaxed));
            {
                std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
                if (!out) return false;
                out.write(content.data(), static_cast<std::streamsize>(content.size()));
                if (!out.good()) { out.close(); std::filesystem::remove(tmp, ec); return false; }
            }
            if (!::MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                std::filesystem::remove(tmp, ec);
                return false;
            }
            return true;
#else
            static std::atomic<std::uint64_t> seq{0};
            auto tmp = path.parent_path() /
                std::format(".{}.tmp.{}.{}", path.filename().string(), ::getpid(),
                            seq.fetch_add(1, std::memory_order_relaxed));
            int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
            if (fd < 0) return false;
            if (::fchmod(fd, 0600) != 0) { ::close(fd); ::unlink(tmp.c_str()); return false; }
            std::size_t off = 0;
            while (off < content.size()) {
                auto n = ::write(fd, content.data() + off, content.size() - off);
                if (n < 0 && errno == EINTR) continue;
                if (n <= 0) { ::close(fd); ::unlink(tmp.c_str()); return false; }
                off += static_cast<std::size_t>(n);
            }
            bool closed = (::close(fd) == 0);
            if (!closed || std::rename(tmp.c_str(), path.c_str()) != 0) { ::unlink(tmp.c_str()); return false; }
            return true;
#endif
        }

        auto generate_random_hex_token() -> std::string {
            std::array<unsigned char, 32> bytes{};
            bool filled = false;
#ifndef _WIN32
            int rfd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
            if (rfd >= 0) {
                std::size_t off = 0;
                while (off < bytes.size()) {
                    auto n = ::read(rfd, bytes.data() + off, bytes.size() - off);
                    if (n < 0 && errno == EINTR) continue;
                    if (n <= 0) break;
                    off += static_cast<std::size_t>(n);
                }
                ::close(rfd);
                filled = (off == bytes.size());
            }
#endif
            if (!filled) {
                std::random_device rd;
                for (auto& b : bytes) b = static_cast<unsigned char>(rd() & 0xFFu);
            }
            static constexpr char kHex[] = "0123456789abcdef";
            std::string out;
            out.reserve(bytes.size() * 2 + 1);
            for (unsigned char b : bytes) {
                out.push_back(kHex[(b >> 4) & 0xFu]);
                out.push_back(kHex[b & 0xFu]);
            }
            out.push_back('\n');
            return out;
        }
    }

    auto ensure_control_bearer_token(std::filesystem::path const& token_path) -> bool {
        if (token_path.empty()) return false;
        std::error_code ec;
        if (std::filesystem::is_regular_file(token_path, ec) && !ec && std::filesystem::file_size(token_path, ec) > 0 && !ec) {
            return true;
        }
        if (!token_path.parent_path().empty()) {
            std::filesystem::create_directories(token_path.parent_path(), ec);
#ifndef _WIN32
            (void)::chmod(token_path.parent_path().c_str(), 0700);
#endif
        }
        auto const token = generate_random_hex_token();
#ifdef _WIN32
        return write_file_atomic_host(token_path, token);
#else
        int fd = ::open(token_path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0) {
            if (errno == EEXIST) {
                return std::filesystem::is_regular_file(token_path, ec) && !ec &&
                       std::filesystem::file_size(token_path, ec) > 0 && !ec;
            }
            return false;
        }
        if (::fchmod(fd, 0600) != 0) { ::close(fd); ::unlink(token_path.c_str()); return false; }
        std::size_t off = 0;
        while (off < token.size()) {
            auto n = ::write(fd, token.data() + off, token.size() - off);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) { ::close(fd); ::unlink(token_path.c_str()); return false; }
            off += static_cast<std::size_t>(n);
        }
        return ::close(fd) == 0;
#endif
    }

    auto current_desktop_platform_id() noexcept -> std::string_view {
#ifdef _WIN32
        return "desktop-windows";
#elif defined(__APPLE__)
        return "desktop-macos";
#else
        return "desktop-linux";
#endif
    }

    auto is_valid_workers_spec(std::string_view spec) noexcept -> bool {
        if (spec.empty() || spec == "auto" || spec == "max") return true;
        std::string_view rest;
        if (spec.starts_with("max-")) rest = spec.substr(4);
        else if (spec.starts_with("auto-")) rest = spec.substr(5);
        else return false;
        if (rest.empty()) return false;
        for (char c : rest) {
            if (c < '0' || c > '9') return false;
        }
        unsigned parsed = 0;
        auto [ptr, ec] = std::from_chars(rest.data(), rest.data() + rest.size(), parsed);
        return ec == std::errc{} && ptr == rest.data() + rest.size();
    }

    auto make_default_desktop_host_config(
        std::filesystem::path const& cfg_dir,
        std::string_view control_socket) -> DesktopHostConfig {
        DesktopHostConfig cfg{};
        cfg.schema_version = 1;
        cfg.platform = std::string(current_desktop_platform_id());
        cfg.state_dir = path_to_utf8_host(cfg_dir / "state");
        cfg.cache_dir = path_to_utf8_host(cfg_dir / "cache");
        cfg.control_socket = std::string(control_socket);
        auto bearer_path = cfg_dir / "secrets" / "control-http.token";
        if (ensure_control_bearer_token(bearer_path)) {
            cfg.control_bearer_file = path_to_utf8_host(bearer_path);
        } else if (is_loopback_listen(cfg.control_http_listen)) {
            cfg.control_bearer_file.clear();
        }
        return cfg;
    }

    auto normalize_desktop_host_config(DesktopHostConfig& cfg, bool is_en) -> std::vector<std::string> {
        std::vector<std::string> notices;
        if (cfg.platform.empty()) cfg.platform = std::string(current_desktop_platform_id());
        if (cfg.workers < 0) cfg.workers = 1;
        if (cfg.workers_max < 0) cfg.workers_max = 0;
        if (!cfg.workers_spec.empty() && !is_valid_workers_spec(cfg.workers_spec)) {
            cfg.workers_spec.clear();
            notices.push_back(is_en
                ? "Invalid workers_spec reset to default (expected auto, max, max-<N>, or auto-<N>)."
                : "无效的 workers_spec 已重置为默认（仅支持 auto、max、max-<N> 或 auto-<N>）。");
        }
        if (cfg.tun_mtu < 576 || cfg.tun_mtu > 9000) cfg.tun_mtu = 1400;
        if (cfg.max_selector_members < 1) cfg.max_selector_members = 128;
        if (cfg.max_selector_members > 4096) cfg.max_selector_members = 4096;
        if (cfg.platform == "desktop-linux" && cfg.enable_tun && cfg.tun_strict_route) {
            bool const had_mixed = cfg.enable_mixed;
            bool const had_extra = !cfg.second_local_listen.empty() || !cfg.lan_listen.empty();
            if (had_mixed) cfg.enable_mixed = false;
            if (had_mixed || had_extra) {
                notices.push_back(is_en
                    ? "Linux strict-route forbids a second inbound; mixed/LAN local listeners are disabled while strict-route is active."
                    : "Linux 严格路由 (strict-route) 下核心不允许第二个入站，本地混合/局域网监听端口已自动禁用。");
            }
        }
        if (!cfg.enable_mixed && !cfg.enable_tun && cfg.second_local_listen.empty() && cfg.lan_listen.empty()) {
            notices.push_back(is_en
                ? "No inbound enabled (both Mixed proxy and TUN are off); enable at least one inbound before starting Core."
                : "混合代理与 TUN 入站均已关闭，启动核心前请至少启用一个入站。");
        }
        if (!cfg.control_bearer_file.empty()) {
            std::filesystem::path bp(std::u8string_view(
                reinterpret_cast<char8_t const*>(cfg.control_bearer_file.data()), cfg.control_bearer_file.size()));
            if (!ensure_control_bearer_token(bp) && is_loopback_listen(cfg.control_http_listen)) {
                cfg.control_bearer_file.clear();
            }
        }
        return notices;
    }

    auto desktop_host_to_json(DesktopHostConfig const& cfg) -> std::string {
        JsonObject desktop_obj{
            {"enable_mixed", cfg.enable_mixed},
            {"mixed_listen", cfg.mixed_listen},
            {"second_local_listen", cfg.second_local_listen},
            {"lan_listen", cfg.lan_listen},
            {"lan_username", cfg.lan_username},
            {"lan_password", cfg.lan_password},
            {"enable_tun", cfg.enable_tun},
            {"tun_interface_name", cfg.tun_interface_name},
            {"tun_mtu", cfg.tun_mtu},
            {"tun_inet4", cfg.tun_inet4},
            {"tun_inet6", cfg.tun_inet6},
            {"tun_auto_route", cfg.tun_auto_route},
            {"tun_strict_route", cfg.tun_strict_route},
            {"tun_route_exclude", json_from_string_vec(cfg.tun_route_exclude)},
            {"tun_route_exclude_private", cfg.tun_route_exclude_private},
            {"bind_interface", cfg.bind_interface},
            {"inet4_bind_address", cfg.inet4_bind_address},
            {"inet6_bind_address", cfg.inet6_bind_address},
            {"tun_elevation_mode", cfg.tun_elevation_mode},
            {"system_proxy_mode", cfg.system_proxy_mode},
            {"system_proxy_exceptions", cfg.system_proxy_exceptions},
            {"custom_pac_path", cfg.custom_pac_path},
            {"auto_launch", cfg.auto_launch},
            {"start_minimized", cfg.start_minimized},
            {"theme", cfg.theme},
            {"language", cfg.language},
            {"webdav_url", cfg.webdav_url},
            {"webdav_username", cfg.webdav_username},
            {"webdav_password", cfg.webdav_password},
            {"sync_passphrase", cfg.sync_passphrase},
            {"sync_device_label", cfg.sync_device_label},
            {"webdav_last_etag", cfg.webdav_last_etag},
            {"webdav_last_revision", cfg.webdav_last_revision},
        };
        JsonObject root{
            {"schema_version", cfg.schema_version},
            {"platform", cfg.platform.empty() ? std::string(current_desktop_platform_id()) : cfg.platform},
            {"log_level", cfg.log_level},
            {"log_file", cfg.log_file},
            {"workers", cfg.workers},
            {"state_dir", cfg.state_dir},
            {"cache_dir", cfg.cache_dir},
            {"control_socket", cfg.control_socket},
            {"control_http_listen", cfg.control_http_listen},
            {"control_bearer_file", cfg.control_bearer_file},
            {"ca_file", cfg.ca_file},
            {"include_sibling_nodes_in_selector", cfg.include_sibling_nodes_in_selector},
            {"max_selector_members", cfg.max_selector_members},
            {"desktop", JsonValue(std::move(desktop_obj))},
        };
        if (!cfg.workers_spec.empty()) root.emplace_back("workers_spec", cfg.workers_spec);
        if (cfg.workers_max > 0) root.emplace_back("workers_max", cfg.workers_max);
        return json_stringify(JsonValue(std::move(root)), true);
    }

    auto desktop_host_to_nonsecret_json(DesktopHostConfig const& cfg) -> std::string {
        DesktopHostConfig copy = cfg;
        copy.webdav_password.clear();
        copy.sync_passphrase.clear();
        copy.lan_password.clear();
        return desktop_host_to_json(copy);
    }

    auto desktop_host_to_core_json(DesktopHostConfig const& cfg) -> std::string {
        DesktopHostConfig copy = cfg;
        copy.webdav_password.clear();
        copy.sync_passphrase.clear();
        return desktop_host_to_json(copy);
    }

    auto load_sync_secrets(std::filesystem::path const& secrets_dir) -> SyncSecrets {
        SyncSecrets out{};
        if (secrets_dir.empty()) return out;
        auto const path = secrets_dir / "sync-creds.json";
        std::ifstream in(path, std::ios::binary);
        if (!in) return out;
        std::ostringstream ss;
        ss << in.rdbuf();
        auto parsed = json_parse(ss.str());
        if (!parsed || !parsed->is_object()) return out;
        auto const& obj = std::get<JsonObject>(parsed->data);
        out.webdav_password = json_get_string(obj, "webdav_password", "");
        out.sync_passphrase = json_get_string(obj, "sync_passphrase", "");
        out.lan_password = json_get_string(obj, "lan_password", "");
        return out;
    }

    auto save_sync_secrets(std::filesystem::path const& secrets_dir, SyncSecrets const& secrets) -> bool {
        if (secrets_dir.empty()) return false;
        std::error_code ec;
        std::filesystem::create_directories(secrets_dir, ec);
#ifndef _WIN32
        (void)::chmod(secrets_dir.c_str(), 0700);
#endif
        auto const path = secrets_dir / "sync-creds.json";
        if (secrets.webdav_password.empty() && secrets.sync_passphrase.empty() && secrets.lan_password.empty()) {
            std::filesystem::remove(path, ec);
            return true;
        }
        JsonObject obj{
            {"schema_version", static_cast<std::int64_t>(1)},
            {"webdav_password", secrets.webdav_password},
            {"sync_passphrase", secrets.sync_passphrase},
            {"lan_password", secrets.lan_password},
        };
        return write_file_atomic_host(path, json_stringify(JsonValue(std::move(obj)), false));
    }

    auto desktop_host_from_json(std::string_view text) -> std::expected<DesktopHostConfig, std::string> {
        auto parsed = json_parse(text);
        if (!parsed) return std::unexpected(parsed.error());
        if (!parsed->is_object()) return std::unexpected("host.json root must be a JSON object");
        auto const& root = std::get<JsonObject>(parsed->data);
        DesktopHostConfig cfg{};
        cfg.schema_version = json_get_i64(root, "schema_version", 1);
        if (cfg.schema_version != 1) return std::unexpected("unsupported host.json schema_version");
        cfg.platform = json_get_string(root, "platform", current_desktop_platform_id());
        cfg.log_level = json_get_string(root, "log_level", "info");
        cfg.log_file = json_get_string(root, "log_file", "");
        cfg.workers = json_get_i64(root, "workers", 1);
        if (cfg.workers < 0) cfg.workers = 1;
        cfg.workers_spec = json_get_string(root, "workers_spec", "");
        cfg.workers_max = std::max<std::int64_t>(0, json_get_i64(root, "workers_max", 0));
        cfg.state_dir = json_get_string(root, "state_dir", "");
        cfg.cache_dir = json_get_string(root, "cache_dir", "");
        cfg.control_socket = json_get_string(root, "control_socket", "");
        cfg.control_http_listen = json_get_string(root, "control_http_listen", "127.0.0.1:19090");
        cfg.control_bearer_file = json_get_string(root, "control_bearer_file", "");
        cfg.ca_file = json_get_string(root, "ca_file", "");
        cfg.include_sibling_nodes_in_selector = json_get_bool(root, "include_sibling_nodes_in_selector", true);
        cfg.max_selector_members = json_get_i64(root, "max_selector_members", 128);

        if (auto const* d = json_find(root, "desktop"); d && d->is_object()) {
            auto const& obj = std::get<JsonObject>(d->data);
            cfg.enable_mixed = json_get_bool(obj, "enable_mixed", true);
            cfg.mixed_listen = json_get_string(obj, "mixed_listen", "127.0.0.1:7890");
            cfg.second_local_listen = json_get_string(obj, "second_local_listen", "");
            cfg.lan_listen = json_get_string(obj, "lan_listen", "");
            cfg.lan_username = json_get_string(obj, "lan_username", "");
            cfg.lan_password = json_get_string(obj, "lan_password", "");
            cfg.enable_tun = json_get_bool(obj, "enable_tun", false);
            cfg.tun_interface_name = json_get_string(obj, "tun_interface_name", "nexus-tun0");
            cfg.tun_mtu = json_get_i64(obj, "tun_mtu", 1400);
            cfg.tun_inet4 = json_get_string(obj, "tun_inet4", "172.19.0.1/30");
            cfg.tun_inet6 = json_get_string(obj, "tun_inet6", "");
            cfg.tun_auto_route = json_get_bool(obj, "tun_auto_route", true);
            cfg.tun_strict_route = json_get_bool(obj, "tun_strict_route", false);
            cfg.tun_route_exclude = json_get_string_vec(obj, "tun_route_exclude");
            cfg.tun_route_exclude_private = json_get_bool(obj, "tun_route_exclude_private", true);
            cfg.bind_interface = json_get_string(obj, "bind_interface", "");
            cfg.inet4_bind_address = json_get_string(obj, "inet4_bind_address", "");
            cfg.inet6_bind_address = json_get_string(obj, "inet6_bind_address", "");
            cfg.tun_elevation_mode = json_get_string(obj, "tun_elevation_mode", "persistent");
            cfg.system_proxy_mode = json_get_string(obj, "system_proxy_mode", "off");
            cfg.system_proxy_exceptions = json_get_string(obj, "system_proxy_exceptions", "");
            cfg.custom_pac_path = json_get_string(obj, "custom_pac_path", "");
            cfg.auto_launch = json_get_bool(obj, "auto_launch", false);
            cfg.start_minimized = json_get_bool(obj, "start_minimized", false);
            cfg.theme = json_get_string(obj, "theme", "system");
            cfg.language = json_get_string(obj, "language", "system");
            cfg.webdav_url = json_get_string(obj, "webdav_url", "");
            cfg.webdav_username = json_get_string(obj, "webdav_username", "");
            cfg.webdav_password = json_get_string(obj, "webdav_password", "");
            cfg.sync_passphrase = json_get_string(obj, "sync_passphrase", "");
            cfg.sync_device_label = json_get_string(obj, "sync_device_label", "");
            cfg.webdav_last_etag = json_get_string(obj, "webdav_last_etag", "");
            cfg.webdav_last_revision = json_get_i64(obj, "webdav_last_revision", 0);
        }
        return cfg;
    }

    auto load_desktop_host_config(
        std::filesystem::path const& path,
        std::filesystem::path const& cfg_dir,
        std::string_view control_socket) -> DesktopHostConfig {
        auto fallback = make_default_desktop_host_config(cfg_dir, control_socket);
        std::ifstream in(path, std::ios::binary);
        if (!in) return fallback;
        std::ostringstream ss;
        ss << in.rdbuf();
        auto parsed = desktop_host_from_json(ss.str());
        if (!parsed) return fallback;
        if (parsed->state_dir.empty()) parsed->state_dir = fallback.state_dir;
        if (parsed->cache_dir.empty()) parsed->cache_dir = fallback.cache_dir;
        if (parsed->control_socket.empty()) parsed->control_socket = fallback.control_socket;
        if (parsed->control_bearer_file.empty()) parsed->control_bearer_file = fallback.control_bearer_file;
        return *parsed;
    }

    auto save_desktop_host_config(std::filesystem::path const& path, DesktopHostConfig const& cfg) -> bool {
        return write_file_atomic_host(path, desktop_host_to_json(cfg));
    }
}
