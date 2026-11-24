#include "../../include/nexus/core_c_api.h"

import std;
import utility;
import config;
import provider;
import cli.proxy_run;
import cli.route_files;
import platform.socket_options;
import platform.tun_bridge;
import platform.system_proxy;

auto nexus_run(int argc, char** argv) -> int;
auto nexus_run_embedded(int argc, char** argv) -> int;
auto nexus_check(int argc, char** argv) -> int;

namespace {
    std::mutex g_lifecycle_mu;
    std::atomic<bool> g_core_running{false};

    auto write_c_buf(std::string_view text, char* dst, std::size_t cap) noexcept -> void {
        if (!dst || cap == 0) return;
        auto n = std::min(text.size(), cap - 1);
        std::ranges::copy_n(text.data(), n, dst);
        dst[n] = '\0';
    }

    auto feature_list_literal() -> char const* {
        static std::string const features = [] {
            std::vector<std::string_view> f;
#ifdef NEXUS_ENABLE_IO_URING
            f.push_back("io-uring");
#endif
#ifdef NEXUS_ENABLE_KTLS
            f.push_back("ktls");
#endif
#ifdef NEXUS_ENABLE_TUN
            f.push_back("tun-inbound");
#endif
#ifdef NEXUS_ENABLE_FAKEIP
            f.push_back("dns-fakeip");
#endif
#ifdef NEXUS_DNS_RESPONSE
            f.push_back("dns-response");
#endif
#ifdef NEXUS_ENABLE_CONTROL_HTTP
            f.push_back("control-http");
#endif
#ifdef NEXUS_ENABLE_OPENVPN
            f.push_back("openvpn");
#endif
#ifdef NEXUS_ENABLE_OPENCONNECT
            f.push_back("openconnect");
#endif
            std::string out;
            for (std::size_t i = 0; i < f.size(); ++i) {
                if (i) out.push_back(',');
                out += f[i];
            }
            return out;
        }();
        return features.c_str();
    }
}

extern "C" {
    const char* nexus_core_version(void) {
        return "0.1.0";
    }

    int nexus_core_is_running(void) {
        return g_core_running.load(std::memory_order_acquire) ? 1 : 0;
    }

    void nexus_core_request_stop(void) {
        try {
            std::lock_guard lk(g_lifecycle_mu);
            cli::request_proxy_stop();
        } catch (...) {}
    }

    void nexus_core_request_reload(void) {
        try {
            std::lock_guard lk(g_lifecycle_mu);
            cli::request_proxy_reload();
        } catch (...) {}
    }

    int nexus_core_check_config(const char* config_path) {
        try {
            if (!config_path || config_path[0] == '\0') return 2;
            std::string arg0 = "nexus-check";
            std::string path = config_path;
            char* argv[] = {arg0.data(), path.data(), nullptr};
            return nexus_check(2, argv);
        } catch (...) {
            return 1;
        }
    }

    int nexus_core_run_args(int argc, char* const* argv) {
        try {
            if (argc <= 0 || !argv) return 2;
            std::vector<std::string> storage;
            storage.reserve(static_cast<std::size_t>(argc));
            std::optional<std::filesystem::path> pending_dir;
            for (int i = 0; i < argc; ++i) {
                if (!argv[i]) return 2;
                std::string_view arg(argv[i]);
                if (arg == "-D" || arg == "--directory") {
                    if (i + 1 >= argc || !argv[i + 1]) return 2;
                    std::error_code ec;
                    auto dir = std::filesystem::canonical(argv[i + 1], ec);
                    if (ec || !std::filesystem::is_directory(dir, ec)) return 2;
                    pending_dir = std::move(dir);
                    ++i;
                    continue;
                }
                storage.emplace_back(arg);
            }
            if (storage.empty()) return 2;
            {
                std::lock_guard lk(g_lifecycle_mu);
                if (g_core_running.load(std::memory_order_acquire)) return 1;
                if (pending_dir) cli::set_working_directory(std::move(*pending_dir));
                cli::ensure_http_fetchers_registered();
                cli::reset_proxy_signals();
                g_core_running.store(true, std::memory_order_release);
            }
            utility::scope_exit reset_flag([&] {
                std::lock_guard lk(g_lifecycle_mu);
                g_core_running.store(false, std::memory_order_release);
            });
            std::vector<char*> mutable_argv;
            mutable_argv.reserve(storage.size() + 1);
            for (auto& item : storage) mutable_argv.push_back(item.data());
            mutable_argv.push_back(nullptr);
            return nexus_run_embedded(static_cast<int>(storage.size()), mutable_argv.data());
        } catch (...) {
            return 1;
        }
    }

    void nexus_core_set_protect_fd_callback(nexus_protect_fd_fn cb, void* ctx) {
        try {
            platform::set_protect_fd_callback(cb, ctx);
        } catch (...) {}
    }

    void nexus_core_set_tun_fd(int fd, int adopt, int skip_ioctl) {
        try {
            platform::set_external_tun_fd(fd, adopt != 0, skip_ioctl != 0);
        } catch (...) {}
    }

    int nexus_core_tun_bridge_enable(int enabled, unsigned short mtu,
        nexus_packet_output_fn on_outbound_packet, void* ctx) {
        try {
            if (enabled && mtu != 0 && mtu < 68) return -1;
            auto effective_mtu = static_cast<std::uint16_t>(mtu == 0 ? 1500 : mtu);
            (void)platform::enable_global_tun_bridge(enabled != 0, effective_mtu, on_outbound_packet, ctx);
            return 0;
        } catch (...) {
            return -1;
        }
    }

    int nexus_core_tun_bridge_inject(const unsigned char* packet, size_t len) {
        try {
            if (!packet || len == 0) return -1;
            auto bridge = platform::global_tun_bridge();
            if (!bridge) return -2;
            auto ok = bridge->inject_packet(std::span<std::uint8_t const>(packet, len));
            return ok ? 0 : -3;
        } catch (...) {
            return -1;
        }
    }

    int nexus_core_tun_bridge_pop_outbound(unsigned char* out_buf, size_t capacity, size_t* out_len) {
        try {
            if (out_len) *out_len = 0;
            if (!out_buf || capacity == 0) return -1;
            auto bridge = platform::global_tun_bridge();
            if (!bridge) return -2;
            auto copied = bridge->pop_outbound(std::span<std::uint8_t>(out_buf, capacity));
            if (!copied) return 1;
            if (out_len) *out_len = *copied;
            return 0;
        } catch (...) {
            return -1;
        }
    }

    const char* nexus_core_build_features(void) {
        try {
            return feature_list_literal();
        } catch (...) {
            return "";
        }
    }

    int nexus_core_check_config_text(const char* kdl_text, char* err_buf, size_t err_cap) {
        try {
            write_c_buf({}, err_buf, err_cap);
            if (!kdl_text) {
                write_c_buf("kdl_text must not be null", err_buf, err_cap);
                return 2;
            }
            auto parsed = config::parse_kdl(kdl_text);
            if (!parsed) {
                write_c_buf(parsed.error(), err_buf, err_cap);
                return 1;
            }
            return 0;
        } catch (...) {
            write_c_buf("internal error", err_buf, err_cap);
            return 1;
        }
    }

    int nexus_core_convert_config(const char* format, const char* input_text,
        char* out_buf, size_t out_cap, size_t* out_len, char* err_buf, size_t err_cap) {
        try {
            if (out_len) *out_len = 0;
            write_c_buf({}, err_buf, err_cap);
            if (!input_text) {
                write_c_buf("input_text must not be null", err_buf, err_cap);
                return -1;
            }
            provider::ConvertOptions opts{};
            std::string_view fmt = format ? std::string_view(format) : std::string_view("auto");
            if (fmt == "auto" || fmt.empty()) opts.format = provider::ProviderFormat::auto_detect;
            else if (fmt == "clash" || fmt == "clash-yaml") opts.format = provider::ProviderFormat::clash_yaml;
            else if (fmt == "singbox" || fmt == "sing-box" || fmt == "singbox-json")
                opts.format = provider::ProviderFormat::singbox_json;
            else if (fmt == "uri" || fmt == "uri-list") opts.format = provider::ProviderFormat::uri_list;
            else if (fmt == "base64") opts.format = provider::ProviderFormat::base64_uri;
            else if (fmt == "sip008") opts.format = provider::ProviderFormat::sip008_json;
            else {
                write_c_buf("unsupported config format", err_buf, err_cap);
                return -1;
            }
            auto res = provider::convert_config_to_kdl(input_text, opts);
            if (!res) {
                write_c_buf(res.error(), err_buf, err_cap);
                return -2;
            }
            auto const& kdl = res->first;
            if (out_len) *out_len = kdl.size();
            if (!out_buf || out_cap <= kdl.size()) return -4;
            std::ranges::copy(kdl, out_buf);
            out_buf[kdl.size()] = '\0';
            return 0;
        } catch (...) {
            write_c_buf("internal error", err_buf, err_cap);
            return -2;
        }
    }

    int nexus_core_set_system_proxy(int enabled, const char* host,
        unsigned short http_port, unsigned short socks_port, const char* bypass_csv) {
        try {
            if (!enabled) return platform::disable_system_proxy() ? 0 : -1;
            platform::SystemProxyConfig cfg{
                .host = (host && host[0]) ? std::string(host) : std::string("127.0.0.1"),
                .http_port = http_port,
                .socks_port = socks_port,
                .bypass = (bypass_csv && bypass_csv[0]) ? platform::parse_bypass_csv(bypass_csv) : platform::default_bypass_list(),
            };
            return platform::enable_system_proxy(cfg) ? 0 : -1;
        } catch (...) {
            return -1;
        }
    }

    int nexus_core_runtime_info_json(char* out_buf, size_t out_cap, size_t* out_len) {
        try {
            if (out_len) *out_len = 0;
#if defined(_WIN32)
            constexpr std::string_view os = "windows";
#elif defined(__APPLE__)
            constexpr std::string_view os = "darwin";
#elif defined(__ANDROID__)
            constexpr std::string_view os = "android";
#else
            constexpr std::string_view os = "linux";
#endif
#if defined(__aarch64__) || defined(_M_ARM64)
            constexpr std::string_view arch = "arm64";
#elif defined(__x86_64__) || defined(_M_X64)
            constexpr std::string_view arch = "amd64";
#else
            constexpr std::string_view arch = "unknown";
#endif
            auto json = std::format(
                "{{\"version\":\"0.1.0\",\"os\":\"{}\",\"arch\":\"{}\",\"running\":{},\"protect_fd\":{},\"tun_bridge\":{},\"features\":\"{}\"}}",
                os, arch, g_core_running.load(std::memory_order_acquire) ? "true" : "false",
                platform::has_protect_fd_callback() ? "true" : "false",
                platform::global_tun_bridge() ? "true" : "false",
                feature_list_literal());
            if (out_len) *out_len = json.size();
            if (!out_buf || out_cap <= json.size()) return -4;
            std::ranges::copy(json, out_buf);
            out_buf[json.size()] = '\0';
            return 0;
        } catch (...) {
            return -1;
        }
    }
}
