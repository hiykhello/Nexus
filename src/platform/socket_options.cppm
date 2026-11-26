export module platform.socket_options;
import std;
export import containers.inplace_vector;
export import functional;
import platform.platform_defaults;

export namespace platform {
    // The caller owns a successful descriptor until an asynchronous socket
    // adopts it. Linux MPTCP creation failures are never replaced with TCP.
    [[nodiscard]] auto open_physical_socket(bool ipv6, bool datagram, bool multipath,
        std::string const& network_namespace) noexcept -> std::expected<int, std::error_code>;
    auto close_unadopted_socket(int fd) noexcept -> void;

    struct RoutingMarkFilter {
        std::uint32_t mark = 0, mask = 0xffffffffU;
        [[nodiscard]] auto valid() const noexcept -> bool { return mask && !(mark & ~mask); }
    };

    using SocketDeadline = std::chrono::steady_clock::time_point;

    // Global in-process socket protection hook (e.g., Android VpnService.protect / iOS bypass).
    // C/FFI compatible signature; returning 0 indicates success, non-zero indicates an OS errno.
    using ProtectFdCallback = int (*)(int fd, void* ctx);
    auto set_protect_fd_callback(ProtectFdCallback cb, void* ctx = nullptr) noexcept -> void;
    [[nodiscard]] auto has_protect_fd_callback() noexcept -> bool;
    [[nodiscard]] auto invoke_protect_fd(int fd) noexcept -> std::error_code;

    namespace network {
        enum class Type : std::uint8_t { ethernet, wifi, cellular, vpn, other };
        enum class Strategy : std::uint8_t { require, prefer, fallback, hybrid };

        struct Interface {
            std::string name;
            Type type;
            auto operator==(Interface const&) const -> bool = default;
        };

        struct Policy {
            Strategy strategy = Strategy::require;
            Type preferred = Type::ethernet;
            std::optional<Type> fallback;
            std::vector<Interface> interfaces;
            std::chrono::milliseconds fallback_delay{300};
            auto operator==(Policy const&) const -> bool = default;
        };

        struct FallbackMemory {
            static constexpr std::int64_t window_ms = 15000;
            struct FamilyState {
                std::atomic<std::int64_t> failed_at_ms{0};
                std::atomic<std::uint32_t> degraded_index{0};

                auto mark_failed(std::uint32_t index, std::int64_t now_ms) noexcept -> void {
                    if (!index) return;
                    degraded_index.store(index, std::memory_order_relaxed);
                    failed_at_ms.store(now_ms, std::memory_order_release);
                }
                auto mark_healthy(std::uint32_t index) noexcept -> void {
                    if (index && degraded_index.load(std::memory_order_relaxed) == index)
                        failed_at_ms.store(0, std::memory_order_release);
                }
                [[nodiscard]] auto is_degraded(std::uint32_t index, std::int64_t now_ms) const noexcept -> bool {
                    if (!index) return false;
                    auto at = failed_at_ms.load(std::memory_order_acquire);
                    if (!at || now_ms < at || now_ms - at >= window_ms) return false;
                    return degraded_index.load(std::memory_order_relaxed) == index;
                }
            };
            FamilyState ipv4{}, ipv6{};

            auto mark_failed(std::uint32_t index, std::int64_t now_ms, bool v6) noexcept -> void {
                (v6 ? ipv6 : ipv4).mark_failed(index, now_ms);
            }
            auto mark_healthy(std::uint32_t index, bool v6) noexcept -> void {
                (v6 ? ipv6 : ipv4).mark_healthy(index);
            }
            [[nodiscard]] auto is_degraded(std::uint32_t index, std::int64_t now_ms, bool v6) const noexcept -> bool {
                return (v6 ? ipv6 : ipv4).is_degraded(index, now_ms);
            }
            auto mark_failed(std::uint32_t index, std::int64_t now_ms) noexcept -> void {
                ipv4.mark_failed(index, now_ms);
                ipv6.mark_failed(index, now_ms);
            }
            auto mark_healthy(std::uint32_t index) noexcept -> void {
                ipv4.mark_healthy(index);
                ipv6.mark_healthy(index);
            }
            [[nodiscard]] auto is_degraded(std::uint32_t index, std::int64_t now_ms) const noexcept -> bool {
                return ipv4.is_degraded(index, now_ms) && ipv6.is_degraded(index, now_ms);
            }
        };

        struct InterfaceCandidates {
            containers::inplace_vector<std::uint32_t, 16> indices;
            containers::inplace_vector<std::uint8_t, 16> tiers;
            std::chrono::milliseconds fallback_delay{};
            bool parallel_fallback = false;
            bool hybrid_race = false;
            std::shared_ptr<FallbackMemory> fallback_memory;
            [[nodiscard]] auto first() const noexcept -> std::uint32_t {
                return indices.empty() ? 0 : indices.front();
            }
        };

        using InterfaceSelection = functional::copyable_function<InterfaceCandidates(bool) const noexcept>;

        [[nodiscard]] auto retry_interface_error(std::error_code error) noexcept -> bool {
            return error == std::errc::network_unreachable || error == std::errc::host_unreachable ||
                error == std::errc::network_down || error == std::errc::no_such_device ||
                error == std::errc::address_not_available || error == std::errc::operation_not_permitted;
        }
    }

    struct SocketBinding {
        std::array<char, 16> bind_interface{};
        std::optional<std::array<std::uint8_t, 4>> inet4_bind_address;
        std::optional<std::array<std::uint8_t, 16>> inet6_bind_address;
        std::optional<std::uint32_t> routing_mark;
        std::optional<std::uint16_t> udp_bind_port;
        std::optional<bool> reuse_addr, udp_fragment;
        std::shared_ptr<network::InterfaceSelection const> network;
        std::uint32_t interface_index = 0;
        std::string network_namespace, protect_path;
        bool auto_detect_interface = false;
        std::optional<network::Strategy> network_strategy;
        std::optional<network::Type> network_type;
        [[nodiscard]] auto interface_name() const noexcept -> std::string_view {
            auto end = std::ranges::find(bind_interface, '\0');
            return {bind_interface.data(), static_cast<std::size_t>(end - bind_interface.begin())};
        }
        [[nodiscard]] auto configured() const noexcept -> bool {
            return !network_namespace.empty() || !protect_path.empty() || bind_interface.front() || network ||
                interface_index || inet4_bind_address || inet6_bind_address || routing_mark ||
                udp_bind_port.has_value() || reuse_addr.has_value() || udp_fragment.has_value() ||
                auto_detect_interface || network_strategy.has_value() || has_protect_fd_callback();
        }
        [[nodiscard]] auto separate_families() const noexcept -> bool {
            return network || inet4_bind_address || inet6_bind_address;
        }
        [[nodiscard]] auto valid() const noexcept -> bool {
            auto absolute_path = [](std::string const& path, std::size_t capacity) {
                return path.empty() || (path.front() == '/' && path.size() < capacity && path.find('\0') == path.npos);
            };
            if (!absolute_path(network_namespace, 4096) || !absolute_path(protect_path, 108) ||
                ((network || auto_detect_interface) && !network_namespace.empty())) return false;
            auto name = interface_name();
            if ((!name.empty() && (network || interface_index)) || (network && interface_index)) return false;
            if (name.size() == bind_interface.size() || name == "." || name == ".." ||
                std::ranges::any_of(name, [](unsigned char c) { return c == '/' || c == ':' || c <= 32 || c == 127; }))
                return false;
            return std::ranges::all_of(std::span(bind_interface).subspan(name.size()), [](auto c) { return c == '\0'; });
        }
        auto operator==(SocketBinding const&) const -> bool = default;
    };

    struct TcpSocketOptions {
        std::optional<bool> keepalive;
        std::optional<std::uint32_t> keepalive_idle_seconds, keepalive_interval_seconds, keepalive_count;
        SocketBinding binding;
        std::optional<bool> bind_address_no_port;
        std::optional<bool> multipath_tcp;
        // The connector, rather than socket preparation, performs Fast Open.
        std::optional<bool> tcp_fast_open;
        [[nodiscard]] auto keepalive_configured() const noexcept -> bool {
            return keepalive.has_value() || keepalive_idle_seconds || keepalive_interval_seconds || keepalive_count;
        }
        [[nodiscard]] auto tcp_configured() const noexcept -> bool {
            return keepalive_configured() || bind_address_no_port.has_value() || multipath_tcp.has_value() ||
                tcp_fast_open.has_value();
        }
        [[nodiscard]] auto configured() const noexcept -> bool { return tcp_configured() || binding.configured(); }
        [[nodiscard]] auto valid() const noexcept -> bool {
            auto seconds = [](auto value) { return !value || (*value >= 1 && *value <= 32767); };
            if (!binding.valid() || !seconds(keepalive_idle_seconds) || !seconds(keepalive_interval_seconds) ||
                (keepalive_count && (*keepalive_count < 1 || *keepalive_count > 127))) return false;
            return keepalive != false || (!keepalive_idle_seconds && !keepalive_interval_seconds && !keepalive_count);
        }
        auto operator==(TcpSocketOptions const&) const -> bool = default;
    };

    namespace linux_socket_abi {
        using SetOptionSignature = int (*)(int, int, int, void const*, unsigned int) noexcept;
        using GetOptionSignature = int (*)(int, int, int, void*, unsigned int*) noexcept;
        inline constexpr int socket_level = 1, tcp_level = 6, tcp_nodelay = 1, keepalive = 9;
        inline constexpr int keepalive_idle = 4, keepalive_interval = 5, keepalive_count = 6, tcp_user_timeout = 18;
        inline constexpr int bind_to_device = 25, bind_to_ifindex = 62, mark = 36, reuse_addr = 2, reuse_port = 15;
        inline constexpr int ip_level = 0, bind_address_no_port = 24;
        inline constexpr int socket_domain = 39, af_inet = 2, af_inet6 = 10, ipv6_level = 41;
        inline constexpr int ip_mtu_discover = 10, ipv6_mtu_discover = 23, pmtu_dont = 0, pmtu_do = 2;
    }

    namespace socket_detail {
        auto set(int fd, int level, int name, void const* bytes, unsigned int size) noexcept -> std::error_code;
        auto get_raw(int fd, int level, int name, void* out, unsigned int size,
            std::errc size_error) noexcept -> std::error_code;

        template<class Value>
        auto get(int fd, int level, int name, std::errc size_error = std::errc::protocol_error) noexcept
            -> std::expected<Value, std::error_code> {
            Value value{};
            if (auto err = get_raw(fd, level, name, &value, static_cast<unsigned int>(sizeof(value)), size_error))
                return std::unexpected(err);
            return value;
        }

        template<class Value>
        auto set(int fd, int level, int name, Value value) noexcept -> std::error_code {
            return set(fd, level, name, &value, static_cast<unsigned int>(sizeof(value)));
        }
    }

    // Source-address binding follows these options in the socket adapter.
    // Explicit failures abort preparation before connect or application data.
    [[nodiscard]] auto apply_socket_binding(int fd, SocketBinding const& options, bool datagram = false,
        SocketDeadline deadline = SocketDeadline::max()) noexcept -> std::error_code;
    [[nodiscard]] auto apply_tcp_options(int fd, TcpSocketOptions const& options,
        SocketDeadline deadline = SocketDeadline::max()) noexcept -> std::error_code;
    // Best-effort low-latency & dead-peer eviction tuning for interactive TCP sockets.
    auto tune_tcp_low_latency(int fd, std::uint32_t user_timeout_ms = 20000) noexcept -> void;
    // Best-effort re-arm TCP_QUICKACK on Linux to avoid 40ms delayed-ACK stalls.
    auto enable_tcp_quickack(int fd) noexcept -> void;
}
