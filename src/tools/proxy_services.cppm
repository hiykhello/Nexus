export module cli.proxy_services;
import std;
import config;
import functional;
import logging;
import logging.cli;

export namespace cli {
    using ServiceTickFn = void (*)(void*, std::uint64_t, logging::Runtime&) noexcept;

    struct ServiceHandle {
        using Deleter = void (*)(void*) noexcept;
        std::unique_ptr<void, Deleter> state{nullptr, +[](void*) noexcept {}};
        ServiceTickFn tick = nullptr;

        ServiceHandle() = default;
        ServiceHandle(std::unique_ptr<void, Deleter> s, ServiceTickFn t = nullptr) noexcept
            : state(std::move(s)), tick(t) {}
        ~ServiceHandle() = default;
        ServiceHandle(ServiceHandle const&) = delete;
        auto operator=(ServiceHandle const&) -> ServiceHandle& = delete;
        ServiceHandle(ServiceHandle&&) noexcept = default;
        auto operator=(ServiceHandle&&) noexcept -> ServiceHandle& = default;

        template<class T>
        static auto create(std::unique_ptr<T> owned, ServiceTickFn tick_fn = nullptr) noexcept -> ServiceHandle {
            return ServiceHandle{
                std::unique_ptr<void, Deleter>{owned.release(), +[](void* p) noexcept { delete static_cast<T*>(p); }},
                tick_fn};
        }
    };

    struct WatchdogHooks {
        std::shared_ptr<std::atomic_bool> shed_new_sessions;
        functional::move_only_function<void(std::uint8_t) noexcept> on_reclaim;
    };

    struct AcmeHooks {
        functional::move_only_function<void(std::string_view cert_pem, std::string_view key_pem) noexcept> on_credential_updated;
        std::shared_ptr<void> shared_credential{};
    };

    struct TorHooks {
        functional::move_only_function<std::expected<std::size_t, std::string>(config::TorServiceConfig const&)> register_outbound;
    };

    struct ServiceHooks {
        WatchdogHooks watchdog;
        AcmeHooks acme;
        TorHooks tor;
    };

    struct BridgeStatsSnapshot {
        std::uint64_t forwarded_v4 = 0;
        std::uint64_t forwarded_v6 = 0;
        std::uint64_t dropped_ttl = 0;
        std::uint64_t dropped_mtu = 0;
        std::uint64_t dropped_loop = 0;
        std::uint64_t dropped_filtered = 0;
        std::uint64_t dropped_tx = 0;
    };

    class OptionalServicesRuntime {
        std::vector<ServiceHandle> services_;
        std::shared_ptr<void> acme_credential_;
    public:
        OptionalServicesRuntime() = default;
        ~OptionalServicesRuntime() { stop(); }
        OptionalServicesRuntime(OptionalServicesRuntime const&) = delete;
        auto operator=(OptionalServicesRuntime const&) -> OptionalServicesRuntime& = delete;
        OptionalServicesRuntime(OptionalServicesRuntime&&) noexcept = default;
        auto operator=(OptionalServicesRuntime&&) noexcept -> OptionalServicesRuntime& = default;

        [[nodiscard]] auto start(config::ServicesConfig const&, logging::Runtime&, ServiceHooks hooks = {})
            -> std::expected<void, std::string>;
        auto push_handle(ServiceHandle handle) -> void { services_.push_back(std::move(handle)); }
        auto poll(std::uint64_t now_ms, logging::Runtime&) noexcept -> void;
        auto stop() noexcept -> void;
        [[nodiscard]] auto active_count() const noexcept -> std::size_t { return services_.size(); }
        [[nodiscard]] auto acme_credential_erased() const noexcept -> std::shared_ptr<void> { return acme_credential_; }
    };

    auto init_watchdog_service(config::MemoryWatchdogConfig const&, logging::Runtime&, WatchdogHooks hooks = {})
        -> std::expected<ServiceHandle, std::string>;
    auto init_sni_demux_service(config::SniDemuxConfig const&, logging::Runtime&)
        -> std::expected<ServiceHandle, std::string>;
    auto init_acme_service(config::AcmeServiceConfig const&, logging::Runtime&, AcmeHooks hooks = {})
        -> std::expected<ServiceHandle, std::string>;
    auto init_reverse_tunnel_service(config::ReverseTunnelServiceConfig const&, logging::Runtime&)
        -> std::expected<ServiceHandle, std::string>;
    auto init_bridge_service(config::BridgeServiceConfig const&, logging::Runtime&)
        -> std::expected<ServiceHandle, std::string>;
    auto init_bridge_service_with_fds(config::BridgeServiceConfig const&, int tun_fd, int phys_fd, logging::Runtime&)
        -> std::expected<ServiceHandle, std::string>;
    auto init_tor_service(config::TorServiceConfig const&, logging::Runtime&, TorHooks hooks = {})
        -> std::expected<ServiceHandle, std::string>;
    auto init_derp_server_service(config::DerpServerServiceConfig const&, logging::Runtime&)
        -> std::expected<ServiceHandle, std::string>;

    // Runtime inspection & control hooks for active service handles.
    [[nodiscard]] auto sni_demux_bound_port(ServiceHandle const&) noexcept -> std::uint16_t;
    [[nodiscard]] auto acme_http01_port(ServiceHandle const&) noexcept -> std::uint16_t;
    [[nodiscard]] auto acme_alpn01_port(ServiceHandle const&) noexcept -> std::uint16_t;
    [[nodiscard]] auto acme_credential_generation(ServiceHandle const&) noexcept -> std::uint64_t;
    [[nodiscard]] auto acme_has_valid_credential(ServiceHandle const&) noexcept -> bool;
    [[nodiscard]] auto acme_credential_provider_erased(ServiceHandle const&) noexcept -> std::shared_ptr<void>;
    [[nodiscard]] auto acme_dns01_record(ServiceHandle const&, std::string_view domain) -> std::optional<std::string>;
    [[nodiscard]] auto tor_signal_newnym(ServiceHandle&) -> std::expected<void, std::string>;
    [[nodiscard]] auto tor_query_bootstrap(ServiceHandle&) -> std::expected<int, std::string>;
    [[nodiscard]] auto derp_bound_port(ServiceHandle const&) noexcept -> std::uint16_t;
    [[nodiscard]] auto derp_public_key(ServiceHandle const&) noexcept -> std::array<std::uint8_t, 32>;
    [[nodiscard]] auto reverse_tunnel_control_port(ServiceHandle const&) noexcept -> std::uint16_t;
    [[nodiscard]] auto reverse_tunnel_expose_port(ServiceHandle const&) noexcept -> std::uint16_t;
    [[nodiscard]] auto bridge_stats(ServiceHandle const&) noexcept -> BridgeStatsSnapshot;
}
