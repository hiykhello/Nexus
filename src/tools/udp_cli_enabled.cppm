export module cli.udp_enabled;
import std;
import config;
import cli.dns_transports;
import rules;
import crypto;
import relay;
import ss_udp.shared_coordinator;

export namespace cli {
    class ShadowsocksUdpRuntime {
        std::shared_ptr<shadowsocks::detail::UdpListenerIngress> ingress_;
        std::uint64_t generation_ = 0;
        std::optional<relay::DnsRouting> dns_;
        struct SecretKey {
            std::array<std::uint8_t, 32> bytes{};
            ~SecretKey() { crypto::cleanse(bytes); }
        };
        struct ListenerKeys {
            SecretKey primary;
            struct User { std::string name; SecretKey secret; };
            std::vector<User> users;
        };
        std::vector<std::unique_ptr<ListenerKeys>> keys_;
        std::shared_ptr<relay::ShadowsocksUserDirectory> dynamic_users_;
        std::unique_ptr<relay::Server> routing_;
        std::optional<relay::udp_runtime::CoordinatorUdpInbounds> inbounds_;
        bool routing_active_ = false;
    public:
        ShadowsocksUdpRuntime() = default;
        ShadowsocksUdpRuntime(ShadowsocksUdpRuntime const&) = delete;
        auto operator=(ShadowsocksUdpRuntime const&) -> ShadowsocksUdpRuntime& = delete;
        ~ShadowsocksUdpRuntime() { stop(); }
        auto set_dynamic_users(std::shared_ptr<relay::ShadowsocksUserDirectory> users) noexcept -> void {
            dynamic_users_ = std::move(users);
        }
        auto stage_admission(ShadowsocksUdpRuntime const* previous, std::uint64_t generation) -> void {
            ingress_ = previous && previous->ingress_ ? previous->ingress_ :
                std::make_shared<shadowsocks::detail::UdpListenerIngress>();
            generation_ = generation;
        }
        auto publish_admission() noexcept -> void {
            if (ingress_) ingress_->publish(generation_);
        }
        [[nodiscard]] auto has_listeners() const noexcept -> bool { return inbounds_.has_value(); }
        [[nodiscard]] auto idle() const noexcept -> bool { return !inbounds_ || inbounds_->idle(); }
        auto resize(std::size_t count, bool has_shadowsocks) -> void;
        auto remember(std::size_t index, std::span<std::uint8_t const> bytes,
            std::span<relay::ShadowsocksUserKey const> users) -> void;
        [[nodiscard]] auto configure(config::Config const&, std::span<std::string const>,
            std::span<std::size_t const>, std::span<rules::ProgramRule const> = {},
            relay::Server* = nullptr, std::span<relay::Server* const> = {},
            std::span<DnsProtection const> = {},
            std::span<std::shared_ptr<rules::MmapMatcher const> const> = {}) -> std::expected<void, std::string>;
        [[nodiscard]] auto bind_shared_dns(relay::SharedDnsGeneration&, std::size_t, std::size_t) -> bool;
        [[nodiscard]] auto start() -> std::expected<void, std::string>;
        [[nodiscard]] auto healthy() const noexcept -> bool;
        [[nodiscard]] auto failed() const noexcept -> bool;
        [[nodiscard]] auto wait(std::chrono::milliseconds) const noexcept -> std::chrono::milliseconds;
        auto poll() -> void;
        auto stop() noexcept -> void;
    };
}
