export module cli.udp;
import std;
import config;
import cli.dns_transports;
import relay;
import rules;

export namespace cli {
    // A build without SS rejects explicitly configured SS UDP inbounds.
    class UdpRuntime {
    public:
        UdpRuntime()=default;
        auto stage_admission(UdpRuntime const*,std::uint64_t) noexcept -> void {}
        auto publish_admission() noexcept -> void {}
        auto set_dynamic_users(std::shared_ptr<relay::ShadowsocksUserDirectory>) noexcept -> void {}
        [[nodiscard]] auto has_listeners() const noexcept -> bool {return false;}
        [[nodiscard]] auto idle() const noexcept -> bool {return true;}
        UdpRuntime(UdpRuntime const&)=delete;
        auto operator=(UdpRuntime const&) -> UdpRuntime& = delete;
        auto resize(std::size_t,bool) -> void {}
        auto remember(std::size_t,std::span<std::uint8_t const>,std::span<relay::ShadowsocksUserKey const>) -> void {}
        [[nodiscard]] auto configure(config::Config const& configuration,std::span<std::string const>,std::span<std::size_t const>,
            std::span<rules::ProgramRule const> = {},relay::Server* = nullptr,std::span<relay::Server* const> = {},std::span<DnsProtection const> = {}) -> std::expected<void,std::string> {
            if (std::ranges::any_of(configuration.inbounds,[](auto const& inbound) {
                return inbound.shadowsocks.has_value();
            })) {
                return std::unexpected("shadowsocks UDP is not available in this build");
            }
            return {};
        }
        [[nodiscard]] auto bind_shared_dns(relay::SharedDnsGeneration&,std::size_t,std::size_t) -> bool { return true; }
        [[nodiscard]] auto start() -> std::expected<void,std::string> { return {}; }
        [[nodiscard]] auto healthy() const noexcept -> bool { return true; }
        [[nodiscard]] auto failed() const noexcept -> bool { return false; }
        [[nodiscard]] auto wait(std::chrono::milliseconds value) const noexcept -> std::chrono::milliseconds { return value; }
        auto poll() -> void {}
        auto stop() noexcept -> void {}
    };
}
