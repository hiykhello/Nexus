export module packet.tun_device;
import std;
export import packet.tun_windows;

export namespace packet {
    using PlatformTun = WindowsTun;
    using PlatformTunFailure = WintunFailure;
    inline constexpr bool tun_platform_native = true;

    struct TunDeviceInfo {
        std::string name;
        std::uint16_t mtu = 1500;
    };

    [[nodiscard]] inline auto open_platform_tun(std::string_view name, std::uint16_t mtu)
        -> std::expected<PlatformTun, PlatformTunFailure> {
        (void)mtu;
        return WindowsTun::open({name.empty() ? std::string("Nexus") : std::string(name)});
    }

    [[nodiscard]] inline auto attach_platform_tun(int, bool, bool = false)
        -> std::expected<PlatformTun, PlatformTunFailure> {
        return std::unexpected(WintunFailure{WintunError::unsupported});
    }

    [[nodiscard]] inline auto platform_tun_info(PlatformTun const& tun, std::uint16_t mtu) -> TunDeviceInfo {
        return {std::string(tun.adapter_name()), mtu};
    }
}
