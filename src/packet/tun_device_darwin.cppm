export module packet.tun_device;
import std;
export import packet.tun_darwin;

export namespace packet {
    using PlatformTun = DarwinTun;
    using PlatformTunFailure = DarwinTunFailure;
    inline constexpr bool tun_platform_native = true;

    struct TunDeviceInfo {
        std::string name;
        std::uint16_t mtu = 1500;
    };

    [[nodiscard]] inline auto open_platform_tun(std::string_view name, std::uint16_t mtu)
        -> std::expected<PlatformTun, PlatformTunFailure> {
        return DarwinTun::open({std::string(name), mtu});
    }

    [[nodiscard]] inline auto attach_platform_tun(int fd, bool adopt, bool skip_ioctl = false)
        -> std::expected<PlatformTun, PlatformTunFailure> {
        return DarwinTun::attach(fd, adopt ? DarwinTunFdOwnership::adopt : DarwinTunFdOwnership::borrow, !skip_ioctl);
    }

    [[nodiscard]] inline auto platform_tun_info(PlatformTun const& tun, std::uint16_t mtu) -> TunDeviceInfo {
        return {std::string(tun.device_name()), mtu};
    }
}
