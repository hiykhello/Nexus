export module packet.tun_device;
import std;
export import packet.tun_linux;

export namespace packet {
    using PlatformTun = LinuxTun;
    using PlatformTunFailure = TunFailure;
    inline constexpr bool tun_platform_native = true;

    struct TunDeviceInfo {
        std::string name;
        std::uint16_t mtu = 1500;
    };

    [[nodiscard]] inline auto open_platform_tun(std::string_view name, std::uint16_t mtu,
        TunCreateOptions opts = {}) -> std::expected<PlatformTun, PlatformTunFailure> {
        (void)mtu;
        return LinuxTun::create(name, opts);
    }

    [[nodiscard]] inline auto attach_platform_tun(int fd, bool adopt, bool skip_ioctl = false)
        -> std::expected<PlatformTun, PlatformTunFailure> {
        return LinuxTun::attach_external(fd, adopt ? TunFdOwnership::adopt : TunFdOwnership::borrow, !skip_ioctl);
    }

    [[nodiscard]] inline auto platform_tun_info(PlatformTun const& tun, std::uint16_t mtu) -> TunDeviceInfo {
        return {std::string(tun.name()), mtu};
    }
}
