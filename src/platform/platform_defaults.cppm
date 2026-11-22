export module platform.platform_defaults;
import std;
import platform.ip_address;

export namespace platform {
    enum class TargetPlatform : std::uint8_t {
        linux_native,
        android_vpn,
        apple_network_extension,
        macos_native,
        windows_wintun
    };

    // Battle-tested per-OS TUN MTU ceilings avoiding kernel performance cliffs and ENOBUFS:
    // - Apple NetworkExtension (utun): MTU > 4064 (4096 - UTUN_IF_HEADROOM_SIZE) suffers severe throughput drops.
    // - Android VpnService: MTU 65535 triggers ENOBUFS on many vendor kernels; cap at 9000.
    // - Windows Wintun: standard 1500 / 9000 safe ceiling.
    inline constexpr std::uint16_t kAppleNetworkExtensionSafeMtu = 4064;
    inline constexpr std::uint16_t kAndroidVpnSafeMtu = 9000;
    inline constexpr std::uint16_t kLinuxTunGsoMaxMtu = 49152;
    inline constexpr std::uint16_t kWindowsWintunDefaultMtu = 1500;
    inline constexpr std::uint32_t kAndroidMultiUserUidRange = 100000;

    [[nodiscard]] constexpr auto default_tun_mtu(TargetPlatform target) noexcept -> std::uint16_t {
        switch (target) {
        case TargetPlatform::apple_network_extension: return kAppleNetworkExtensionSafeMtu;
        case TargetPlatform::android_vpn:             return kAndroidVpnSafeMtu;
        case TargetPlatform::macos_native:            return 4064;
        case TargetPlatform::windows_wintun:          return kWindowsWintunDefaultMtu;
        case TargetPlatform::linux_native:            return 9000;
        }
        return 1500;
    }

    [[nodiscard]] constexpr auto clamp_tun_mtu(TargetPlatform target, std::uint16_t requested) noexcept -> std::uint16_t {
        if (requested == 0) return default_tun_mtu(target);
        std::uint16_t clamped = requested < 1280 ? std::uint16_t{1280} : requested;
        if (target == TargetPlatform::apple_network_extension && clamped > kAppleNetworkExtensionSafeMtu)
            return kAppleNetworkExtensionSafeMtu;
        if (target == TargetPlatform::android_vpn && clamped > kAndroidVpnSafeMtu)
            return kAndroidVpnSafeMtu;
        return clamped;
    }

    [[nodiscard]] constexpr auto allow_tun_gso(TargetPlatform target, std::uint16_t mtu) noexcept -> bool {
        return target == TargetPlatform::linux_native && mtu > 0 && mtu < kLinuxTunGsoMaxMtu;
    }

    // Darwin XNU net.inet.{tcp,udp}.pcblist_n struct stride (8-byte aligned in in_pcblist.c).
    [[nodiscard]] constexpr auto darwin_pcblist_struct_size(int darwin_major) noexcept -> std::size_t {
        return darwin_major >= 22 ? 408u : 384u;
    }

    // Windows special pseudo-PIDs that cannot be queried via OpenProcess.
    [[nodiscard]] constexpr auto windows_special_process_name(std::uint32_t pid) noexcept -> std::string_view {
        if (pid == 0) return ":System Idle Process";
        if (pid == 4) return ":System";
        return {};
    }

    // Android multi-user profile AppID normalization (uid % 100000) & Zygote noise filter.
    [[nodiscard]] constexpr auto android_app_id(std::uint32_t uid) noexcept -> std::uint32_t {
        return uid % kAndroidMultiUserUidRange;
    }

    [[nodiscard]] constexpr auto is_android_zygote_noise(std::string_view process_path) noexcept -> bool {
        return process_path.starts_with("/system/bin/app_process");
    }

    // Windows injects deprecated RFC 3879 site-local anycast fec0:0:0:ffff::1..3 when no IPv6 DNS exists.
    [[nodiscard]] constexpr auto is_windows_site_local_fake_dns(std::span<std::uint8_t const, 16> ipv6) noexcept -> bool {
        return ipv6[0] == 0xfe && (ipv6[1] & 0xc0) == 0xc0;
    }

    // Windows Winsock2 quirk: IP_UNICAST_IF takes network byte order (big-endian),
    // whereas IPV6_UNICAST_IF takes host byte order!
    [[nodiscard]] constexpr auto windows_unicast_if_option_value(std::uint32_t ifindex, bool ipv6) noexcept -> std::uint32_t {
        return ipv6 ? ifindex : host_to_net32(ifindex);
    }
}
