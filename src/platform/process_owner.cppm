export module platform.process_owner;
import std;
export import containers.inplace_vector;
import platform.ip_address;

export namespace platform {
    struct ProcessOwner {
        std::uint32_t pid = 0;
        std::uint32_t uid = 0;
        std::string executable;
        std::optional<std::uint32_t> gid{};
        std::string user{};
        std::string package_name{};
        containers::inplace_vector<std::string, 8> executables{};
    };

    struct SocketTuple {
        bool is_udp = false;
        IpAddress local_ip{};
        std::uint16_t local_port = 0;
        IpAddress remote_ip{};
        std::uint16_t remote_port = 0;
        bool need_process = true;
    };

    [[nodiscard]] inline auto normalize_socket_ip(std::span<std::uint8_t const> raw) noexcept -> std::optional<IpAddress> {
        IpAddress out{};
        if (raw.size() == 4) {
            std::ranges::copy(raw, out.bytes.begin());
            out.size = 4;
            return out;
        }
        if (raw.size() == 16) {
            constexpr std::array<std::uint8_t, 12> v4_mapped{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255};
            if (std::equal(v4_mapped.begin(), v4_mapped.end(), raw.begin())) {
                std::copy_n(raw.begin() + 12, 4, out.bytes.begin());
                out.size = 4;
                return out;
            }
            std::ranges::copy(raw, out.bytes.begin());
            out.size = 16;
            return out;
        }
        return std::nullopt;
    }

    [[nodiscard]] inline auto is_loopback_ip(IpAddress const& ip) noexcept -> bool {
        if (ip.size == 4) return ip.bytes[0] == 127;
        if (ip.size == 16) {
            return std::ranges::all_of(std::span(ip.bytes).first<15>(), [](std::uint8_t b) { return b == 0; }) &&
                   ip.bytes[15] == 1;
        }
        return false;
    }

    // Converts proxy accepted peer/local endpoints into the client's local/remote SocketTuple.
    [[nodiscard]] inline auto make_loopback_socket_tuple(bool is_udp,
        std::span<std::uint8_t const> peer_ip, std::uint16_t peer_port,
        std::span<std::uint8_t const> local_ip, std::uint16_t local_port) noexcept -> std::optional<SocketTuple> {
        if (peer_port == 0 || local_port == 0) return std::nullopt;
        auto norm_peer = normalize_socket_ip(peer_ip);
        auto norm_local = normalize_socket_ip(local_ip);
        if (!norm_peer || !norm_local || norm_peer->size != norm_local->size) return std::nullopt;
        if (!is_loopback_ip(*norm_peer) || !is_loopback_ip(*norm_local)) return std::nullopt;
        return SocketTuple{
            .is_udp = is_udp,
            .local_ip = *norm_peer,
            .local_port = peer_port,
            .remote_ip = *norm_local,
            .remote_port = local_port,
        };
    }

    [[nodiscard]] auto lookup_socket_owner(SocketTuple const& tuple) -> std::optional<ProcessOwner>;
}
