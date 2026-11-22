export module transport.tun_linux;
export import transport.memory;
export import packet.fd;
export import packet.tun_linux;
import std;

export namespace transport {
    struct TunLimits {
        std::size_t tcp_flows=256, tcp_buffer=65535, tcp_direct=256, mtu=1500;
        udp::Mapping mapping=udp::Mapping::endpoint_independent;
        udp::Filtering filtering=udp::Filtering::address_port_dependent;
        udp::Limits udp{};
        packet::DeviceLimits external{}, internal{};
        // Applied to every direct socket before connect/send; failures are reported.
        std::optional<std::uint32_t> socket_mark;
        tcp::ChallengeAckLimits challenge_ack{};
    };
    enum class TunDriverError { stopped, invalid_device, invalid_limits, time_reversed };
    struct TunRandomFailure { std::error_code error; };
    using TunDriverFailure=std::variant<TunDriverError,tcp::TableError,packet::FdFailure,MemoryError,TunRandomFailure>;
    struct TunStep { packet::FdStep device; MemoryStep transport; };
    // Single executor owner. The TUN is configured by the caller. No addresses,
    // routes or host state are changed. Stop is terminal, discards queued
    // packets and closes the device.
    class LinuxTunDirect {
        packet::LinuxTun tun_;
        packet::MemoryLink link_;
        tcp::ConnectionTable table_;
        tcp::ConnectionTable6 table6_;
        MemoryEngine engine_;
        std::optional<packet::FdPump> pump_;
        std::uint64_t now_=0;
        bool initialized_=false, stopped_=false;
        LinuxTunDirect(packet::LinuxTun&& tun,tcp::ConnectionTable&& table,tcp::ConnectionTable6&& table6,rules::Matcher policy,TunLimits limits);
    public:
        LinuxTunDirect(LinuxTunDirect const&)=delete;
        auto operator=(LinuxTunDirect const&) -> LinuxTunDirect& = delete;
        ~LinuxTunDirect();
        // Validates limits before consuming tun. After that point failures
        // may consume it; allocation failures propagate normally.
        [[nodiscard]] static auto create(packet::LinuxTun&& tun,rules::Matcher policy,TunLimits limits={})
            -> std::expected<std::unique_ptr<LinuxTunDirect>,TunDriverFailure>;
        // Uses Linux getrandom without blocking before processing any packets.
        // Entropy failure leaves the device and transport untouched.
        [[nodiscard]] auto step(std::uint64_t now) -> std::expected<TunStep,TunDriverFailure>;
        // Explicit ISS is for callers providing secure randomness and deterministic tests.
        // Any reported device or transport error must be handled by the caller.
        // ISS must be unpredictable whenever a new TCP flow can be accepted.
        [[nodiscard]] auto step(std::uint64_t now,std::uint32_t iss) -> std::expected<TunStep,TunDriverFailure>;
        [[nodiscard]] auto stop(std::uint64_t now) -> std::expected<void,TunDriverFailure>;
    };
}
