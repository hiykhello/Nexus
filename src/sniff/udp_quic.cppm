export module sniff.udp_quic;
import std;
export import sniff.stun;
export namespace sniff {
    enum class QuicProbeStatus { waiting,matched,unknown,unrelated };
    struct QuicProbeResult {QuicProbeStatus status=QuicProbeStatus::unknown;std::optional<std::string> domain;};
    class QuicProbe {
        struct Impl;
        std::unique_ptr<Impl> impl_;
        explicit QuicProbe(std::unique_ptr<Impl>);
        friend auto make_quic_probe() -> std::unique_ptr<QuicProbe>;
    public:
        ~QuicProbe();
        QuicProbe(QuicProbe const&)=delete;
        auto operator=(QuicProbe const&) -> QuicProbe& = delete;
        [[nodiscard]] auto feed(std::span<std::uint8_t const>) -> QuicProbeResult;
    };
    // Returns null when this build has no QUIC sniffing. The caller bounds
    // probe count, lifetime and packet storage for each authenticated flow.
    [[nodiscard]] auto make_quic_probe() -> std::unique_ptr<QuicProbe>;
    // A match requires a complete ClientHello. With ECH, the name stays unknown.
    [[nodiscard]] auto sniff_quic_datagram(std::span<std::uint8_t const>) -> QuicProbeResult;
}
