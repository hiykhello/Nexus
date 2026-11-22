module sniff.udp_quic;
import std;
#ifndef NEXUS_QUIC_SNIFF
namespace sniff {
    struct QuicProbe::Impl {};
    QuicProbe::QuicProbe(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
    QuicProbe::~QuicProbe()=default;
    auto make_quic_probe() -> std::unique_ptr<QuicProbe> { return {}; }
    auto QuicProbe::feed(std::span<std::uint8_t const>) -> QuicProbeResult {return {QuicProbeStatus::unknown,{}};}
    auto sniff_quic_datagram(std::span<std::uint8_t const>) -> QuicProbeResult { return {}; }
}
#endif
