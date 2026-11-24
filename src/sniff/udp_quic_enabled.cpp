module sniff.udp_quic;
import std;
import sniff.quic;
namespace sniff {
    struct QuicProbe::Impl {QuicSniffer parser;};
    QuicProbe::QuicProbe(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
    QuicProbe::~QuicProbe()=default;
    auto make_quic_probe() -> std::unique_ptr<QuicProbe> {
        return std::unique_ptr<QuicProbe>(new QuicProbe(std::make_unique<QuicProbe::Impl>()));
    }
    namespace {
    auto classify(QuicSniffResult result) -> QuicProbeResult {
        switch(result.status) {
        case QuicSniffStatus::need_more:return {QuicProbeStatus::waiting,{}};
        case QuicSniffStatus::matched:
            return {QuicProbeStatus::matched,
                (result.server_name && !result.ech_offered) ? std::optional<std::string>(std::string(*result.server_name)) : std::nullopt,
                result.client ? std::optional<std::string>(std::string(*result.client)) : std::nullopt};
        case QuicSniffStatus::not_initial:
        case QuicSniffStatus::authentication_failed:
        case QuicSniffStatus::unsupported:return {QuicProbeStatus::unrelated,{}};
        case QuicSniffStatus::malformed:
        case QuicSniffStatus::too_large:return {QuicProbeStatus::unknown,{}};
        }
        return {QuicProbeStatus::unknown,{}};
    }
    }
    auto QuicProbe::feed(std::span<std::uint8_t const> packet) -> QuicProbeResult {
        return classify(impl_->parser.feed(packet));
    }
    auto sniff_quic_datagram(std::span<std::uint8_t const> packet) -> QuicProbeResult {
        QuicSniffer parser;
        return classify(parser.feed(packet));
    }
}
