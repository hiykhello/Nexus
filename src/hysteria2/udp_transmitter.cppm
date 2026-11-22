export module hysteria2.udp_transmitter;
import std;
import hysteria2.udp;
import hysteria2.wire;

export namespace hysteria2 {
    enum class UdpSendError { busy,invalid,too_large,exhausted,canceled,state };
    struct UdpSendTicket { std::uint64_t generation=0; auto operator==(UdpSendTicket const&) const noexcept -> bool=default; };
    struct UdpWriteView { std::span<std::uint8_t const> header,payload; };
    // Single borrowed datagram, fragmented without payload copies. The caller
    // retains address/payload through done(ticket). QUIC copies each accepted
    // DATAGRAM into the driver's sealed output packet, so successful native
    // acceptance alone releases a fragment. Socket completion is separate.
    class UdpTransmitter {
        std::optional<FragmentPlan> plan_;
        std::array<std::uint8_t,8+8+max_address_bytes> header_{};
        std::size_t next_=0;
        std::uint64_t generation_=0;
        bool canceled_=false;
    public:
        UdpTransmitter()=default;
        UdpTransmitter(UdpTransmitter const&)=delete;
        auto operator=(UdpTransmitter const&) -> UdpTransmitter& = delete;
        auto submit(std::uint32_t session,std::uint16_t packet,std::string_view address,std::span<std::uint8_t const> bytes,std::size_t budget) noexcept
            -> std::expected<UdpSendTicket,UdpSendError> {
            if (plan_) return std::unexpected(UdpSendError::busy);
            if (generation_==std::numeric_limits<std::uint64_t>::max()) return std::unexpected(UdpSendError::exhausted);
            auto plan=FragmentPlan::create(session,packet,address,bytes,budget);
            if (!plan) return std::unexpected(plan.error()==UdpError::invalid_address ? UdpSendError::invalid : UdpSendError::too_large);
            plan_=*plan;next_=0;canceled_=false;++generation_;return UdpSendTicket{generation_};
        }
        auto pending() noexcept -> std::optional<UdpWriteView> {
            if (!plan_) return {};
            auto fragment=*plan_->fragment(next_);auto size=write_udp_header(header_,fragment);
            if (!size) std::terminate();
            return UdpWriteView{std::span(header_).first(*size),fragment.payload};
        }
        auto accepted() noexcept -> bool {
            if (!plan_) return false;
            if (++next_==plan_->count()) plan_.reset();return true;
        }
        auto done(UdpSendTicket ticket) const noexcept -> std::expected<bool,UdpSendError> {
            if (!ticket.generation || ticket.generation!=generation_) return std::unexpected(UdpSendError::state);
            if (canceled_) return std::unexpected(UdpSendError::canceled);
            return !plan_;
        }
        auto cancel() noexcept -> void { plan_.reset();canceled_=true; }
        auto busy() const noexcept -> bool { return plan_.has_value(); }
    };
}
