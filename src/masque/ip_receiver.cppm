export module masque.ip_receiver;
import std;
import masque.ip_control;
import masque.datagram;
import masque.capsule;

export namespace masque {
    enum class IpReceiveStatus { active, closed, malformed, limit, reused_request_id, sink_failure, reentrant };
    struct IpReceiveResult {IpReceiveStatus status;std::size_t consumed;};

    // A single authorized request stream on one executor. Sink methods are
    // synchronous and noexcept. assigned/routes/requested must either apply
    // the whole proposed change and return true, or leave external state
    // unchanged and return false. They may not retain borrowed spans. Packet
    // delivery is a forwarding decision: the sink may drop it independently
    // of the control stream. This class does not grant packet permissions.
    template<class Sink,std::size_t Bytes,std::size_t Addresses,std::size_t Routes,std::size_t Requests>
    class IpReceiver {
        IpControlCapsules<Bytes> capsules_{true};
        IpControlState<Addresses,Routes,Requests> state_;
        Sink& sink_;
        IpReceiveStatus status_=IpReceiveStatus::active;
        bool busy_=false;

        auto fail(IpSnapshotError error) noexcept -> void {
            switch(error) {
            case IpSnapshotError::malformed:status_=IpReceiveStatus::malformed;break;
            case IpSnapshotError::limit:status_=IpReceiveStatus::limit;break;
            case IpSnapshotError::reused_request_id:status_=IpReceiveStatus::reused_request_id;break;
            }
        }
        auto packet(std::span<std::uint8_t const> body) noexcept -> void {
            auto parsed=parse_proxy_datagram(body,false);
            if(!parsed) {status_=IpReceiveStatus::malformed;return;}
            if(!parsed->context_id)sink_.packet(parsed->payload);
        }
        auto consume(IpCapsuleResult const& capsule) noexcept -> void {
            if(capsule.type==datagram_capsule_type) {
                packet(capsule.body);return;
            }
            auto proposed=state_;
            if(capsule.type==address_assign_capsule) {
                auto result=proposed.assign(capsule.body);
                if(!result) {fail(result.error());return;}
                if(!sink_.assigned(proposed.addresses())) {status_=IpReceiveStatus::sink_failure;return;}
            } else if(capsule.type==route_advertisement_capsule) {
                auto result=proposed.advertise(capsule.body);
                if(!result) {fail(result.error());return;}
                if(!sink_.routes(proposed.routes())) {status_=IpReceiveStatus::sink_failure;return;}
            } else {
                std::array<AddressEntry,Requests> requests{};
                auto result=proposed.request(capsule.body,requests);
                if(!result) {fail(result.error());return;}
                if(!sink_.requested(std::span(requests).first(*result))) {status_=IpReceiveStatus::sink_failure;return;}
            }
            if(status_==IpReceiveStatus::active)state_=proposed;
        }
    public:
        explicit IpReceiver(Sink& sink) noexcept:sink_(sink) {
            static_assert(noexcept(sink.assigned(std::span<AddressEntry const>{})));
            static_assert(noexcept(sink.routes(std::span<RouteEntry const>{})));
            static_assert(noexcept(sink.requested(std::span<AddressEntry const>{})));
            static_assert(noexcept(sink.packet(std::span<std::uint8_t const>{})));
        }
        IpReceiver(IpReceiver const&)=delete;
        auto operator=(IpReceiver const&) -> IpReceiver& = delete;
        auto state() const noexcept -> IpControlState<Addresses,Routes,Requests> const& {return state_;}
        auto status() const noexcept -> IpReceiveStatus {return status_;}
        auto stop() noexcept -> void {if(status_==IpReceiveStatus::active)status_=IpReceiveStatus::closed;}
        // The QUIC DATAGRAM payload has already had its HTTP stream ID
        // removed; it starts with the same Context ID as a DATAGRAM capsule.
        auto datagram(std::span<std::uint8_t const> body) noexcept -> IpReceiveStatus {
            if(busy_)return IpReceiveStatus::reentrant;
            if(status_!=IpReceiveStatus::active)return status_;
            busy_=true;packet(body);busy_=false;return status_;
        }
        auto feed(std::span<std::uint8_t const> input) noexcept -> IpReceiveResult {
            if(busy_)return {IpReceiveStatus::reentrant,0};
            if(status_!=IpReceiveStatus::active)return {status_,0};
            busy_=true;std::size_t consumed=0;
            while(status_==IpReceiveStatus::active) {
                auto capsule=capsules_.feed(input.subspan(consumed));consumed+=capsule.consumed;
                if(capsule.event==IpCapsuleEvent::complete) {consume(capsule);continue;}
                if(capsule.event==IpCapsuleEvent::limit)status_=IpReceiveStatus::limit;
                else if(capsule.event==IpCapsuleEvent::truncated || capsule.event==IpCapsuleEvent::malformed)status_=IpReceiveStatus::malformed;
                else if(capsule.event==IpCapsuleEvent::closed)status_=IpReceiveStatus::closed;
                break;
            }
            busy_=false;return {status_,consumed};
        }
        auto finish() noexcept -> IpReceiveStatus {
            if(busy_)return IpReceiveStatus::reentrant;
            if(status_!=IpReceiveStatus::active)return status_;
            busy_=true;auto capsule=capsules_.finish();
            if(capsule.event==IpCapsuleEvent::complete)consume(capsule);
            else if(capsule.event==IpCapsuleEvent::limit)status_=IpReceiveStatus::limit;
            else if(capsule.event==IpCapsuleEvent::truncated || capsule.event==IpCapsuleEvent::malformed)status_=IpReceiveStatus::malformed;
            if(status_==IpReceiveStatus::active)status_=IpReceiveStatus::closed;
            busy_=false;return status_;
        }
    };
}
