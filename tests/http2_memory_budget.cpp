import std;
import nexus.http2.server;
import nexus.thirdparty.nghttp2;
namespace h2 = nex::nghttp2;
namespace nh = nexus::http2;
struct Observed { nh::ServerSession* session = nullptr; unsigned headers = 0; };
auto on_headers(void* context,std::int32_t,std::span<nh::Header const>,bool,bool) noexcept -> bool {
    ++static_cast<Observed*>(context)->headers; return true;
}
auto on_data(void*,std::int32_t,std::span<std::byte const>) noexcept -> nh::DataDisposition { return nh::DataDisposition::accepted; }
auto on_end(void*,std::int32_t) noexcept -> bool { return true; }
void on_closed(void*,std::int32_t,std::uint32_t) noexcept {}
int main() {
    // The nghttp2 allocator has a hard per-session live-allocation budget.
    // Exhaust it with peer-generated ACK work while keeping the ACK queue
    // limit high enough that the memory limit is the first failure.
    Observed budget_observed;
    nh::ServerEvents budget_events{&budget_observed, on_headers, on_data, on_end, on_closed};
    nh::ServerLimits limits{8, 4, 128, 64, 16};
    limits.shared_memory_bytes=0;
    if (nh::ServerSession::create(limits, budget_events)) return 91;
    limits.shared_memory_bytes=1;
    auto shared_too_small=nh::ServerSession::create(limits, budget_events);
    if (shared_too_small || shared_too_small.error().library_code!=h2::NGHTTP2_ERR_NOMEM) return 92;
    limits.shared_memory_bytes=std::numeric_limits<std::size_t>::max();
    limits.library_memory_bytes=0;
    if (nh::ServerSession::create(limits, budget_events)) return 70;
    limits.library_memory_bytes=1;
    auto too_small=nh::ServerSession::create(limits, budget_events);
    if (too_small || too_small.error().library_code!=h2::NGHTTP2_ERR_NOMEM) return 71;
    limits.library_memory_bytes=4*1024*1024;
    auto reference=nh::ServerSession::create(limits, budget_events);
    if (!reference || !(*reference)->library_memory_used() ||
        (*reference)->library_memory_peak()<(*reference)->library_memory_used()) return 72;
    auto baseline=(*reference)->library_memory_used();
    reference->reset();
    limits.library_memory_bytes=baseline;
    auto submission=nh::ServerSession::create(limits, budget_events);
    if (!submission) return 79;
    auto no_memory=(**submission).start_shutdown();
    if (no_memory || no_memory.error().library_code!=h2::NGHTTP2_ERR_NOMEM) return 80;
    auto after_submission=(**submission).receive({});
    if (after_submission || after_submission.error().kind!=nh::ServerErrorKind::failed) return 81;
    limits.library_memory_bytes=baseline+1024;
    auto budget=nh::ServerSession::create(limits, budget_events);
    if (!budget) return 73;
    budget_observed.session=budget->get();
    constexpr std::string_view preface="PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    auto initial=(**budget).receive(std::as_bytes(std::span{preface}));
    constexpr std::array<std::byte,9> settings{std::byte{0},std::byte{0},std::byte{0},std::byte{4},std::byte{0},std::byte{0},std::byte{0},std::byte{0},std::byte{0}};
    auto setup=(**budget).receive(settings);
    if (!initial || *initial!=preface.size() || !setup || *setup!=settings.size()) return 74;
    constexpr std::array<std::byte,17> ping{std::byte{0},std::byte{0},std::byte{8},std::byte{6}};
    for (int i=0;i<3;++i) if (!(**budget).receive(ping)) return 76;
    auto queued=(**budget).library_memory_used();
    std::array<std::byte,1024> sink{};
    for (;;) {
        auto n=(**budget).output(sink);
        if (!n) return 77;
        if (!*n) break;
    }
    if ((**budget).library_memory_used()>=queued || (**budget).library_memory_peak()<queued) return 78;
    bool exhausted=false;
    for (int i=0;i<64;++i) {
        auto received=(**budget).receive(ping);
        if (!received) {
            exhausted=received.error().kind==nh::ServerErrorKind::library && received.error().library_code==h2::NGHTTP2_ERR_NOMEM;
            break;
        }
    }
    if (!exhausted || (**budget).library_memory_used()>limits.library_memory_bytes ||
        (**budget).library_memory_peak()>limits.library_memory_bytes || (**budget).receive({})) return 75;
    // A failed nghttp2 response submission must release the separately
    // allocated response body and leave the session unusable after fatal OOM.
    constexpr std::array<std::byte,15> request{
        std::byte{0},std::byte{0},std::byte{6},std::byte{1},std::byte{5},std::byte{0},std::byte{0},std::byte{0},std::byte{1},
        std::byte{0x82},std::byte{0x87},std::byte{0x01},std::byte{0x01},std::byte{'x'},std::byte{0x84}};
    auto feed_request=[&](nh::ServerSession& session) {
        auto a=session.receive(std::as_bytes(std::span{preface}));
        auto b=session.receive(settings);
        auto c=session.receive(request);
        return a && b && c && *a==preface.size() && *b==settings.size() && *c==request.size();
    };
    // Incomplete header blocks consume a logical share of the same budget;
    // completing the block releases it before application code can respond.
    limits.shared_memory_bytes=4*1024*1024;
    auto fragmented=nh::ServerSession::create(limits,budget_events);
    if (!fragmented || !(**fragmented).receive(std::as_bytes(std::span{preface})) ||
        !(**fragmented).receive(settings)) return 102;
    auto prefix=(**fragmented).receive(std::span{request}.first(10));
    if (!prefix || *prefix!=10 || !(**fragmented).header_memory_charge() ||
        (**fragmented).shared_memory_used()!=(**fragmented).library_memory_used()+(**fragmented).stream_memory_charge()+(**fragmented).header_memory_charge()) return 103;
    auto suffix=(**fragmented).receive(std::span{request}.subspan(10));
    if (!suffix || *suffix!=request.size()-10 || (**fragmented).header_memory_charge()!=0 ||
        (**fragmented).shared_memory_used()!=(**fragmented).library_memory_used()+(**fragmented).stream_memory_charge() || !(**fragmented).stream_memory_charge()) return 104;
    fragmented->reset();
    limits.shared_memory_bytes=std::numeric_limits<std::size_t>::max();
    limits.library_memory_bytes=4*1024*1024;
    auto measurement=nh::ServerSession::create(limits,budget_events);
    if (!measurement || !feed_request(**measurement)) return 82;
    auto request_peak=(**measurement).library_memory_peak();
    auto stream_charge=(**measurement).stream_memory_charge();
    if (!stream_charge) return 113;
    measurement->reset();
    // Find a cap where library allocations fit, but the request-header
    // charge exhausts the shared budget. The stream is reset and a later
    // request can still be accepted after the reservation is released.
    bool header_limit_recovered=false;
    for (std::size_t extra=0; extra<=1024 && !header_limit_recovered; ++extra) {
        limits.shared_memory_bytes=request_peak+stream_charge+extra;
        budget_observed.headers=0;
        auto candidate=nh::ServerSession::create(limits,budget_events);
        if (!candidate || !feed_request(**candidate) || budget_observed.headers) continue;
        std::vector<std::byte> wire;
        bool output_ok=true;
        for (;;) {
            auto n=(**candidate).output(sink);
            if (!n) { output_ok=false; break; }
            if (!*n) break;
            wire.insert(wire.end(),sink.begin(),sink.begin()+static_cast<std::ptrdiff_t>(*n));
        }
        if (!output_ok || (**candidate).header_memory_charge()!=0) continue;
        bool reset_seen=false;
        for (std::size_t pos=0; pos+9<=wire.size();) {
            auto length=(std::to_integer<std::size_t>(wire[pos])<<16) |
                        (std::to_integer<std::size_t>(wire[pos+1])<<8) | std::to_integer<std::size_t>(wire[pos+2]);
            if (length>wire.size()-pos-9) break;
            if (wire[pos+3]==std::byte{3} && wire[pos+8]==std::byte{1}) reset_seen=true;
            pos+=9+length;
        }
        if (!reset_seen) continue;
        auto retry=request; retry[8]=std::byte{3};
        auto received=(**candidate).receive(retry);
        if (received && *received==retry.size() && budget_observed.headers==1 &&
            (**candidate).shared_memory_used()<=limits.shared_memory_bytes) header_limit_recovered=true;
    }
    if (!header_limit_recovered) return 105;
    limits.shared_memory_bytes=std::numeric_limits<std::size_t>::max();
    bool submission_exhausted=false;
    constexpr std::array<std::byte,16> body{};
    for (std::size_t extra=0;extra<=1024 && !submission_exhausted;extra+=16) {
        for (int queued_pings=0;queued_pings<=6 && !submission_exhausted;++queued_pings) {
            limits.library_memory_bytes=request_peak+extra;
            auto candidate=nh::ServerSession::create(limits,budget_events);
            if (!candidate || !feed_request(**candidate)) continue;
            bool ready=true;
            for (int i=0;i<queued_pings;++i) if (!(**candidate).receive(ping)) { ready=false; break; }
            if (!ready) continue;
            auto response=(**candidate).respond_body(1,200,body);
            if (!response && response.error().library_code==h2::NGHTTP2_ERR_NOMEM) {
                auto after=(**candidate).receive({});
                submission_exhausted=(**candidate).response_memory_used()==0 &&
                    !after && after.error().kind==nh::ServerErrorKind::failed;
                if (!submission_exhausted) return 83;
            }
        }
    }
    if (!submission_exhausted) return 84;
    // Response storage and nghttp2 allocations compete for the same cap.
    // A body rejected before allocation must leave the stream usable; if the
    // body consumes the remaining budget, nghttp2 submission fails and the
    // body reservation must be released.
    limits.library_memory_bytes=4*1024*1024;
    // The response body on one stream competes with a header block that is
    // still being decoded for another stream. Rejecting it must not consume
    // the response slot, and completing the header block releases its charge.
    limits.shared_memory_bytes=request_peak+8192;
    limits.response_bytes=limits.shared_memory_bytes;
    limits.total_response_bytes=limits.shared_memory_bytes;
    auto mixed=nh::ServerSession::create(limits,budget_events);
    if (!mixed || !feed_request(**mixed)) return 106;
    auto partial_request=request; partial_request[8]=std::byte{3};
    auto partial=(**mixed).receive(std::span{partial_request}.first(10));
    if (!partial || *partial!=10 || !(**mixed).header_memory_charge()) return 107;
    auto mixed_available=limits.shared_memory_bytes-(**mixed).shared_memory_used();
    std::vector<std::byte> competing_body(mixed_available+1);
    if (competing_body.size()>limits.shared_memory_bytes-(**mixed).library_memory_used()) return 112;
    auto held_header_charge=(**mixed).header_memory_charge();
    auto blocked_body=(**mixed).respond_body(1,200,competing_body);
    if (blocked_body || blocked_body.error().kind!=nh::ServerErrorKind::budget_exceeded ||
        (**mixed).response_memory_used()!=0 || (**mixed).header_memory_charge()!=held_header_charge ||
        (**mixed).shared_memory_used()>limits.shared_memory_bytes) return 108;
    auto partial_end=(**mixed).receive(std::span{partial_request}.subspan(10));
    if (!partial_end || *partial_end!=partial_request.size()-10 || (**mixed).header_memory_charge()!=0 ||
        !(**mixed).respond_body(1,200,body) || !(**mixed).respond_empty(3,204)) return 109;
    for (;;) {
        auto n=(**mixed).output(sink);
        if (!n) return 110;
        if (!*n) break;
    }
    if ((**mixed).response_memory_used()!=0 || (**mixed).shared_memory_used()>limits.shared_memory_bytes) return 111;
    limits.shared_memory_bytes=request_peak+1024;
    limits.response_bytes=limits.shared_memory_bytes;
    limits.total_response_bytes=limits.shared_memory_bytes;
    limits.response_header_fields=1024;
    auto shared=nh::ServerSession::create(limits,budget_events);
    if (!shared || !feed_request(**shared)) return 85;
    auto available=limits.shared_memory_bytes-(**shared).shared_memory_used();
    std::vector<nh::Header> many_headers(1024,nh::Header{"x","y"});
    auto fields_rejected=(**shared).respond_empty(1,200,many_headers);
    if (fields_rejected || fields_rejected.error().kind!=nh::ServerErrorKind::budget_exceeded ||
        (**shared).shared_memory_used()!=limits.shared_memory_bytes-available) return 116;
    std::vector<std::byte> too_big(available+1);
    if (too_big.size()>limits.shared_memory_bytes-(**shared).library_memory_used() || !(**shared).stream_memory_charge()) return 115;
    auto rejected=(**shared).respond_body(1,200,too_big);
    if (rejected || rejected.error().kind!=nh::ServerErrorKind::budget_exceeded ||
        (**shared).response_memory_used()!=0 || (**shared).shared_memory_used()>limits.shared_memory_bytes) return 86;
    too_big.resize(available-sizeof(h2::nghttp2_nv));
    auto exhausted_submission=(**shared).respond_body(1,200,too_big);
    if (exhausted_submission || exhausted_submission.error().library_code!=h2::NGHTTP2_ERR_NOMEM ||
        (**shared).response_memory_used()!=0 || (**shared).shared_memory_used()>limits.shared_memory_bytes) return 87;
    limits.shared_memory_bytes=request_peak+4096;
    auto success=nh::ServerSession::create(limits,budget_events);
    if (!success || !feed_request(**success) || !(**success).respond_body(1,200,body) ||
        (**success).shared_memory_used()!=(**success).library_memory_used()+(**success).stream_memory_charge()+body.size() ||
        (**success).shared_memory_used()>limits.shared_memory_bytes) return 88;
    for (;;) {
        auto n=(**success).output(sink);
        if (!n) return 89;
        if (!*n) break;
    }
    if ((**success).response_memory_used()!=0 ||
        (**success).shared_memory_used()!=(**success).library_memory_used()) return 90;
    // Releasing one stream on a peer reset makes its body reservation
    // available to another already-open stream.
    auto reused=nh::ServerSession::create(limits,budget_events);
    if (!reused || !feed_request(**reused)) return 93;
    auto second_request=request;
    second_request[8]=std::byte{3};
    auto received_second=(**reused).receive(second_request);
    if (!received_second || *received_second!=second_request.size()) return 94;
    if ((**reused).stream_memory_charge()!=2*stream_charge) return 114;
    auto remaining=limits.shared_memory_bytes-(**reused).shared_memory_used();
    std::vector<std::byte> larger_body(remaining/2+1);
    if (!(**reused).respond_body(1,200,larger_body) || (**reused).response_memory_used()!=larger_body.size()) return 94;
    auto blocked=(**reused).respond_body(3,200,larger_body);
    if (blocked || blocked.error().kind!=nh::ServerErrorKind::budget_exceeded) return 101;
    constexpr std::array<std::byte,13> reset{std::byte{0},std::byte{0},std::byte{4},std::byte{3},std::byte{0},
        std::byte{0},std::byte{0},std::byte{0},std::byte{1},std::byte{0},std::byte{0},std::byte{0},std::byte{8}};
    auto received_reset=(**reused).receive(reset);
    if (!received_reset || *received_reset!=reset.size() || (**reused).response_memory_used()!=0 || (**reused).stream_memory_charge()!=stream_charge ||
        !(**reused).respond_body(3,200,larger_body) || (**reused).response_memory_used()!=larger_body.size() ||
        (**reused).shared_memory_used()>limits.shared_memory_bytes) return 95;
    for (;;) {
        auto n=(**reused).output(sink);
        if (!n) return 96;
        if (!*n) break;
    }
    if ((**reused).response_memory_used()!=0 || (**reused).shared_memory_used()>limits.shared_memory_bytes) return 97;
    // A live response body reduces the space available to peer-generated ACKs.
    auto competing=nh::ServerSession::create(limits,budget_events);
    if (!competing || !feed_request(**competing) || !(**competing).respond_body(1,200,larger_body)) return 98;
    bool shared_exhausted=false;
    for (int i=0;i<64;++i) {
        auto r=(**competing).receive(ping);
        if (!r) {
            shared_exhausted=r.error().kind==nh::ServerErrorKind::library && r.error().library_code==h2::NGHTTP2_ERR_NOMEM;
            break;
        }
        if ((**competing).shared_memory_used()>limits.shared_memory_bytes) return 99;
    }
    if (!shared_exhausted || (**competing).response_memory_used()!=larger_body.size() ||
        (**competing).shared_memory_used()>limits.shared_memory_bytes) return 100;
    // Simultaneous transport allowances compete with application response
    // storage, and releasing them makes the same stream usable again.
    limits.shared_memory_bytes=request_peak+stream_charge+32768;
    limits.response_bytes=limits.shared_memory_bytes;
    limits.total_response_bytes=limits.shared_memory_bytes;
    auto transport=nh::ServerSession::create(limits,budget_events);
    if (!transport || !feed_request(**transport)) return 117;
    auto before=(**transport).shared_memory_used();
    if (!(**transport).reserve_input(4096) || !(**transport).reserve_output(4096) ||
        !(**transport).reserve_ciphertext(4096) || !(**transport).reserve_scratch(4096) ||
        !(**transport).reserve_transport(4096) || (**transport).reserve_input(1) ||
        (**transport).shared_memory_used()!=before+5*4096) return 118;
    auto remaining_transport=limits.shared_memory_bytes-(**transport).shared_memory_used();
    std::vector<std::byte> blocked_transport(remaining_transport+1);
    auto transport_rejected=(**transport).respond_body(1,200,blocked_transport);
    if (transport_rejected || transport_rejected.error().kind!=nh::ServerErrorKind::budget_exceeded ||
        (**transport).response_memory_used() || (**transport).shared_memory_used()!=before+5*4096) return 119;
    (**transport).release_input(); (**transport).release_output(); (**transport).release_ciphertext();
    (**transport).release_scratch(); (**transport).release_transport();
    if ((**transport).shared_memory_used()!=before || !(**transport).respond_body(1,200,body)) return 120;
    for (;;) { auto n=(**transport).output(sink); if (!n) return 121; if (!*n) break; }
    if ((**transport).response_memory_used() || (**transport).shared_memory_used()>limits.shared_memory_bytes) return 122;
    // Queue many responses before draining, exercising nghttp2's output scheduler.
    nh::ServerLimits many_limits{64, 4, 128, 64, 4096};
    auto many=nh::ServerSession::create(many_limits,budget_events);
    if (!many || !feed_request(**many) || !(**many).respond_body(1,200,body)) return 123;
    for (unsigned id=3; id<128; id+=2) {
        auto next=request; next[8]=static_cast<std::byte>(id);
        if (!(**many).receive(next) || !(**many).respond_body(static_cast<std::int32_t>(id),200,body)) return 124;
    }
    for (;;) { auto n=(**many).output(sink); if (!n) return 125; if (!*n) break; }
    if ((**many).response_memory_used() || (**many).library_memory_peak()>many_limits.library_memory_bytes) return 126;
    // Reservations may precede session creation and survive its destruction.
    nh::ServerLimits owned_limits{8,4,128,1024,4096}; owned_limits.shared_memory_bytes=65536;
    auto owner=std::make_shared<nexus::memory::Budget>(owned_limits.shared_memory_bytes);
    auto handshake=nexus::memory::Budget::reserve(owner,8192);
    if (!handshake || owner->used()!=8192) return 127;
    auto owned=nh::ServerSession::create(owned_limits,budget_events,owner);
    if (!owned || owner->used()!=(**owned).shared_memory_used() || owner->reserved()!=8192 || !feed_request(**owned)) return 128;
    auto duplicate=nh::ServerSession::create(owned_limits,budget_events,owner);
    if (duplicate || duplicate.error().kind!=nh::ServerErrorKind::invalid_state) return 129;
    auto mismatch=owned_limits; --mismatch.shared_memory_bytes;
    auto invalid=nh::ServerSession::create(mismatch,budget_events,owner);
    if (invalid || invalid.error().kind!=nh::ServerErrorKind::invalid_argument) return 130;
    auto remaining_owner=owner->limit()-owner->used();
    auto blocker=nexus::memory::Budget::reserve(owner,remaining_owner);
    if (!blocker || owner->used()!=owner->limit() || nexus::memory::Budget::reserve(owner,1)) return 131;
    auto response_blocked=(**owned).respond_body(1,200,body);
    if (response_blocked || response_blocked.error().kind!=nh::ServerErrorKind::budget_exceeded) return 132;
    blocker.reset();
    if (!(**owned).respond_body(1,200,body) || owner->used()!=(**owned).shared_memory_used()) return 133;
    owned->reset();
    if (owner->used()!=8192) return 134;
    auto moved=std::move(*handshake); handshake.reset();
    if (owner->used()!=8192 || moved.size()!=8192) return 135;
    moved.reset();
    if (owner->used()!=0 || !nh::ServerSession::create(owned_limits,budget_events,owner)) return 136;
    auto full=nexus::memory::Budget::reserve(owner,owner->limit());
    if (!full) return 137;
    auto no_space=nh::ServerSession::create(owned_limits,budget_events,owner);
    if (no_space || no_space.error().library_code!=h2::NGHTTP2_ERR_NOMEM) return 138;
    full.reset();
    if (!nh::ServerSession::create(owned_limits,budget_events,owner)) return 139;
    auto isolated=std::make_shared<nexus::memory::Budget>(10);
    std::weak_ptr<nexus::memory::Budget> weak=isolated;
    auto survivor=nexus::memory::Budget::reserve(isolated,10);
    if (!survivor || nexus::memory::Budget::reserve(isolated,0)) return 140;
    isolated.reset();
    if (weak.expired()) return 141;
    survivor.reset();
    if (!weak.expired()) return 142;
    std::println("HTTP/2 nghttp2 memory budget and recovery passed");
}
