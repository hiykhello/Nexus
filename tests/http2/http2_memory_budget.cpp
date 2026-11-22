import std;
import http2.server;
import nexus.thirdparty.nghttp2;
namespace h2 = nex::nghttp2;
namespace nh = http2;
static thread_local bool watch_body=false, body_released_charged=false;
static thread_local void* body_allocation=nullptr;
static thread_local ::memory::Budget* body_budget=nullptr;
static thread_local nh::ServerSession* body_session=nullptr;
void* operator new[](std::size_t size) {
    if (auto p=std::malloc(size ? size : 1)) {
        if (watch_body && size==37) body_allocation=p;
        return p;
    }
    throw std::bad_alloc{};
}
void operator delete[](void* p) noexcept {
    if (p && p==body_allocation) {
        body_released_charged=body_budget && body_session && body_session->response_memory_used()==37 && body_budget->used()>=37;
        body_allocation=nullptr;
    }
    std::free(p);
}
void operator delete[](void* p,std::size_t) noexcept { ::operator delete[](p); }
struct Observed { nh::ServerSession* session = nullptr; unsigned headers = 0; bool fail_in_callback = false, view_survived = false; };
auto on_headers(void* context,std::int32_t,std::span<nh::Header const> fields,bool,bool) noexcept -> bool {
    auto& observed=*static_cast<Observed*>(context); ++observed.headers;
    if (observed.fail_in_callback) {
        if (fields.empty() || fields.front().name!=":method") return false;
        auto charged=observed.session->header_memory_charge();
        observed.session->fail_transport(false);
        observed.view_survived=charged && observed.session->header_memory_charge()==charged &&
            fields.front().name==":method" && fields.front().value=="GET";
    }
    return true;
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
    // Failed transport must release an incomplete header block while the
    // session and its shared budget are still alive.
    auto abandoned=nh::ServerSession::create(limits,budget_events);
    if (!abandoned || !feed_request(**abandoned)) return 113;
    auto abandoned_partial=(**abandoned).receive(std::span{partial_request}.first(10));
    if (!abandoned_partial || *abandoned_partial!=10 || !(**abandoned).header_memory_charge()) return 114;
    auto header_charge=(**abandoned).header_memory_charge();
    auto before_failure=(**abandoned).shared_memory_used();
    (**abandoned).fail_transport(false);
    if ((**abandoned).header_memory_charge()!=0 || (**abandoned).shared_memory_used()!=before_failure-header_charge ||
        (**abandoned).receive({}).error().kind!=nh::ServerErrorKind::failed) return 115;
    // Defensive coverage: even if failure is reported during a callback, the
    // borrowed header view must survive until it returns. Normal callbacks
    // must not reenter the session.
    Observed callback_observed; callback_observed.fail_in_callback=true;
    nh::ServerEvents callback_events{&callback_observed,on_headers,on_data,on_end,on_closed};
    auto callback_session=nh::ServerSession::create(limits,callback_events);
    if (!callback_session) return 116;
    callback_observed.session=callback_session->get();
    auto callback_initial=(**callback_session).receive(std::as_bytes(std::span{preface}));
    auto callback_settings=(**callback_session).receive(settings);
    auto callback_request=(**callback_session).receive(request);
    if (!callback_initial || !callback_settings || !callback_request || !callback_observed.view_survived ||
        (**callback_session).header_memory_charge()!=0) return 117;
    auto callback_after=(**callback_session).receive({});
    if (callback_after || callback_after.error().kind!=nh::ServerErrorKind::failed) return 118;
    // A malformed field rejected by nghttp2 after valid fields must not
    // retain the partially decoded application header block.
    Observed malformed_observed;
    nh::ServerEvents malformed_events{&malformed_observed,on_headers,on_data,on_end,on_closed};
    auto malformed=nh::ServerSession::create(limits,malformed_events);
    if (!malformed) return 119;
    auto malformed_initial=(**malformed).receive(std::as_bytes(std::span{preface}));
    auto malformed_settings=(**malformed).receive(settings);
    constexpr std::array<std::byte,17> invalid_request{
        std::byte{0},std::byte{0},std::byte{8},std::byte{1},std::byte{5},std::byte{0},std::byte{0},std::byte{0},std::byte{1},
        std::byte{0x82},std::byte{0x87},std::byte{0x84},std::byte{0},std::byte{1},std::byte{'X'},std::byte{1},std::byte{'y'}};
    auto invalid_result=(**malformed).receive(invalid_request);
    if (!malformed_initial || !malformed_settings || !invalid_result) return 120;
    for (;;) { auto n=(**malformed).output(sink); if (!n) return 121; if (!*n) break; }
    if ((**malformed).header_memory_charge()!=0 || malformed_observed.headers) return 122;
    auto valid_after=request; valid_after[8]=std::byte{3};
    auto accepted_after=(**malformed).receive(valid_after);
    if (!accepted_after || *accepted_after!=valid_after.size() || malformed_observed.headers!=1 ||
        !(**malformed).respond_empty(3,204)) return 123;
    // HEADERS without END_HEADERS must be followed by CONTINUATION. A PING
    // here terminates the connection; its partial header must be discarded.
    Observed interleaved_observed;
    nh::ServerEvents interleaved_events{&interleaved_observed,on_headers,on_data,on_end,on_closed};
    auto interleaved=nh::ServerSession::create(limits,interleaved_events);
    if (!interleaved) return 124;
    if (!(**interleaved).receive(std::as_bytes(std::span{preface})) || !(**interleaved).receive(settings)) return 125;
    constexpr std::array<std::byte,10> unfinished{std::byte{0},std::byte{0},std::byte{1},std::byte{1},
        std::byte{0},std::byte{0},std::byte{0},std::byte{0},std::byte{1},std::byte{0x82}};
    if (!(**interleaved).receive(unfinished) || !(**interleaved).header_memory_charge()) return 126;
    auto violation=(**interleaved).receive(ping);
    if (!violation) return 127;
    std::vector<std::byte> shutdown_wire;
    for (;;) {
        auto n=(**interleaved).output(sink); if (!n) return 128; if (!*n) break;
        shutdown_wire.insert(shutdown_wire.end(),sink.begin(),sink.begin()+*n);
    }
    bool protocol_goaway=false;
    for (std::size_t offset=0; offset+9<=shutdown_wire.size();) {
        auto byte=[&](std::size_t i) { return std::to_integer<unsigned>(shutdown_wire[offset+i]); };
        auto length=(byte(0)<<16)|(byte(1)<<8)|byte(2);
        if (length>shutdown_wire.size()-offset-9) return 130;
        if (byte(3)==7 && length>=8 && byte(13)==0 && byte(14)==0 && byte(15)==0 && byte(16)==1)
            protocol_goaway=true;
        offset+=9+length;
    }
    if (!protocol_goaway || (**interleaved).header_memory_charge()!=0) return 129;
    // Preserve a response behind a zero flow-control window while a different
    // stream causes a connection error, then observe terminal cleanup.
    Observed terminal_observed;
    nh::ServerEvents terminal_events{&terminal_observed,on_headers,on_data,on_end,on_closed};
    auto terminal_budget=std::make_shared<::memory::Budget>(limits.shared_memory_bytes);
    auto terminal=nh::ServerSession::create(limits,terminal_events,terminal_budget);
    if (!terminal || !(**terminal).receive(std::as_bytes(std::span{preface}))) return 131;
    constexpr std::array<std::byte,15> zero_window{std::byte{0},std::byte{0},std::byte{6},std::byte{4},
        std::byte{0},std::byte{0},std::byte{0},std::byte{0},std::byte{0},std::byte{0},std::byte{4},
        std::byte{0},std::byte{0},std::byte{0},std::byte{0}};
    if (!(**terminal).receive(zero_window) || !(**terminal).receive(request) || !(**terminal).respond_body(1,200,body)) return 132;
    auto unfinished_other=unfinished; unfinished_other[8]=std::byte{3};
    if (!(**terminal).receive(unfinished_other) || !(**terminal).receive(ping)) return 133;
    std::vector<std::byte> terminal_wire; std::size_t released_at=0;
    for (;;) {
        auto n=(**terminal).output(std::span{sink}.first(1)); if (!n) return 134; if (!*n) break;
        terminal_wire.push_back(sink[0]);
        if (!released_at && (**terminal).response_memory_used()==0) released_at=terminal_wire.size();
    }
    bool released_after_goaway=false;
    for (std::size_t offset=0; offset+9<=terminal_wire.size();) {
        auto byte=[&](std::size_t i) { return std::to_integer<unsigned>(terminal_wire[offset+i]); };
        auto length=(byte(0)<<16)|(byte(1)<<8)|byte(2);
        if (length>terminal_wire.size()-offset-9) return 137;
        auto type=byte(3);
        offset+=9+length;
        if (type==7 && offset==released_at) released_after_goaway=true;
    }
    if (!released_after_goaway) return 138;
    // The library is destroyed before its borrowed providers, without waiting
    // for destruction of the enclosing ServerSession.
    if ((**terminal).response_memory_used()!=0 || (**terminal).stream_memory_charge()!=0 ||
        terminal_budget->used()!=0 || (**terminal).receive({}) || (**terminal).respond_empty(1,204)) return 135;
    terminal->reset();
    if (terminal_budget->used()!=0) return 136;
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
    auto owner=std::make_shared<::memory::Budget>(owned_limits.shared_memory_bytes);
    auto handshake=::memory::Budget::reserve(owner,8192);
    if (!handshake || owner->used()!=8192) return 127;
    auto owned=nh::ServerSession::create(owned_limits,budget_events,owner);
    if (!owned || owner->used()!=(**owned).shared_memory_used() || owner->reserved()!=8192 || !feed_request(**owned)) return 128;
    auto duplicate=nh::ServerSession::create(owned_limits,budget_events,owner);
    if (duplicate || duplicate.error().kind!=nh::ServerErrorKind::invalid_state) return 129;
    auto mismatch=owned_limits; --mismatch.shared_memory_bytes;
    auto invalid=nh::ServerSession::create(mismatch,budget_events,owner);
    if (invalid || invalid.error().kind!=nh::ServerErrorKind::invalid_argument) return 130;
    auto remaining_owner=owner->limit()-owner->used();
    auto blocker=::memory::Budget::reserve(owner,remaining_owner);
    if (!blocker || owner->used()!=owner->limit() || ::memory::Budget::reserve(owner,1)) return 131;
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
    auto full=::memory::Budget::reserve(owner,owner->limit());
    if (!full) return 137;
    auto no_space=nh::ServerSession::create(owned_limits,budget_events,owner);
    if (no_space || no_space.error().library_code!=h2::NGHTTP2_ERR_NOMEM) return 138;
    full.reset();
    if (!nh::ServerSession::create(owned_limits,budget_events,owner)) return 139;
    for (bool destroy : {false,true}) {
        auto probe_owner=std::make_shared<::memory::Budget>(owned_limits.shared_memory_bytes);
        auto probe=nh::ServerSession::create(owned_limits,budget_events,probe_owner);
        if (!probe || !feed_request(**probe)) return 141;
        std::array<std::byte,37> probe_body{};
        body_budget=probe_owner.get(); body_session=probe->get(); body_released_charged=false; watch_body=true;
        auto response=(**probe).respond_body(1,200,probe_body); watch_body=false;
        if (!response || !body_allocation) return 142;
        if (destroy) probe->reset();
        else if (!(**probe).receive(reset)) return 143;
        if (body_allocation || !body_released_charged || (destroy && probe_owner->used())) return 144;
        body_budget=nullptr; body_session=nullptr;
    }
    auto isolated=std::make_shared<::memory::Budget>(10);
    std::weak_ptr<::memory::Budget> weak=isolated;
    auto survivor=::memory::Budget::reserve(isolated,10);
    if (!survivor || ::memory::Budget::reserve(isolated,0)) return 140;
    isolated.reset();
    if (weak.expired()) return 141;
    survivor.reset();
    if (!weak.expired()) return 142;
    std::println("HTTP/2 nghttp2 memory budget and recovery passed");
}
