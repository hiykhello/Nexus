import std;
import nexus.http2.server;
import nexus.thirdparty.nghttp2;
namespace h2 = nex::nghttp2;
namespace nh = nexus::http2;
struct Observed { nh::ServerSession* session = nullptr; };
auto on_headers(void*,std::int32_t,std::span<nh::Header const>,bool,bool) noexcept -> bool { return true; }
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
    limits.library_memory_bytes=4*1024*1024;
    auto measurement=nh::ServerSession::create(limits,budget_events);
    if (!measurement || !feed_request(**measurement)) return 82;
    auto request_peak=(**measurement).library_memory_peak();
    measurement->reset();
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
    std::println("HTTP/2 nghttp2 memory budget and recovery passed");
}
