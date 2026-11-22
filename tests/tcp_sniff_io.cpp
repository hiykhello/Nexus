import std;
import sniff.tcp;
import sniff.tcp_io;
import sniff.route_tcp;
import rules;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

namespace s=sniff;
namespace c=nex::capy;
namespace io=nex::corosio;
using Clock=std::chrono::steady_clock;
using namespace std::chrono_literals;

auto exercise(io::local_stream_socket& reader,io::local_stream_socket& writer,bool& passed) -> c::task<> {
    std::array<std::uint8_t,1024> wire{},scratch{},after{};
    s::TcpSniffer sniff(wire,scratch);
    std::string_view first="GET / HTTP/1.1\r\nHost: ";
    auto [write_error,written]=co_await writer.write_some(c::const_buffer(first.data(),first.size()));
    if(write_error || written!=first.size())co_return;
    auto result=co_await s::read_tcp_sniff(reader,sniff,Clock::now()+20ms);
    if(result.stop!=s::TcpReadStop::deadline || result.sniff.status!=s::TcpStatus::need_more ||
       !std::ranges::equal(sniff.wire(),first))co_return;
    std::string_view remainder="site.example\r\n\r\nbody";
    auto [error,count]=co_await writer.write_some(c::const_buffer(remainder.data(),remainder.size()));
    if(error || count!=remainder.size())co_return;
    auto [read_error,size]=co_await io::timeout(reader.read_some(c::mutable_buffer(after.data(),after.size())),Clock::now()+1s);
    if(read_error || size!=remainder.size() || !std::ranges::equal(std::span(after).first(size),remainder))co_return;
    std::string_view full="GET / HTTP/1.1\r\nHost: site.example\r\n\r\nbody";
    auto [second_error,second_size]=co_await writer.write_some(c::const_buffer(full.data(),full.size()));
    if(second_error || second_size!=full.size())co_return;
    std::array<std::uint8_t,1024> wire2{},scratch2{};s::TcpSniffer classified(wire2,scratch2);
    auto second=co_await s::read_tcp_sniff(reader,classified,Clock::now()+1s);
    auto kept=classified.wire();
    if(second.stop!=s::TcpReadStop::classified || second.sniff.status!=s::TcpStatus::matched ||
        second.sniff.domain!="site.example" || kept.size()>full.size() ||
        !std::ranges::equal(kept,full.substr(0,kept.size())))co_return;
    auto offset=kept.size();
    while(offset<full.size()) {
        auto [tail_error,tail_size]=co_await io::timeout(reader.read_some(c::mutable_buffer(after.data(),after.size())),Clock::now()+1s);
        if(tail_error || !tail_size || tail_size>full.size()-offset ||
            !std::ranges::equal(std::span(after).first(tail_size),full.substr(offset,tail_size)))co_return;
        offset+=tail_size;
    }
    passed=true;
}

auto canceled(io::local_stream_socket& reader,bool& passed) -> c::task<> {
    std::array<std::uint8_t,64> wire{},scratch{};s::TcpSniffer sniff(wire,scratch);
    auto result=co_await s::read_tcp_sniff(reader,sniff,Clock::now()+1s);
    passed=result.stop==s::TcpReadStop::canceled && sniff.wire().empty() && reader.is_open();
}

auto route(io::local_stream_socket& reader,io::local_stream_socket& writer,bool& passed) -> c::task<> {
    namespace r = ::rules;
    std::vector<r::ProgramRule> rules{
        {r::RuleSet{{},2},{r::ProgramActionKind::sniff}},
        {r::RuleSet{{{"domain","site.example"}},2},{r::ProgramActionKind::route,1},r::DomainSource::sniffed},
        {r::RuleSet{{},2},{r::ProgramActionKind::reject}}
    };
    auto program=r::RouteProgram::compile(rules,2);if(!program)co_return;
    r::ProgramCursor cursor;r::ProgramInput input{.network=r::Network::tcp};
    std::array<std::uint8_t,1024> wire{},scratch{};s::TcpSniffer sniff(wire,scratch);
    std::string_view request="GET / HTTP/1.1\r\nHost: site.example\r\n\r\nbody";
    auto [error,size]=co_await writer.write_some(c::const_buffer(request.data(),request.size()));
    if(error || size!=request.size())co_return;
    auto result=co_await s::run_tcp_route(*program,cursor,input,reader,sniff,Clock::now()+1s,false);
    passed=result.stop==s::RouteTcpStop::terminal && result.step && result.step->action.kind==r::ProgramActionKind::route &&
        result.step->action.outbound==1 && input.sniffed_domain=="site.example" &&
        std::ranges::equal(sniff.wire(),request.substr(0,sniff.wire().size()));
}

auto candidates() -> bool {
    s::RouteCandidates owner;
    ::rules::ProgramInput input;
    if(owner.view())return false;
    std::array<io::endpoint,2> endpoints{io::endpoint(io::ipv4_address::loopback(),80),io::endpoint(io::ipv6_address::loopback(),80)};
    if(!owner.assign(endpoints,input) || !input.candidates || !owner.view() || owner.view()->size()!=2 || (*owner.view())[0].size!=4 ||
        (*owner.view())[0].bytes[0]!=127 || (*owner.view())[1].size!=16 || (*owner.view())[1].bytes[15]!=1)return false;
    std::array<io::endpoint,257> excessive{};
    if(owner.assign(excessive,input) || !owner.view() || owner.view()->size()!=2)return false;
    input.ip="127.0.0.1";
    if(owner.assign({},input) || owner.view()->size()!=2)return false;
    input.ip.reset();
    return owner.assign({},input) && owner.view() && owner.view()->empty() && input.candidates && input.candidates->empty();
}

struct FakeResolver {
    auto operator()(std::string_view name,std::uint16_t port,Clock::time_point) -> c::task<std::expected<std::vector<io::endpoint>,int>> {
        if(name!="site.example" || port!=443)co_return std::unexpected(1);
        co_return std::vector<io::endpoint>{io::endpoint(io::ipv4_address::loopback(),port),io::endpoint(io::ipv6_address::loopback(),port)};
    }
};
auto resolve(bool& passed) -> c::task<> {
    namespace r = ::rules;
    std::vector<r::ProgramRule> rules{
        {r::RuleSet{{},2},{r::ProgramActionKind::resolve}},
        {r::RuleSet{{{"ip-cidr","127.0.0.0/8"}},2},{r::ProgramActionKind::route,1}}
    };
    auto program=r::RouteProgram::compile(rules,2);if(!program)co_return;
    r::ProgramCursor cursor;r::ProgramInput input{.explicit_domain="site.example",.port=443};
    auto pending=cursor.poll(*program,input);if(!pending || !pending->step)co_return;
    s::RouteCandidates candidates;std::vector<io::endpoint> endpoints;FakeResolver resolver;
    auto result=co_await s::resolve_tcp_action(cursor,*pending->step,input,candidates,endpoints,resolver,Clock::now()+1s);
    if(!result || endpoints.size()!=2 || !input.candidates || input.candidates->size()!=2)co_return;
    auto next=cursor.poll(*program,input);
    passed=next && next->step && next->step->action.kind==r::ProgramActionKind::route && next->step->action.outbound==1;
}

auto replay(io::local_stream_socket& sender,io::local_stream_socket& receiver,bool& passed) -> c::task<> {
    std::string_view first="retained ",tail="pre-read tail";
    auto bytes=[](std::string_view value){return std::span(reinterpret_cast<std::uint8_t const*>(value.data()),value.size());};
    s::TcpReplay replay(bytes(first),bytes(tail));
    if(!co_await replay.send(sender,Clock::now()+1s) || replay.status()!=s::ReplayStatus::complete ||
        replay.committed()!=first.size()+tail.size() || co_await replay.send(sender,Clock::now()+1s))co_return;
    std::array<std::uint8_t,64> output{};std::size_t total=0;
    while(total<first.size()+tail.size()) {
        auto [error,size]=co_await io::timeout(receiver.read_some(c::mutable_buffer(output.data()+total,output.size()-total)),Clock::now()+1s);
        if(error || !size)co_return;total+=size;
    }
    auto expected=std::string(first)+std::string(tail);
    if(!std::ranges::equal(std::span(output).first(total),expected))co_return;
    s::TcpReplay expired(bytes(first));
    if(co_await expired.send(sender,Clock::now()) || expired.status()!=s::ReplayStatus::failed ||
       expired.committed()!=0 || co_await expired.send(sender,Clock::now()+1s))co_return;
    passed=true;
}

int main() {
    if(!candidates())return 9;
    auto context=io::make_io_context(false);io::local_stream_socket reader(context),writer(context);
    if(io::connect_pair(reader,writer))return 1;
    bool passed=false,done=false,exception=false;
    c::run_async(context.get_executor(),[&] {done=true;},[&](std::exception_ptr) noexcept {done=true;exception=true;})(exercise(reader,writer,passed));
    context.run_for(2s);
    if(!done || exception || !passed)return 2;
    auto canceled_context=io::make_io_context(false);io::local_stream_socket a(canceled_context),b(canceled_context);
    if(io::connect_pair(a,b))return 3;
    std::stop_source stop;stop.request_stop();bool cancel_passed=false,cancel_done=false,cancel_exception=false;
    c::run_async(canceled_context.get_executor(),stop.get_token(),[&] {cancel_done=true;},
        [&](std::exception_ptr) noexcept {cancel_done=true;cancel_exception=true;})(canceled(a,cancel_passed));
    canceled_context.run_for(2s);
    if(!cancel_done || cancel_exception || !cancel_passed)return 4;
    auto route_context=io::make_io_context(false);io::local_stream_socket x(route_context),y(route_context);
    if(io::connect_pair(x,y))return 5;
    bool route_passed=false,route_done=false,route_exception=false;
    c::run_async(route_context.get_executor(),[&] {route_done=true;},
        [&](std::exception_ptr) noexcept {route_done=true;route_exception=true;})(route(x,y,route_passed));
    route_context.run_for(2s);
    if(!route_done || route_exception || !route_passed)return 6;
    auto replay_context=io::make_io_context(false);io::local_stream_socket p(replay_context),q(replay_context);
    if(io::connect_pair(p,q))return 7;
    bool replay_passed=false,replay_done=false,replay_exception=false;
    c::run_async(replay_context.get_executor(),[&] {replay_done=true;},
        [&](std::exception_ptr) noexcept {replay_done=true;replay_exception=true;})(replay(p,q,replay_passed));
    replay_context.run_for(2s);
    if(!replay_done || replay_exception || !replay_passed)return 8;
    auto resolve_context=io::make_io_context(false);bool resolve_passed=false,resolve_done=false,resolve_exception=false;
    c::run_async(resolve_context.get_executor(),[&] {resolve_done=true;},
        [&](std::exception_ptr) noexcept {resolve_done=true;resolve_exception=true;})(resolve(resolve_passed));
    resolve_context.run_for(2s);
    if(!resolve_done || resolve_exception || !resolve_passed)return 10;
    std::cout << "TCP sniff deadline, cancellation, retained input and subsequent socket reads passed\n";
    return 0;
}
