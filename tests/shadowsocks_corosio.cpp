#include <boost/capy/buffers.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/local_stream_socket.hpp>
#include <boost/corosio/local_connect_pair.hpp>
import std;
import nexus.shadowsocks.corosio_client;
import nexus.shadowsocks.key;
import nexus.shadowsocks.chunk;
import nexus.shadowsocks.request;
import nexus.shadowsocks.replay;
import nexus.shadowsocks.frame;
import nexus.shadowsocks.response;
namespace capy=boost::capy;
namespace io=boost::corosio;
namespace s=nexus::shadowsocks;
using namespace std::chrono_literals;
struct State {
    std::optional<std::expected<s::detail::StartedRequest,s::detail::StartError>> result;
    std::array<std::uint8_t,2048> bytes{}; std::size_t received=0; std::error_code error;
};
auto send(io::local_stream_socket& socket, State& state) -> capy::task<> {
    std::array<std::uint8_t,16> psk{}; std::array<std::uint8_t,7> address{1,127,0,0,1,0,80};
    state.result=co_await s::detail::start_request(socket,psk,address,std::chrono::steady_clock::now()+2s);
}
auto receive(io::local_stream_socket& socket, State& state) -> capy::task<> {
    auto [error,n]=co_await socket.read_some(capy::mutable_buffer(state.bytes.data(),state.bytes.size()));
    state.error=error; state.received=n;
}
struct FrameState { std::optional<std::expected<void,s::detail::SendError>> result; std::array<std::uint8_t,2048> bytes{}; std::size_t received=0; };
struct LimitedSocket {
    io::local_stream_socket& socket; std::size_t writes=0;
    auto write_some(capy::const_buffer data) { ++writes; return socket.write_some(capy::const_buffer(data.data(),std::min(data.size(),std::size_t{3}))); }
    auto cancel() noexcept -> void { socket.cancel(); }
};
struct FailingSocket {
    io::local_stream_socket& socket; std::size_t writes=0, cancels=0;
    auto write_some(capy::const_buffer data) {
        if (++writes==2) socket.close();
        return socket.write_some(capy::const_buffer(data.data(),std::min(data.size(),std::size_t{3})));
    }
    auto cancel() noexcept -> void { ++cancels; socket.cancel(); }
};
struct ThrowingSocket {
    io::local_stream_socket& socket; std::size_t cancels=0;
    auto write_some(capy::const_buffer data) {
        if (data.size()) throw std::runtime_error("injected submission failure");
        return socket.write_some(data);
    }
    auto cancel() noexcept -> void { ++cancels; socket.cancel(); }
};
template<class Socket>
auto send_data(Socket& socket, s::FrameEncoder& encoder, FrameState& state, bool expired) -> capy::task<> {
    std::array<std::uint8_t,5> payload{'h','e','l','l','o'};
    state.result=co_await s::detail::send_frame(socket,encoder,payload,std::chrono::steady_clock::now()+(expired ? -1s : 2s));
}
auto send_partial(LimitedSocket& socket, State& state) -> capy::task<> {
    std::array<std::uint8_t,16> psk{}; std::array<std::uint8_t,7> address{1,127,0,0,1,0,80};
    state.result=co_await s::detail::start_request(socket,psk,address,std::chrono::steady_clock::now()+2s);
}
auto send_throwing(ThrowingSocket& socket, bool& caught) -> capy::task<> {
    std::array<std::uint8_t,16> psk{}; std::array<std::uint8_t,7> address{1,127,0,0,1,0,80};
    try { (void)co_await s::detail::start_request(socket,psk,address,std::chrono::steady_clock::now()+2s); }
    catch (std::runtime_error const&) { caught=true; }
}
auto receive_data(io::local_stream_socket& socket, FrameState& state) -> capy::task<> {
    while (state.received<39) {
        auto [error,n]=co_await socket.read_some(capy::mutable_buffer(state.bytes.data()+state.received,39-state.received));
        if (error || !n) co_return;
        state.received+=n;
    }
}
struct ResponseState { std::optional<std::expected<s::detail::StartedResponse,s::detail::ReceiveError>> result; };
struct ObservedReader {
    io::local_stream_socket& socket; std::size_t reads=0,cancels=0;
    auto read_some(capy::mutable_buffer data) { ++reads; return socket.read_some(data); }
    auto cancel() noexcept -> void { ++cancels; socket.cancel(); }
};
auto receive_observed(ObservedReader& socket, std::span<std::uint8_t const> psk,
                      std::span<std::uint8_t const> salt, ResponseState& state) -> capy::task<> {
    state.result=co_await s::detail::receive_response(socket,psk,salt,std::chrono::steady_clock::now()+100ms);
}
auto receive_response(io::local_stream_socket& socket, std::span<std::uint8_t const> psk,
                      std::span<std::uint8_t const> salt, ResponseState& state) -> capy::task<> {
    state.result=co_await s::detail::receive_response(socket,psk,salt,std::chrono::steady_clock::now()+2s);
}
auto send_bytes(io::local_stream_socket& socket, std::span<std::uint8_t const> bytes, bool& sent) -> capy::task<> {
    auto [error,n]=co_await socket.write_some(capy::const_buffer(bytes.data(),bytes.size()));
    sent=!error && n==bytes.size();
}
struct ReadState { std::vector<std::uint8_t> data; std::optional<s::detail::ReadError> error; bool done=false; };
template<class Socket>
auto read_all(s::detail::FrameReader<Socket>& reader, ReadState& state) -> capy::task<> {
    std::array<std::uint8_t,2> bytes{};
    for (;;) {
        auto result=co_await reader.read(bytes,std::chrono::steady_clock::now()+2s);
        if (!result) { state.error=result.error(); break; }
        if (!*result) break;
        state.data.insert(state.data.end(),bytes.begin(),bytes.begin()+*result);
    }
    state.done=true;
}
auto read_closed(s::detail::FrameReader<ObservedReader>& reader, bool& closed) -> capy::task<> {
    std::array<std::uint8_t,1> bytes{};
    auto result=co_await reader.read(bytes,std::chrono::steady_clock::now()+1s);
    closed=!result && result.error()==s::detail::ReadError::state;
}
auto main() -> int {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context(io::uring);
#else
    io::io_context context;
#endif
    io::local_stream_socket a(context),b(context); if (io::connect_pair(a,b)) return 1;
    State state; capy::run_async(context.get_executor())(send(a,state)); capy::run_async(context.get_executor())(receive(b,state));
    context.run_for(3s);
    if (!state.result || !*state.result || state.error || !state.received) return 2;
    std::array<std::uint8_t,16> psk{}; s::ReplayTable replay(1);
    auto wall=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    auto prefix=s::decode_request_prefix(psk,std::span{state.bytes}.first(state.received),wall,std::chrono::steady_clock::now(),replay);
    if (!prefix || prefix->consumed+prefix->header_length+16!=state.received) return 3;
    auto offset=prefix->consumed; auto count=prefix->header_length+16;
    auto decoded=s::decode_request_header(std::move(*prefix),std::span{state.bytes}.subspan(offset,count));
    std::array<std::uint8_t,7> expected{1,127,0,0,1,0,80};
    if (!decoded || !std::ranges::equal(decoded->header.address,expected) || !decoded->header.payload.empty() ||
        !std::ranges::equal(decoded->salt,(*state.result)->salt)) return 4;
    s::FrameEncoder writer(std::move((*state.result)->cipher)); s::FrameDecoder reader(std::move(decoded->cipher));
    FrameState frame; LimitedSocket limited{a}; context.restart();
    capy::run_async(context.get_executor())(send_data(limited,writer,frame,false));
    capy::run_async(context.get_executor())(receive_data(b,frame)); context.run_for(3s);
    if (!frame.result || !*frame.result || frame.received!=39 || limited.writes<=1) return 5;
    auto step=reader.feed(std::span{frame.bytes}.first(frame.received));
    if (!step || !step->payload || std::string(step->payload->begin(),step->payload->end())!="hello") return 6;
    FrameState expired; context.restart(); capy::run_async(context.get_executor())(send_data(limited,writer,expired,true)); context.run_for(3s);
    if (!expired.result || expired.result->error()!=s::detail::SendError::timeout || writer.encode({}).error()!=s::FrameError::closed) return 7;
    a.close(); b.close(); context.restart(); context.run_for(1s);
    io::local_stream_socket c(context),d(context); if (io::connect_pair(c,d)) return 8;
    std::array<std::uint8_t,16> request_salt{},response_salt{}; response_salt[0]=1;
    std::array<std::uint8_t,5> first{'w','o','r','l','d'};
    auto timestamp=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    auto response=s::encode_response(psk,response_salt,request_salt,timestamp,first); if (!response) return 9;
    auto cut=std::size_t{62}; bool sent_first=false,sent_rest=false; ResponseState got;
    context.restart(); capy::run_async(context.get_executor())(send_bytes(d,std::span{response->wire}.first(cut),sent_first));
    capy::run_async(context.get_executor())(receive_response(c,psk,request_salt,got)); context.run_for(30ms);
    if (!sent_first || got.result) return 10;
    context.restart(); capy::run_async(context.get_executor())(send_bytes(d,std::span{response->wire}.subspan(cut),sent_rest)); context.run_for(3s);
    if (!sent_rest || !got.result || !*got.result || !std::ranges::equal((*got.result)->payload,first)) return 11;
    c.close(); d.close(); context.restart(); context.run_for(1s);
    io::local_stream_socket e(context),f(context); if (io::connect_pair(e,f)) return 12;
    s::FrameEncoder response_writer(std::move(response->cipher));
    auto next=response_writer.encode(first); if (!next) return 13;
    auto combined=response->wire; combined.insert(combined.end(),next->begin(),next->end());
    bool sent_all=false; context.restart(); capy::run_async(context.get_executor())(send_bytes(f,combined,sent_all)); context.run_for(1s);
    if (!sent_all) return 14;
    ResponseState both; context.restart(); capy::run_async(context.get_executor())(receive_response(e,psk,request_salt,both)); context.run_for(1s);
    if (!both.result || !*both.result || (*both.result)->unread!=*next) return 15;
    s::detail::FrameReader next_reader(e,std::move(**both.result)); ReadState read_state;
    f.close(); context.restart(); capy::run_async(context.get_executor())(read_all(next_reader,read_state)); context.run_for(2s);
    if (!read_state.done || read_state.error || std::string(read_state.data.begin(),read_state.data.end())!="worldworld") return 16;
    e.close(); context.restart(); context.run_for(1s);
    io::local_stream_socket g(context),h(context); if (io::connect_pair(g,h)) return 17;
    bool sent_short=false; context.restart(); capy::run_async(context.get_executor())(send_bytes(h,std::span{combined}.first(12),sent_short)); context.run_for(1s);
    ResponseState short_result; context.restart(); capy::run_async(context.get_executor())(receive_response(g,psk,request_salt,short_result)); context.run_for(1s);
    if (!sent_short || !short_result.result || short_result.result->error()!=s::detail::ReceiveError::invalid_header) return 18;
    g.close(); h.close(); context.restart(); context.run_for(1s);
    io::local_stream_socket i(context),j(context); if (io::connect_pair(i,j)) return 19;
    auto truncated=combined; truncated.pop_back(); bool sent_truncated=false;
    context.restart(); capy::run_async(context.get_executor())(send_bytes(j,truncated,sent_truncated)); context.run_for(1s);
    ResponseState partial; context.restart(); capy::run_async(context.get_executor())(receive_response(i,psk,request_salt,partial)); context.run_for(1s);
    if (!sent_truncated || !partial.result || !*partial.result) return 20;
    s::detail::FrameReader truncated_reader(i,std::move(**partial.result)); ReadState truncated_state;
    j.close(); context.restart(); capy::run_async(context.get_executor())(read_all(truncated_reader,truncated_state)); context.run_for(2s);
    if (!truncated_state.done || truncated_state.error!=s::detail::ReadError::truncated ||
        std::string(truncated_state.data.begin(),truncated_state.data.end())!="world") return 21;
    i.close(); context.restart(); context.run_for(1s);
    io::local_stream_socket k(context),l(context); if (io::connect_pair(k,l)) return 22;
    LimitedSocket limited_start{k}; State short_start;
    context.restart(); capy::run_async(context.get_executor())(send_partial(limited_start,short_start)); context.run_for(2s);
    if (!short_start.result || short_start.result->error()!=s::detail::StartError::partial_write || limited_start.writes!=1) return 23;
    k.close(); l.close(); context.restart(); context.run_for(1s);
    io::local_stream_socket m(context),n(context); if (io::connect_pair(m,n)) return 24;
    auto failure_key=s::SessionKey::derive(psk,request_salt);
    auto failure_cipher=s::ChunkCipher::create(std::move(*failure_key),true);
    s::FrameEncoder failure_encoder(std::move(*failure_cipher)); FailingSocket failing{m}; FrameState failed;
    context.restart(); capy::run_async(context.get_executor())(send_data(failing,failure_encoder,failed,false)); context.run_for(2s);
    if (!failed.result || failed.result->error()!=s::detail::SendError::transport || failing.writes!=2 || failing.cancels!=1 ||
        failure_encoder.encode({}).error()!=s::FrameError::closed) return 25;
    m.close(); n.close(); context.restart(); context.run_for(1s);
    io::local_stream_socket o(context),p(context); if (io::connect_pair(o,p)) return 26;
    ThrowingSocket throwing{o}; bool caught=false;
    context.restart(); capy::run_async(context.get_executor())(send_throwing(throwing,caught)); context.run_for(2s);
    if (!caught || throwing.cancels!=1) return 27;
    o.close(); p.close(); context.restart(); context.run_for(1s);
    for (int scenario=0;scenario<4;++scenario) {
        io::local_stream_socket input(context),output(context); if (io::connect_pair(input,output)) return 28;
        auto wire=response->wire;
        if (scenario==2) wire[16]^=1; // authenticated fixed header
        if (scenario==3) wire.back()^=1; // authenticated first payload
        bool sent=false;
        if (scenario) {
            auto bytes=scenario==1 ? std::span{wire}.first(cut) : std::span{wire};
            context.restart(); capy::run_async(context.get_executor())(send_bytes(output,bytes,sent)); context.run_for(1s);
            if (!sent) return 29;
        }
        ObservedReader observed{input}; ResponseState failure;
        context.restart(); capy::run_async(context.get_executor())(receive_observed(observed,psk,request_salt,failure)); context.run_for(1s);
        auto expected=scenario<2 ? s::detail::ReceiveError::timeout : s::detail::ReceiveError::authentication;
        if (!failure.result || *failure.result || failure.result->error()!=expected || observed.cancels!=1 ||
            observed.reads<(scenario==1 ? 2U : 1U) || !context.stopped()) return 30+scenario;
        input.close(); output.close(); context.restart(); context.run_for(1s);
    }
    io::local_stream_socket q(context),r(context); if (io::connect_pair(q,r)) return 34;
    auto corrupt=combined; corrupt.back()^=1; bool sent_corrupt=false;
    context.restart(); capy::run_async(context.get_executor())(send_bytes(r,corrupt,sent_corrupt)); context.run_for(1s);
    ObservedReader observed{q}; ResponseState authenticated;
    context.restart(); capy::run_async(context.get_executor())(receive_observed(observed,psk,request_salt,authenticated)); context.run_for(1s);
    if (!sent_corrupt || !authenticated.result || !*authenticated.result) return 35;
    s::detail::FrameReader corrupted_reader(observed,std::move(**authenticated.result)); ReadState corrupted_state;
    context.restart(); capy::run_async(context.get_executor())(read_all(corrupted_reader,corrupted_state)); context.run_for(1s);
    if (!corrupted_state.done || corrupted_state.error!=s::detail::ReadError::authentication ||
        std::string(corrupted_state.data.begin(),corrupted_state.data.end())!="world" || observed.cancels!=1) return 36;
    bool closed=false; context.restart(); capy::run_async(context.get_executor())(read_closed(corrupted_reader,closed)); context.run_for(1s);
    if (!closed || observed.cancels!=1) return 37;
    q.close(); r.close(); context.restart(); context.run_for(1s);
    std::cout << "Shadowsocks 2022 Corosio request passed\n";
}
