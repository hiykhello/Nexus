import std;
import grpc.headers;
import grpc.session;
import grpc.stream;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace g=grpc;
namespace capy=nex::capy;
namespace io=nex::corosio;
using namespace std::chrono_literals;
// A valid nghttp2 peer supplies complete wire records. The lower driver
// controls only completion order and transport failures, including a read
// failure that also poisons a still-pending final write, as TLS may do.
struct Lower {
    std::unique_ptr<g::Session> peer;
    g::Session* local=nullptr;
    capy::async_event changed;
    std::vector<std::uint8_t> input;
    std::size_t offset=0,late_reads=0;
    int mode;
    bool response=false,canceled=false,transport_closed=false,late_pending=false,poisoned=false,last_started=false,last_done=false,last_ok=false;
    Lower(std::unique_ptr<g::Session> server,int test) : peer(std::move(server)),mode(test) {}
    auto cancel() noexcept -> void { canceled=true; changed.set(); }
    auto collect() -> std::vector<std::uint8_t> {
        std::vector<std::uint8_t> wire; std::array<std::uint8_t,16384> buffer{};
        for (;;) {
            auto size=peer->output(buffer); if (!size) throw std::runtime_error("peer output failed");
            if (!*size) return wire;
            wire.insert(wire.end(),buffer.begin(),buffer.begin()+*size);
        }
    }
    auto alter(std::vector<std::uint8_t>& wire) -> void {
        if (mode<4 || mode==7) return;
        for (std::size_t begin=0;wire.size()-begin>=9;) {
            auto size=(std::size_t(wire[begin])<<16)|(std::size_t(wire[begin+1])<<8)|wire[begin+2];
            if (size>wire.size()-begin-9) throw std::runtime_error("partial peer frame");
            if (wire[begin+3]==0 && size) {
                if (mode==4) wire[begin+4]|=1;
                if (mode==4 || mode==5 || mode==8) wire.resize(begin+9+size);
                if (mode==6) ++wire[begin+9+4];
                return;
            }
            begin+=9+size;
        }
        throw std::runtime_error("missing peer DATA");
    }
    auto send(std::span<std::uint8_t const> bytes,g::Deadline) -> capy::task<bool> {
        if (canceled) co_return false;
        auto accepted=peer->receive(bytes); if (!accepted || *accepted!=bytes.size()) co_return false;
        bool created=false;
        if (peer->ready() && !response) {
            auto queued=peer->queue(std::array<std::uint8_t,3>{'a','b','c'});
            if (!queued || !*queued || !peer->close_output()) co_return false;
            response=created=true;
        }
        auto wire=collect(); if (created) alter(wire);
        input.insert(input.end(),wire.begin(),wire.end()); changed.set();
        if (local->local_ended()) {
            last_started=true; changed.set();
            if (mode==1 || mode==2 || mode==3) {
                auto [error]=co_await io::delay(40ms);
                if (error) { last_done=true; co_return false; }
            }
            last_done=true; last_ok=mode!=2 && !poisoned && !canceled; co_return last_ok;
        }
        co_return true;
    }
    auto close_output(g::Deadline) -> capy::task<bool> {transport_closed=true;changed.set();co_return !poisoned&&!canceled;}
    auto read(std::span<std::uint8_t> bytes,g::Deadline deadline) -> capy::task<std::expected<std::size_t,std::error_code>> {
        for (;;) {
            if (canceled) co_return std::unexpected(std::make_error_code(std::errc::operation_canceled));
            if(transport_closed)co_return 0;
            bool immediate=mode==1 || mode==3 || mode==7 || mode==8;
            if (offset<input.size() && (immediate || local->local_ended())) {
                auto size=std::min(bytes.size(),input.size()-offset);
                std::copy_n(input.begin()+offset,size,bytes.begin()); offset+=size; co_return size;
            }
            if (response && offset==input.size()) {
                if((mode==7||mode==8)&&!local->local_ended()){late_pending=true;++late_reads;co_return 0;}
                if (immediate && !local->local_ended()) late_pending=true;
                if (local->local_ended()) {
                    ++late_reads; poisoned=mode==3;
                    co_return std::unexpected(std::make_error_code(std::errc::connection_reset));
                }
            }
            changed.clear(); auto operation=changed.wait();
            auto [error]=deadline ? co_await io::timeout(std::move(operation),*deadline) : co_await std::move(operation);
            if (error) co_return std::unexpected(error);
        }
    }
};
using Channel=g::Channel<Lower>;
struct Result {
    bool done=false,success=false,close_done=false,closed=false,eof=false;
    std::vector<std::uint8_t> bytes;
    std::optional<g::Failure> failure;
};
auto close(Channel& channel,Result& result,int mode) -> capy::task<capy::results<>> {
    if (mode==1 || mode==3 || mode==7 || mode==8) { auto [error]=co_await io::delay(20ms); if (error) co_return capy::results<>{error}; }
    result.closed=co_await channel.close_output(g::Clock::now()+1s); result.close_done=true;
    co_return capy::results<>{};
}
auto read(Channel& channel,Result& result) -> capy::task<capy::results<>> {
    std::array<std::uint8_t,16> buffer{};
    for (;;) {
        auto size=co_await channel.read(buffer,g::Clock::now()+1s);
        if (!size) co_return capy::results<>{};
        if (!*size) { result.eof=true; co_return capy::results<>{}; }
        result.bytes.insert(result.bytes.end(),buffer.begin(),buffer.begin()+*size);
    }
}
auto run(Channel& channel,Result& result,int mode) -> capy::task<> {
    try {
        auto [error,protocol,closing,reading]=co_await capy::when_all(channel.run(),close(channel,result,mode),read(channel,result));
        (void)protocol; (void)closing; (void)reading;
        result.success=!error && channel.finished() && !channel.failure();
    } catch (...) { channel.cancel(); }
    result.failure=channel.failure(); result.done=true;
}
auto exercise(bool uring,int mode) -> bool {
    auto context=io::make_io_context(uring);
    auto profile=g::RequestProfile::create("nexus.Service","cover.example",false); if (!profile) return false;
    auto client=g::Session::create(g::Role::client,*profile),server=g::Session::create(g::Role::server,*profile);
    if (!client || !server) return false;
    Lower lower(std::move(*server),mode); lower.local=client->get();
    Channel channel(lower,std::move(*client),g::Clock::now()+1s); Result result;
    capy::run_async(context.get_executor())(run(channel,result,mode)); context.run_for(1500ms);
    if (!result.done) { channel.cancel(); context.restart(); context.run_for(500ms); }
    bool success=result.done && context.stopped() && channel.drained();
    if (mode==0 || mode==1 || mode==7) {
        success=success && result.success && result.close_done && result.closed && result.eof && lower.last_done && lower.last_ok &&
            result.bytes==std::vector<std::uint8_t>{'a','b','c'} && (mode==0 ? lower.late_reads==0 : lower.late_pending && lower.late_reads==1);
    } else {
        auto expected=mode==4 ? g::Error::headers : (mode==6||mode==8) ? g::Error::truncated : g::Error::transport;
        success=success && !result.success && result.failure && result.failure->error==expected;
        if (mode==2 || mode==3) success=success && lower.last_started && lower.last_done && !lower.last_ok && result.close_done && !result.closed;
    }
    if (!success) std::cerr << "gRPC terminal regression failed: backend=" << uring << " mode=" << mode << " done=" << result.done
        << " success=" << result.success << " close=" << result.close_done << ':' << result.closed << " eof=" << result.eof
        << " last=" << lower.last_started << ':' << lower.last_done << ':' << lower.last_ok << " late-read=" << lower.late_pending << ':' << lower.late_reads
        << " error=" << (result.failure ? int(result.failure->error) : -1) << '\n';
    return success;
}
auto main() -> int {
    for (bool uring:{false,true}) {
        if (uring && !io::has_uring) continue;
        for (int mode=0;mode<9;++mode) if (!exercise(uring,mode)) return 1;
    }
    std::println("gRPC terminal read cessation, early transport EOF, pending final write/error, strict trailers and truncated messages passed");
}
