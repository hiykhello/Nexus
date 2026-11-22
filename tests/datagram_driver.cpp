import std;
import net.datagram_driver;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

namespace capy=nex::capy;
namespace io=nex::corosio;
using Clock=std::chrono::steady_clock;
using namespace std::chrono_literals;
namespace {
    struct Active { bool& flag; explicit Active(bool& value):flag(value) { flag=true; } ~Active() { flag=false; } };
    struct Socket {
        io::io_context& context_;
        capy::async_event readable,writable;
        bool closed=false,read_active=false,send_active=false,hold=true,queued=false;
        unsigned receives=0,sends=0,close_calls=0;
        std::size_t incoming_size=3;
        std::error_code send_error,receive_error;
        bool short_send=false,corrupt=false;
        std::span<std::uint8_t const> pending;
        explicit Socket(io::io_context& context):context_(context) {}
        auto context() noexcept -> io::io_context& { return context_; }
        auto close() noexcept -> void { ++close_calls; closed=true; readable.set(); writable.set(); }
        auto recv_from(capy::mutable_buffer bytes,io::endpoint& source) -> capy::task<capy::results<std::size_t>> {
            Active guard(read_active); ++receives;
            while (!closed && !queued) { auto [error]=co_await readable.wait(); if (error) co_return capy::results<std::size_t>{error,0}; }
            if (closed) co_return capy::results<std::size_t>{std::make_error_code(std::errc::operation_canceled),0};
            queued=false; readable.clear(); source=io::endpoint(io::ipv4_address::loopback(),4321);
            std::memset(bytes.data(),7,std::min(incoming_size,bytes.size()));
            co_return capy::results<std::size_t>{receive_error,incoming_size};
        }
        auto send_to(capy::const_buffer bytes,io::endpoint) -> capy::task<capy::results<std::size_t>> {
            Active guard(send_active); ++sends; pending={static_cast<std::uint8_t const*>(bytes.data()),bytes.size()};
            if (hold) { auto [error]=co_await writable.wait(); if (error) co_return capy::results<std::size_t>{error,0}; }
            if (closed) co_return capy::results<std::size_t>{std::make_error_code(std::errc::operation_canceled),0};
            for (std::size_t i=0;i<pending.size();++i) corrupt|=pending[i]!=static_cast<std::uint8_t>(i*73);
            co_return capy::results<std::size_t>{send_error,short_send ? bytes.size()-1 : bytes.size()};
        }
        auto input(std::size_t size=3) noexcept -> void { incoming_size=size; queued=true; readable.set(); }
    };
    struct Protocol {
        enum class Failure { receive=71,output=72,transmitted=73,expiry=74 };
        using Driver=net::DatagramDriver<Protocol,Socket,64,64>;
        Socket& socket;
        Driver* driver=nullptr;
        bool alive=true,business=true,broken=false,stalled=false,no_output=false;
        unsigned action=0,outputs=0,transmissions=0,mtu_rejections=0,received=0,expiries=0,requested=0,stops=0,drains=0;
        Clock::time_point expiry=Clock::now()+8ms;
        explicit Protocol(Socket& value):socket(value) {}
        auto request_stop() noexcept -> void { ++requested; business=false; broken|=!alive; }
        auto stop() noexcept -> void { ++stops; broken|=socket.read_active || socket.send_active; alive=false; }
        auto drain() noexcept -> void { ++drains; broken|=alive || socket.read_active || socket.send_active; }
        auto next_expiry() const noexcept -> net::DatagramDeadline { return expiry; }
        auto receive(io::endpoint const&,std::span<std::uint8_t const> bytes,Clock::time_point) -> std::expected<void,Failure>;
        auto output(std::span<std::uint8_t> bytes,Clock::time_point) -> std::expected<std::optional<net::DatagramOutput>,Failure>;
        auto transmitted(std::uint64_t token,Clock::time_point) -> std::expected<void,Failure>;
        auto mtu_rejected(std::uint64_t token,Clock::time_point now) -> std::expected<void,Failure> {++mtu_rejections;return transmitted(token,now);}
        auto expire(Clock::time_point time) -> std::expected<void,Failure>;
    };
    auto Protocol::receive(io::endpoint const&,std::span<std::uint8_t const> bytes,Clock::time_point) -> std::expected<void,Failure> {
        broken|=!alive || !business; ++received;
        if (action==2) driver->finish();
        if (action==8) return std::unexpected(Failure::receive);
        if (action==9) throw std::bad_alloc();
        if (action==10) throw std::runtime_error("receive policy exception");
        for (auto byte:bytes) if (byte!=7) return std::unexpected(Failure::receive);
        return {};
    }
    auto Protocol::output(std::span<std::uint8_t> bytes,Clock::time_point) -> std::expected<std::optional<net::DatagramOutput>,Failure> {
        broken|=!alive || !business || socket.send_active;
        if (no_output || outputs) return std::optional<net::DatagramOutput>{};
        ++outputs; for (std::size_t i=0;i<bytes.size();++i) bytes[i]=static_cast<std::uint8_t>(i*73);
        if (action==3) driver->finish();
        if (action==11) return std::unexpected(Failure::output);
        return net::DatagramOutput{io::endpoint(io::ipv4_address::loopback(),1234),action==12 ? bytes.size()+1 : bytes.size(),91,action==19 || action==21,action==22 || action==23};
    }
    auto Protocol::transmitted(std::uint64_t token,Clock::time_point) -> std::expected<void,Failure> {
        ++transmissions; broken|=!alive || !business || socket.send_active || token!=91;
        if (action==4) driver->finish();
        if (action==13) return std::unexpected(Failure::transmitted);
        return {};
    }
    auto Protocol::expire(Clock::time_point time) -> std::expected<void,Failure> {
        ++expiries; broken|=!alive || !business;
        if (!stalled) expiry=time+8ms;
        if (action==5) driver->finish();
        if (action==14) return std::unexpected(Failure::expiry);
        return {};
    }
    struct Trial {
        io::io_context context;
        Socket socket{context};
        Protocol protocol{socket};
        Clock::time_point began=Clock::now(),ended{};
        Protocol::Driver driver;
        bool done=false,controller_ok=true,task_error=false;
        unsigned mode;
        Trial(bool uring,unsigned kind):context(io::make_io_context(uring)),driver(socket,protocol,kind==1 ? net::DatagramDeadline{began+70ms} : net::DatagramDeadline{began+500ms}),mode(kind) { protocol.driver=&driver; }
    };
    auto control(Trial& trial) -> capy::task<capy::results<>> {
        auto& socket=trial.socket; auto& protocol=trial.protocol;
        if (trial.mode==0) {
            auto [error]=co_await io::delay(48ms); if (error) co_return capy::results<>{error};
            trial.controller_ok=socket.send_active && protocol.outputs==1 && !protocol.transmissions && protocol.expiries>=4 && protocol.alive;
            for (std::size_t i=0;i<socket.pending.size();++i) trial.controller_ok&=socket.pending[i]==static_cast<std::uint8_t>(i*73);
            socket.writable.set();
            for (unsigned i=0;i<100 && !protocol.transmissions;++i) { auto [error]=co_await io::delay(1ms); if (error) co_return capy::results<>{error}; }
            trial.controller_ok&=protocol.transmissions==1;
            trial.driver.finish();
        } else if (trial.mode==1) {
            auto [error]=co_await io::delay(50ms); if (error) co_return capy::results<>{error};
            socket.input(); // late valid input cannot restart the 70ms budget
        } else if (trial.mode==2 || (trial.mode>=8 && trial.mode<=10) || trial.mode==17) {
            auto [error]=co_await io::delay(12ms); if (error) co_return capy::results<>{error};
            socket.input(trial.mode==17 ? 0 : 3);
            if (trial.mode==17) { auto [error]=co_await io::delay(2ms); (void)error; trial.driver.finish(); }
        } else if (trial.mode==6 || trial.mode==7 || trial.mode==15 || trial.mode==19 || trial.mode==20 || trial.mode==21 || trial.mode==22 || trial.mode==23) {
            auto [error]=co_await io::delay(12ms); if (error) co_return capy::results<>{error};
            socket.writable.set();
            if (trial.mode==19 || trial.mode==22) {
                for (unsigned i=0;i<100 && !protocol.transmissions;++i) {auto [error]=co_await io::delay(1ms);if(error)co_return capy::results<>{error};}
                trial.controller_ok=protocol.transmissions==1 && trial.driver.running();trial.driver.finish();
            }
        } else if (trial.mode==18) {
            auto [error]=co_await io::delay(12ms); if (error) co_return capy::results<>{error};
            trial.driver.cancel(); trial.driver.cancel();
        }
        co_return capy::results<>{};
    }
    auto execute(Trial& trial) -> capy::task<> {
        auto [error,run,controller]=co_await capy::when_all(trial.driver.run(),control(trial));
        (void)run; (void)controller; trial.task_error=bool(error); trial.ended=Clock::now(); trial.done=true;
    }
    auto fault(Trial const& trial,net::DatagramError code) -> bool {
        return trial.driver.failure() && std::holds_alternative<net::DatagramFailure>(*trial.driver.failure()) && std::get<net::DatagramFailure>(*trial.driver.failure()).code==code;
    }
    auto protocol_fault(Trial const& trial,Protocol::Failure code) -> bool {
        return trial.driver.failure() && std::holds_alternative<Protocol::Failure>(*trial.driver.failure()) && std::get<Protocol::Failure>(*trial.driver.failure())==code;
    }
    auto scenario(bool uring,unsigned mode) -> int {
        Trial trial(uring,mode); auto& socket=trial.socket; auto& protocol=trial.protocol;
        protocol.action=mode;
        if (mode==4 || mode==13) socket.hold=false;
        if (mode==6) socket.send_error=std::make_error_code(std::errc::permission_denied);
        if (mode==19 || mode==20 || mode==22) socket.send_error=std::make_error_code(std::errc::message_size);
        if (mode==21 || mode==23) socket.send_error=std::make_error_code(std::errc::permission_denied);
        if (mode==7) socket.short_send=true;
        if (mode==15) protocol.stalled=true;
        if (mode==16) { protocol.no_output=true; protocol.stalled=true; }
        capy::run_async(trial.context.get_executor())(execute(trial)); trial.context.run_for(700ms);
        if (!trial.done || !trial.controller_ok || !trial.driver.drained() || protocol.broken || socket.corrupt || protocol.requested!=1 || protocol.stops!=1 || protocol.drains!=1 || protocol.alive || socket.read_active || socket.send_active) return 1;
        bool success=false;
        switch (mode) {
        case 0: success=!trial.driver.failure() && protocol.transmissions==1 && protocol.expiries>=4 && !trial.task_error; break;
        case 1: { auto elapsed=trial.ended-trial.began; success=fault(trial,net::DatagramError::deadline) && protocol.received==1 && !protocol.transmissions && elapsed>=65ms && elapsed<130ms; break; }
        case 2: case 3: case 4: case 5: success=!trial.driver.failure() && !trial.task_error; break;
        case 6: success=fault(trial,net::DatagramError::send) && !protocol.transmissions; break;
        case 7: success=fault(trial,net::DatagramError::short_send) && !protocol.transmissions; break;
        case 8: success=protocol_fault(trial,Protocol::Failure::receive); break;
        case 9: success=fault(trial,net::DatagramError::allocation); break;
        case 10: success=fault(trial,net::DatagramError::callback); break;
        case 11: success=protocol_fault(trial,Protocol::Failure::output); break;
        case 12: success=fault(trial,net::DatagramError::invalid_output) && socket.sends==0; break;
        case 13: success=protocol_fault(trial,Protocol::Failure::transmitted) && protocol.transmissions==1; break;
        case 14: success=protocol_fault(trial,Protocol::Failure::expiry); break;
        case 15: case 16: success=fault(trial,net::DatagramError::expiry_stalled); break;
        case 17: success=!trial.driver.failure() && protocol.received==1 && !trial.task_error; break;
        case 18: success=fault(trial,net::DatagramError::canceled); break;
        case 19: success=!trial.driver.failure() && protocol.transmissions==1 && !trial.task_error; break;
        case 20: case 21: success=fault(trial,net::DatagramError::send) && !protocol.transmissions; break;
        case 22: success=!trial.driver.failure() && protocol.transmissions==1 && protocol.mtu_rejections==1 && !trial.task_error; break;
        case 23: success=fault(trial,net::DatagramError::send) && !protocol.transmissions && !protocol.mtu_rejections; break;
        }
        if (!success) { std::println("driver details mode={} failure={} task={} expiry={} received={} output={} tx={}",mode,trial.driver.failure() ? static_cast<int>(trial.driver.failure()->index()) : -1,trial.task_error,protocol.expiries,protocol.received,protocol.outputs,protocol.transmissions); return 2; }
        return 0;
    }
}
auto main() -> int {
    for (bool uring:{false,true}) {
        if (uring && !io::has_uring) continue;
        for (unsigned mode=0;mode<24;++mode) if (auto error=scenario(uring,mode)) { std::println("datagram driver backend={} scenario={} failed {}",uring,mode,error); return 1; }
    }
    std::println("datagram driver 48 deterministic cases passed: pending send, deadlines, stop, PMTU probe and ordinary packet rejection, I/O faults and drain; direct owner={} bytes",sizeof(Protocol::Driver));
}
