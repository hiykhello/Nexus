import std;
import crypto;
import wireguard;
import wireguard.crypto;
import wireguard.endpoint;
import wireguard.registry;
import wireguard.port_types;
import wireguard.port;
import wireguard.tun;

extern "C" std::ptrdiff_t read(int,void*,std::size_t);
extern "C" int fcntl(int,int,...);
extern "C" int* __errno_location() noexcept;
namespace {
    using namespace wireguard;
    using namespace std::chrono_literals;
    using Port=UdpPort<2,8,2048,8>;
    auto line() -> std::optional<std::string> {
        std::string result; char byte;
        while (::read(0,&byte,1)==1) { if (byte=='\n') return result; if (result.size()>=1024) return {}; result.push_back(byte); }
        return {};
    }
    auto decode(std::string_view text) -> std::optional<Key> {
        if (text.size()!=64) return {};
        auto nibble=[](char c) { return c>='0' && c<='9' ? c-'0' : c>='a' && c<='f' ? c-'a'+10 : -1; };
        Key result;
        for (std::size_t i=0;i<32;++i) { auto a=nibble(text[2*i]),b=nibble(text[2*i+1]); if (a<0 || b<0) return {}; result[i]=static_cast<std::uint8_t>((a<<4)|b); }
        return result;
    }
    auto outer(bool ipv6,unsigned position,unsigned port=0) -> EndpointAddress {
        EndpointAddress result{ipv6 ? std::uint8_t{6} : std::uint8_t{4},{},static_cast<std::uint16_t>(port)};
        if (port) {
            if (ipv6) { result.address[0]=0xfd; result.address[3]=0x42; result.address[5]=static_cast<std::uint8_t>(position+2); result.address[15]=2; }
            else { result.address[0]=192; result.address[2]=2; result.address[3]=static_cast<std::uint8_t>(position*4+2); }
        }
        return result;
    }
    auto prefixes(unsigned node) -> std::array<AllowedPrefix,2> {
        AllowedPrefix v4{4,{10,42,0,static_cast<std::uint8_t>(node)},32},v6{6,{},128};
        v6.address[0]=0xfd; v6.address[1]=0x42; v6.address[15]=static_cast<std::uint8_t>(node); return {v4,v6};
    }
}

auto main(int argc,char** argv) -> int {
    if (argc!=3) return 1;
    bool ipv6=std::string_view(argv[1])=="6"; auto mode=std::string_view(argv[2]);
    if ((!ipv6 && std::string_view(argv[1])!="4") || (mode!="plain" && mode!="cookie" && mode!="backpressure" && mode!="stop" && mode!="deadline")) return 1;
    auto secret_line=line(); if (!secret_line) return 2;
    std::array<std::optional<Key>,5> values;
    {
        std::string_view text=*secret_line;
        for (auto& value:values) {
            auto separator=text.find(' '); value=decode(text.substr(0,separator));
            if (!value) return 3;
            text=separator==std::string_view::npos ? std::string_view{} : text.substr(separator+1);
        }
    }
    ::crypto::cleanse(std::span(reinterpret_cast<std::uint8_t*>(secret_line->data()),secret_line->size())); secret_line.reset();
    PortOptions options; options.require_cookie=mode=="cookie"; options.business_packets=16; options.business_bytes=32768;
    auto port=Port::create(*values[0],options); ::crypto::cleanse(*values[0]);
    auto now=Clock::now();
    if (!port || !port->open(outer(ipv6,0),now,now+(mode=="deadline" ? 7s : 60s))) return 4;
    auto local=port->local_endpoint(); if (!local) return 5;
    std::println("{{\"port\":{}}}",local->port); std::fflush(nullptr);
    auto ports=line(); if (!ports) return 2;
    std::istringstream input(*ports); std::array<unsigned,2> numbers;
    if (!(input>>numbers[0]>>numbers[1]) || !numbers[0] || !numbers[1] || numbers[0]>65535 || numbers[1]>65535) return 2;
    std::array<PeerHandle,2> peers;
    for (unsigned position=0;position<2;++position) {
        auto configured=port->add_peer(EndpointConfig{.peer_public=*values[position+1],.allowed_ips={{4,{},0},{6,{},0}},.peer=outer(ipv6,position,numbers[position])},*values[position+3]);
        ::crypto::cleanse(*values[position+3]);
        if (!configured) return 6; peers[position]=*configured;
        for (auto const& prefix:prefixes(position+2)) if (!port->assign_route(*configured,prefix)) return 7;
    }
    auto tun=LinuxTunPort<Port>::create(*port,"nx-wg",1420); if (!tun) return 8;
    auto saved_tun=tun->native_handle(),saved_port=port->native_handle();
    std::println("{{\"device\":\"{}\",\"adapter_size\":{}}}",tun->name(),sizeof(*tun)); std::fflush(nullptr);
    auto barrier=line(); if (!barrier || *barrier!="start") return 9;
    int flags=::fcntl(0,3); if (flags<0 || ::fcntl(0,4,flags|2048)<0) return 10;
    bool expired=false; unsigned input_rejects=0; std::string commands;
    auto deadline=Clock::now()+50s;
    while (Clock::now()<deadline) {
        auto progress=tun->step(Clock::now(),std::chrono::system_clock::now());
        if (!progress) {
            auto failure=std::get_if<PortFailure>(&progress.error());
            if (mode=="deadline" && failure && failure->code==PortError::timeout) { expired=true; break; }
            std::println("device step failed"); return 11;
        }
        if (progress->device.output_error) { std::println("device output error"); return 12; }
        if (progress->device.input_error) {
            auto failure=std::get_if<PortFailure>(&*progress->device.input_error);
            if (!failure || failure->code!=PortError::no_route) { std::println("device input error"); return 13; }
            ++input_rejects;
        }
        std::array<char,64> command{}; auto count=::read(0,command.data(),command.size());
        if (count>0) { commands.append(command.data(),count); if (commands.find("stop\n")!=std::string::npos) break; }
        else if (!count) break;
        else if (*::__errno_location()!=std::to_underlying(std::errc::resource_unavailable_try_again) && *::__errno_location()!=std::to_underlying(std::errc::interrupted)) return 14;
        std::this_thread::sleep_for(1ms);
    }
    if (Clock::now()>=deadline || (mode=="deadline" && !expired)) return 15;
    if (!expired) {
        for (auto peer:peers) { auto status=port->peer_status(peer); if (!status || !status->current) return 16; }
    }
    auto before=port->status(); tun->stop();
    if (!tun->drained() || tun->native_handle()!=-1 || tun->pending() || port->native_handle()!=-1 || ::fcntl(saved_tun,3)>=0 || ::fcntl(saved_port,3)>=0) return 17;
    if (!before.metrics.received || !before.metrics.delivered) return 18;
    std::println("{{\"stopped\":true,\"deadline\":{},\"received\":{},\"delivered\":{},\"input_no_route\":{},\"drained\":true}}",expired,before.metrics.received,before.metrics.delivered,input_rejects);
}
