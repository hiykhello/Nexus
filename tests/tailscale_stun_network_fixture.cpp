import std;
import tailscale.stun;
import tailscale.stun_queries;
import net.udp_socket;
import platform.linux_random;
namespace s=tailscale::stun;
using namespace std::chrono_literals;
auto number(std::string_view text) -> std::optional<unsigned> {
    unsigned value=0; auto parsed=std::from_chars(text.data(),text.data()+text.size(),value);
    if (parsed.ec!=std::errc{} || parsed.ptr!=text.data()+text.size()) return {}; return value;
}
auto main(int argc,char** argv) -> int {
    if (argc!=3) return 64;
    auto family=number(argv[1]),port=number(argv[2]);
    if (!family || (*family!=4 && *family!=6) || !port || !*port || *port>65535) return 64;
    s::Endpoint server{static_cast<std::uint8_t>(*family),{},static_cast<std::uint16_t>(*port)};
    if (*family==4) { server.address[0]=127; server.address[3]=1; }
    else server.address[15]=1;
    net::UdpSocket socket;
    s::Queries<4> queries;
    std::array<std::uint8_t,2048> buffer{};
    for (unsigned i=0;i<4;++i) {
        s::Transaction transaction{};
        if (!::platform::secure_random(std::as_writable_bytes(std::span(transaction)))) return 1;
        auto now=s::Clock::now(),deadline=now+2s;
        auto ticket=queries.reserve(transaction,server,now,deadline); if (!ticket) return 2;
        auto request=s::encode_request(transaction);
        if (!socket.send(server,request)) { queries.cancel(*ticket); return 3; }
        bool completed=false;
        while (s::Clock::now()<deadline) {
            auto packet=socket.receive(buffer);
            if (!packet) return 4;
            if (!*packet) { std::this_thread::sleep_for(1ms); continue; }
            if (!(**packet).valid) return 5;
            auto accepted=queries.accept(std::span(buffer).first((**packet).size),(**packet).source,s::Clock::now());
            if (!accepted) return 6;
            auto const& mapped=accepted->mapped;
            if (mapped.family!=server.family || mapped.address!=server.address || !mapped.port || queries.size()) return 7;
            completed=true; break;
        }
        if (!completed) return 8;
    }
    queries.stop(); socket.close();
    std::println("stun-network-passed");
}

