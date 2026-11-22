#include <cstdio>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import packet.fd;
import tcp.engine;
namespace p = ::packet; namespace t=tcp;
using namespace std::chrono_literals;
template<bool ipv6>
int run(int fd,std::string_view mode) {
    bool loss=mode=="loss";
    bool fin_loss=mode=="fin-loss";
    if (!loss && !fin_loss && mode!="normal") return 1;
    p::MemoryLink link({1500,16,24000});
    p::MemoryLink tcp_link({1500,16,24000});
    auto pump=p::FdPump::create(fd,link,1500);
    using Table=std::conditional_t<ipv6,t::ConnectionTable6,t::ConnectionTable>;
    using Engine=std::conditional_t<ipv6,t::MemoryEngine6,t::MemoryEngine>;
    auto table=Table::create(4,4096);
    if (!pump || !table) return 2;
    Engine engine(tcp_link,*table);
    auto parse=[](p::Bytes const& bytes) {
        if constexpr (ipv6) return p::parse_tcp6(bytes);
        else return p::parse_tcp4(bytes);
    };
    std::atomic<int> client_result{0};
    std::jthread client([&] {
        int socket=::socket(ipv6 ? AF_INET6 : AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);
        if (socket<0) { client_result=-1; return; }
        timeval timeout{10,0};
        (void)::setsockopt(socket,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
        (void)::setsockopt(socket,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
        sockaddr_in target4{}; target4.sin_family=AF_INET; target4.sin_port=htons(34567);
        sockaddr_in6 target6{}; target6.sin6_family=AF_INET6; target6.sin6_port=htons(34567);
        (void)::inet_pton(AF_INET,"10.77.0.2",&target4.sin_addr);
        (void)::inet_pton(AF_INET6,"fd77::2",&target6.sin6_addr);
        auto* target=ipv6 ? reinterpret_cast<sockaddr*>(&target6) : reinterpret_cast<sockaddr*>(&target4);
        auto target_size=ipv6 ? sizeof(target6) : sizeof(target4);
        if (::connect(socket,target,target_size) ||
            ::send(socket,"hello",5,MSG_NOSIGNAL)!=5 || ::shutdown(socket,SHUT_WR)) { ::close(socket); client_result=-2; return; }
        std::array<char,6> response{}; std::size_t received=0;
        while (received<5) { auto n=::recv(socket,response.data()+received,5-received,0); if (n<=0) { ::close(socket); client_result=-3; return; } received+=n; }
        auto end=::recv(socket,response.data()+5,1,0);
        ::close(socket); client_result=(std::string_view(response.data(),5)=="world" && end==0) ? 1 : -4;
    });
    auto start=std::chrono::steady_clock::now();
    std::optional<t::ConnectionId> id;
    std::string received;
    bool sent=false, closed=false, dropped_synack=false, dropped_data=false, dropped_client_data=false;
    bool dropped_client_fin=false, dropped_server_fin=false;
    std::optional<std::uint32_t> client_fin_sequence, server_fin_sequence;
    bool client_fin_mismatch=false, server_fin_mismatch=false;
    unsigned synacks=0, data_packets=0, client_data_packets=0, client_fins=0, server_fins=0;
    while (std::chrono::steady_clock::now()-start<15s && !client_result.load()) {
        auto now=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-start).count());
        auto moved=pump->step();
        if (moved.input_error || moved.output_error) return 3;
        auto packet=link.receive(p::Side::second);
        if (!packet) return 3;
        if (*packet && !(**packet).empty() && ((**packet)[0]>>4)==(ipv6 ? 6 : 4) &&
            (!ipv6 || ((**packet).size()>=40 && (**packet)[6]==6))) {
            auto decoded=parse(**packet);
            if (!decoded) return 3;
            bool drop=false;
            if (!decoded->payload.empty()) {
                ++client_data_packets;
                if (loss && !dropped_client_data) { dropped_client_data=true; drop=true; }
            }
            if (decoded->flags & 1) {
                ++client_fins;
                auto sequence=decoded->sequence+static_cast<std::uint32_t>(decoded->payload.size());
                if (client_fin_sequence && *client_fin_sequence!=sequence) client_fin_mismatch=true;
                else client_fin_sequence=sequence;
                if (fin_loss && !dropped_client_fin) { dropped_client_fin=true; drop=true; }
            }
            if (!drop && !tcp_link.send(p::Side::first,**packet)) return 3;
        }
        auto input=engine.step(now,0x12345678);
        if (!input) { std::println(stderr,"engine error"); return 4; }
        if (input->rejected) { auto error=*input->rejected; std::println(stderr,"dispatch error={} packet={} table={}",static_cast<int>(error.error),error.packet_error ? static_cast<int>(*error.packet_error) : -1,error.table_error ? static_cast<int>(*error.table_error) : -1); return 4; }
        if (input->output_error) return 4;
        if (input->opened) id=input->id;
        if (id) {
            auto* flow=table->get(*id);
            if (!flow) return 5;
            if (flow->state()==t::ConnectionState::established || flow->state()==t::ConnectionState::peer_closed) {
                std::array<std::uint8_t,32> data{};
                auto read=engine.read(*id,data,now);
                if (!read || read->connection_error || read->notification.output_error) return 6;
                received.append(reinterpret_cast<char const*>(data.data()),read->bytes);
                if (received.size()>5 || !std::string_view("hello").starts_with(received)) return 7;
                if (received=="hello" && !sent) {
                    constexpr std::array<std::uint8_t,5> response{'w','o','r','l','d'};
                    if (!flow->enqueue(response)) return 8;
                    sent=true;
                }
                if (read->eof && sent && !closed) { if (!flow->close_send()) return 9; closed=true; }
            }
        }
        auto service=engine.service(now);
        if (!service || service->table_error || service->output.connection_error || service->output.output_error) return 10;
        auto output=tcp_link.receive(p::Side::first);
        if (!output) return 10;
        if (*output) {
            auto packet=parse(**output);
            if (!packet) return 10;
            bool drop=false;
            if ((packet->flags & 0x12)==0x12) { ++synacks; if (loss && !dropped_synack) { dropped_synack=true; drop=true; } }
            if (!packet->payload.empty()) { ++data_packets; if (loss && !dropped_data) { dropped_data=true; drop=true; } }
            if (packet->flags & 1) {
                ++server_fins;
                auto sequence=packet->sequence+static_cast<std::uint32_t>(packet->payload.size());
                if (server_fin_sequence && *server_fin_sequence!=sequence) server_fin_mismatch=true;
                else server_fin_sequence=sequence;
                if (fin_loss && !dropped_server_fin) { dropped_server_fin=true; drop=true; }
            }
            if (!drop && !link.send(p::Side::second,**output)) return 10;
        }
        std::this_thread::sleep_for(1ms);
    }
    client.join();
    if (client_result!=1 || received!="hello" || !closed ||
        (loss && (!dropped_synack || !dropped_data || !dropped_client_data || synacks<2 || data_packets<2 || client_data_packets<2)) ||
        (fin_loss && (!dropped_client_fin || !dropped_server_fin || client_fins<2 || server_fins<2 ||
                      client_fin_mismatch || server_fin_mismatch))) {
        std::println(stderr,"client={} received={} closed={} synacks={} server_data={} client_data={} client_fin={} server_fin={}",client_result.load(),received,closed,synacks,data_packets,client_data_packets,client_fins,server_fins); return 11;
    }
    std::println("Linux IPv{} TCP client exchanged data and half-closed through isolated TUN ({})",ipv6 ? 6 : 4,mode);
    return 0;
}
int main(int argc,char** argv) {
    if (argc!=4) return 1;
    int fd=std::atoi(argv[1]);
    if (std::string_view(argv[3])=="4") return run<false>(fd,argv[2]);
    if (std::string_view(argv[3])=="6") return run<true>(fd,argv[2]);
    return 1;
}
