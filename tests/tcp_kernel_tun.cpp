#include <cstdio>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import nexus.packet.fd;
import nexus.tcp.engine;
namespace p=nexus::packet; namespace t=nexus::tcp;
using namespace std::chrono_literals;
int main(int argc,char** argv) {
    if (argc!=2) return 1;
    int fd=std::atoi(argv[1]);
    p::MemoryLink link({1500,16,24000});
    p::MemoryLink tcp_link({1500,16,24000});
    auto pump=p::FdPump::create(fd,link,1500);
    auto table=t::ConnectionTable::create(4,4096);
    if (!pump || !table) return 2;
    t::MemoryEngine engine(tcp_link,*table);
    std::atomic<int> client_result{0};
    std::jthread client([&] {
        int socket=::socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);
        if (socket<0) { client_result=-1; return; }
        timeval timeout{5,0};
        (void)::setsockopt(socket,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
        (void)::setsockopt(socket,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
        sockaddr_in target{}; target.sin_family=AF_INET; target.sin_port=htons(34567);
        (void)::inet_pton(AF_INET,"10.77.0.2",&target.sin_addr);
        if (::connect(socket,reinterpret_cast<sockaddr*>(&target),sizeof(target)) ||
            ::send(socket,"hello",5,MSG_NOSIGNAL)!=5 || ::shutdown(socket,SHUT_WR)) { ::close(socket); client_result=-2; return; }
        std::array<char,6> response{}; std::size_t received=0;
        while (received<5) { auto n=::recv(socket,response.data()+received,5-received,0); if (n<=0) { ::close(socket); client_result=-3; return; } received+=n; }
        auto end=::recv(socket,response.data()+5,1,0);
        ::close(socket); client_result=(std::string_view(response.data(),5)=="world" && end==0) ? 1 : -4;
    });
    auto start=std::chrono::steady_clock::now();
    std::optional<t::ConnectionId> id;
    std::string received;
    bool sent=false, closed=false;
    while (std::chrono::steady_clock::now()-start<7s && !client_result.load()) {
        auto now=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-start).count());
        auto moved=pump->step();
        if (moved.input_error || moved.output_error) return 3;
        auto packet=link.receive(p::Side::second);
        if (!packet) return 3;
        if (*packet && !(**packet).empty() && ((**packet)[0]>>4)==4 && !tcp_link.send(p::Side::first,**packet)) return 3;
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
        if (!output || (*output && !link.send(p::Side::second,**output))) return 10;
        std::this_thread::sleep_for(1ms);
    }
    client.join();
    if (client_result!=1 || received!="hello" || !closed) { std::println(stderr,"client={} received={} closed={}",client_result.load(),received,closed); return 11; }
    std::println("Linux TCP client exchanged data and half-closed through isolated TUN");
}
