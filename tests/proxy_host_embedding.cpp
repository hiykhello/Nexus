#include <cerrno>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

import std;
import config;
import relay;
import relay.host;
import cli.tun_host;

namespace {
    namespace relay = ::relay;
    namespace packet = ::packet;

    template<class Condition>
    void require(Condition const& condition,std::string_view message) {
        if (!condition) throw std::runtime_error(std::string(message));
    }

    struct Fd {
        int value;
        explicit Fd(int fd) noexcept : value(fd) {}
        Fd(Fd const&)=delete;
        auto operator=(Fd const&) -> Fd& = delete;
        ~Fd() {if (value>=0) ::close(value);}
    };

    void tcp_rollback() {
        Fd blocker(::socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0));
        require(blocker.value>=0,"cannot create the binding conflict");
        sockaddr_in address{.sin_family=AF_INET,.sin_addr={htonl(INADDR_LOOPBACK)}};
        require(::bind(blocker.value,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0 &&
                ::listen(blocker.value,1)==0,"cannot bind and listen on the occupied port");
        socklen_t size=sizeof(address);
        require(::getsockname(blocker.value,reinterpret_cast<sockaddr*>(&address),&size)==0,"cannot query occupied port");
        auto first=relay::Server::create().value();
        auto second=relay::Server::create().value();
        relay::HostTcpListener available;
        relay::HostTcpListener occupied{.port=ntohs(address.sin_port)};
        relay::Host failed;
        require(failed.add_tcp(*first,available) && failed.add_tcp(*second,occupied),"cannot register TCP services");
        require(!failed.start() && available.port && !failed.healthy(),"failure did not roll back the started listener");
        failed.stop();
        require(!failed.add_tcp(*second,occupied),"a stopped host still accepts registrations");

        auto retry=relay::Server::create().value();
        relay::Host running;
        require(running.add_tcp(*retry,available) && running.start() && running.healthy(),"rolled-back port stayed bound");
        Fd client(::socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0));
        require(client.value>=0,"cannot create client socket");
        address.sin_port=htons(available.port);
        require(::connect(client.value,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0,"cannot connect to embedded listener");
        std::array<unsigned char,3> greeting{5,1,0};
        require(::send(client.value,greeting.data(),greeting.size(),MSG_NOSIGNAL)==3,"cannot write SOCKS5 greeting");
        std::array<unsigned char,2> answer{};
        std::size_t received=0;
        auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(4);
        while (received<answer.size() && std::chrono::steady_clock::now()<deadline) {
            running.poll(std::chrono::milliseconds(5));
            auto count=::recv(client.value,answer.data()+received,answer.size()-received,MSG_DONTWAIT);
            if (count>0) received+=static_cast<std::size_t>(count);
            else require(count<0 && (errno==EAGAIN || errno==EWOULDBLOCK),"embedded SOCKS5 closed prematurely");
        }
        require(received==answer.size() && answer==std::array<unsigned char,2>{5,0},"embedded server did not negotiate SOCKS5");
        running.stop();
        running.stop();
        require(!running.healthy(),"stopped host still reports healthy");
    }

    void tun_ownership() {
        using packet::TunFdOwnership;
        using cli::tun_enabled::TunHost;
        Fd invalid(::open("/dev/null",O_RDWR|O_NONBLOCK|O_CLOEXEC));
        require(invalid.value>=0 && !packet::LinuxTun::attach(invalid.value,TunFdOwnership::adopt) &&
            ::fcntl(invalid.value,F_GETFD)>=0,"invalid descriptor lost caller ownership");
        auto external=packet::LinuxTun::create("nx-embed").value();
        auto original=external.native_handle();
        auto options=config::TunInbound{.interface_name=std::string(external.name()),.tcp_flows=4};
        auto route=relay::Server::create().value();
        for (unsigned cycle=0;cycle<2;++cycle) {
            auto borrowed=packet::LinuxTun::attach(original,TunFdOwnership::borrow).value();
            auto duplicate=borrowed.native_handle();
            require(duplicate!=original && !borrowed.claim_network(),"borrowed TUN descriptor claimed the link");
            TunHost tun(*route,options);
            relay::Host host;
            require(host.add({
                [&]() -> std::expected<void,std::string> {
                    auto started=tun.start(std::move(borrowed));
                    if (!started) return std::unexpected(std::move(started.error()));
                    require(*started==external.name(),"incorrect external interface name");
                    return {};
                },
                [&]() noexcept {tun.stop();},
                [&] {return tun.healthy();}
            }),"cannot register an external TUN");
            require(host.start() && host.healthy(),"cannot start borrowed TUN");
            require(::fcntl(duplicate,F_GETFD)>=0,"borrowed duplicate closed during service");
            host.stop();
            host.stop();
            require(::fcntl(duplicate,F_GETFD)<0 && ::fcntl(original,F_GETFD)>=0,"borrowed TUN was not released correctly");
        }

        int consumed=::fcntl(original,F_DUPFD_CLOEXEC,0);
        require(consumed>=0,"cannot create an adoptable descriptor");
        auto adopted=packet::LinuxTun::attach(consumed,TunFdOwnership::adopt).value();
        TunHost tun(*route,options);
        require(tun.start(std::move(adopted)),"cannot start adopted TUN");
        tun.stop();
        require(::fcntl(consumed,F_GETFD)<0,"adopted descriptor remains open");
        require(::dup2(invalid.value,consumed)==consumed,"cannot reuse adopted descriptor number");
        tun.stop();
        require(::fcntl(consumed,F_GETFD)>=0,"repeated stop closed a reused descriptor");
        ::close(consumed);

        auto bad=options;
        bad.interface_name="missing";
        auto extra=packet::LinuxTun::attach(original,TunFdOwnership::borrow).value();
        auto duplicate=extra.native_handle();
        TunHost rejected(*route,std::move(bad));
        require(!rejected.start(std::move(extra)) && ::fcntl(duplicate,F_GETFD)<0 &&
            ::fcntl(original,F_GETFD)>=0,"failed startup leaked or closed a caller descriptor");
    }
}

int main() {
    try {
        tcp_rollback();
        tun_ownership();
        std::cout << "Embedded TCP negotiated SOCKS5 and rolled back a port conflict. External TUN borrowed, adopted and reused descriptors safely.\n";
        return 0;
    } catch (std::exception const& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
