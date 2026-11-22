import std;
import net.tcp_connect;
import nexus.thirdparty.corosio;

namespace io=nex::corosio;
namespace net=net;
namespace platform = ::platform;

namespace {
    template<int Name,int Level=platform::linux_socket_abi::tcp_level>
    struct ProbeOption {
        int value=0;
        template<class Family> auto level(Family) const noexcept -> int { return Level; }
        template<class Family> auto name(Family) const noexcept -> int { return Name; }
        template<class Family> auto data(Family) noexcept -> void* { return &value; }
        template<class Family> auto size(Family) const noexcept -> std::size_t { return sizeof(value); }
        template<class Family> auto resize(Family,std::size_t) noexcept -> void {}
    };
    template<int Name>
    auto read(io::tcp_socket& socket,int expected) -> bool {
        auto [error,option]=socket.get_option<ProbeOption<Name>>();
        return !error && option.value==expected;
    }
    auto verify(io::tcp_socket& socket,platform::TcpSocketOptions const& options) -> bool {
        auto [error,enabled]=socket.get_option<io::socket_option::keep_alive>();
        return !error && enabled.value()==options.keepalive.value_or(true) &&
            (!options.keepalive_idle_seconds || read<4>(socket,static_cast<int>(*options.keepalive_idle_seconds))) &&
            (!options.keepalive_interval_seconds || read<5>(socket,static_cast<int>(*options.keepalive_interval_seconds))) &&
            (!options.keepalive_count || read<6>(socket,static_cast<int>(*options.keepalive_count)));
    }
    auto run(bool uring,bool ipv6) -> bool {
        auto context=io::make_io_context(uring);
        io::tcp_socket socket(context);
        io::endpoint endpoint=ipv6 ? io::endpoint(io::ipv6_address::loopback(),1) : io::endpoint(io::ipv4_address::loopback(),1);
        if (net::prepare_tcp_socket(socket,endpoint,{}) || socket.is_open()) return false;
        platform::TcpSocketOptions invalid; invalid.keepalive_idle_seconds=0;
        if (net::prepare_tcp_socket(socket,endpoint,invalid)!=std::errc::invalid_argument || socket.is_open()) return false;
        platform::TcpSocketOptions enabled{true,17,3,5};
        if (net::prepare_tcp_socket(socket,endpoint,enabled) || !verify(socket,enabled)) return false;
        platform::TcpSocketOptions disabled; disabled.keepalive=false;
        if (platform::apply_tcp_options(socket.native_handle(),disabled) || !verify(socket,disabled)) return false;
        socket.close();
        platform::TcpSocketOptions multipath; multipath.multipath_tcp=true;
        if (net::prepare_tcp_socket(socket,endpoint,multipath)) return false;
        auto [protocol_error,protocol]=socket.get_option<ProbeOption<38,1>>();
        if(protocol_error || protocol.value!=262) return false;
        socket.close();
        platform::TcpSocketOptions implicit; implicit.keepalive_idle_seconds=32767; implicit.keepalive_interval_seconds=32767; implicit.keepalive_count=127;
        if (net::prepare_tcp_socket(socket,endpoint,implicit) || !verify(socket,implicit)) return false;
        socket.close();
        if (platform::apply_tcp_options(-1,{}) || platform::apply_tcp_options(-1,enabled)!=std::errc::bad_file_descriptor) return false;
        invalid=enabled; invalid.keepalive=false;
        if (platform::apply_tcp_options(-1,invalid)!=std::errc::invalid_argument) return false;
        return true;
    }
}

auto main() -> int {
    for (bool uring:{false,true}) {
        if (uring && !io::has_uring) continue;
        for (bool ipv6:{false,true}) if (!run(uring,ipv6)) return 1;
    }
    std::println("TCP keepalive socket settings, empty policy, validation and errors passed on both address families/backends");
}
