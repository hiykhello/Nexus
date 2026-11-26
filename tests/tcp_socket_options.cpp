import std;
import net.tcp_connect;
import config.listen_types;
import relay;
import relay.listener_options;
import capy;
import corosio;

namespace io = ::corosio;

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

    auto test_listener_options(bool ipv6) -> bool {
        using namespace platform::linux_socket_abi;
        auto ctx = io::make_io_context(false);
        io::endpoint ep = ipv6 ? io::endpoint(io::ipv6_address::loopback(), 0) : io::endpoint(io::ipv4_address::loopback(), 0);
        // TCP listener options: reuse-addr, tcp-fast-open, tcp-keepalive (idle/interval/count), multipath-tcp.
        {
            io::tcp_acceptor acc(ctx);
            config::ListenOptions opts{};
            opts.reuse_addr = true;
            opts.tcp_fast_open = true;
            opts.tcp_keepalive = true;
            opts.tcp_keepalive_idle_s = 20;
            opts.tcp_keepalive_interval_s = 4;
            opts.tcp_keepalive_count = 6;
            opts.multipath_tcp = true;
            if (auto ec = relay::open_and_bind_tcp_listener(acc, ep, opts)) return false;
            int fd = acc.native_handle();
            auto ra = platform::socket_detail::get<int>(fd, socket_level, reuse_addr);
            auto ka = platform::socket_detail::get<int>(fd, socket_level, keepalive);
            auto ki = platform::socket_detail::get<int>(fd, tcp_level, keepalive_idle);
            auto kv = platform::socket_detail::get<int>(fd, tcp_level, keepalive_interval);
            auto kc = platform::socket_detail::get<int>(fd, tcp_level, keepalive_count);
            auto pr = platform::socket_detail::get<int>(fd, socket_level, 38); // SO_PROTOCOL
            if (!ra || *ra != 1 || !ka || *ka != 1 || !ki || *ki != 20 || !kv || *kv != 4 ||
                !kc || *kc != 6 || !pr || *pr != 262) return false;
            acc.close();
        }
        // Invalid bind-interface & nonexistent netns errors on TCP & UDP listeners.
        {
            io::tcp_acceptor acc(ctx);
            config::ListenOptions bad_if{}; bad_if.bind_interface = "nexus-missing0";
            auto ec1 = relay::open_and_bind_tcp_listener(acc, ep, bad_if);
            acc.close();
            if (!ec1 || (ec1 != std::errc::no_such_device && ec1 != std::errc::operation_not_permitted)) return false;
            config::ListenOptions bad_ns{}; bad_ns.netns = "/nonexistent/nexus/netns";
            if (relay::open_and_bind_tcp_listener(acc, ep, bad_ns) != std::errc::no_such_file_or_directory) return false;
            acc.close();
        }
        // UDP listener options: reuse-addr, udp-fragment (#true -> PMTUDISC_DONT, #false -> PMTUDISC_DO), timeout helper.
        for (bool frag : {true, false}) {
            io::udp_socket udp(ctx);
            config::ListenOptions opts{};
            opts.reuse_addr = true;
            opts.udp_fragment = frag;
            opts.udp_timeout_ms = 25000;
            if (relay::effective_udp_timeout_ms(opts, 60000) != 25000) return false;
            if (auto ec = relay::open_and_bind_udp_listener(udp, ep, opts)) return false;
            int fd = udp.native_handle();
            auto ra = platform::socket_detail::get<int>(fd, socket_level, reuse_addr);
            auto rp = platform::socket_detail::get<int>(fd, socket_level, reuse_port);
            auto mtu = platform::socket_detail::get<int>(fd, ip_level, ip_mtu_discover);
            int expected = frag ? pmtu_dont : pmtu_do;
            if (!ra || *ra != 1 || !rp || *rp != 1 || !mtu || *mtu != expected) return false;
            if (ipv6) {
                auto mtu6 = platform::socket_detail::get<int>(fd, ipv6_level, ipv6_mtu_discover);
                if (!mtu6 || *mtu6 != expected) return false;
            }
            udp.close();
        }
        return true;
    }

    auto test_inbound_detour_handoff() -> bool {
        auto shared = relay::make_shared_io_context();
        if (!shared) return false;
        auto& io_ctx = **shared;
        io::tcp_acceptor echo_srv(io_ctx);
        if (echo_srv.open(io::family::v4) || echo_srv.bind(io::endpoint(io::ipv4_address::loopback(), 0)) || echo_srv.listen(4))
            return false;
        auto echo_port = echo_srv.local_endpoint().port();
        auto front = relay::Server::create_shared(io_ctx);
        auto back = relay::Server::create_shared(io_ctx);
        if (!front || !back) return false;
        config::ListenOptions lopts{}; lopts.reuse_addr = true; lopts.tcp_keepalive = true; lopts.tcp_keepalive_idle_s = 15;
        if (!(*front)->set_listen_options(lopts) || !(*back)->set_listen_options(lopts)) return false;
        if (!(*back)->set_fixed_tcp_target("127.0.0.1", echo_port)) return false;
        (*front)->set_detour_target(back->get());
        auto back_port = (*back)->start(0, relay::Inbound::fixed_tcp, 1, false);
        auto front_port = (*front)->start(0, relay::Inbound::socks5, 1, false);
        if (!back_port || !front_port) return false;

        bool echoed = false;
        auto echo_task = [&]() -> capy::task<> {
            auto [ec, peer] = co_await echo_srv.accept();
            if (ec) co_return;
            std::array<char, 16> buf{};
            auto [re, n] = co_await peer.read_some(capy::mutable_buffer(buf.data(), buf.size()));
            if (!re && n) (void)co_await peer.write_some(capy::const_buffer(buf.data(), n));
            peer.close();
            echo_srv.close();
        };
        auto client_task = [&]() -> capy::task<> {
            io::tcp_socket c(io_ctx);
            auto [ce] = co_await c.connect(io::endpoint(io::ipv4_address::loopback(), *front_port));
            if (!ce) {
                std::string_view msg = "detour-ok";
                (void)co_await c.write_some(capy::const_buffer(msg.data(), msg.size()));
                std::array<char, 16> got{};
                auto [re, n] = co_await c.read_some(capy::mutable_buffer(got.data(), got.size()));
                echoed = !re && std::string_view(got.data(), n) == msg;
            }
            c.close();
        };
        capy::run_async(io_ctx.get_executor(), [] {}, [](std::exception_ptr) noexcept {})(echo_task());
        capy::run_async(io_ctx.get_executor(), [] {}, [](std::exception_ptr) noexcept {})(client_task());
        for (int i = 0; i < 200 && !echoed; ++i) (void)io_ctx.run_for(std::chrono::milliseconds(10));
        (*front)->stop();
        (*back)->stop();
        if (!echoed) return false;

        // Verify target teardown before source stop never causes UAF (same-context + cross-context).
        auto back2 = relay::Server::create_shared(io_ctx);
        auto front2 = relay::Server::create_shared(io_ctx);
        if (!back2 || !front2 || !(*back2)->set_fixed_tcp_target("127.0.0.1", 1)) return false;
        (*front2)->set_detour_target(back2->get());
        auto bp2 = (*back2)->start(0, relay::Inbound::fixed_tcp, 1, false);
        auto fp2 = (*front2)->start(0, relay::Inbound::socks5, 1, false);
        if (!bp2 || !fp2) return false;
        (*back2)->stop();
        back2->reset(); // Destroy target completely while front2 is still accepting!
        bool closed_cleanly = false;
        auto probe_after_destroy = [&]() -> capy::task<> {
            io::tcp_socket c(io_ctx);
            auto [ce] = co_await c.connect(io::endpoint(io::ipv4_address::loopback(), *fp2));
            if (!ce) {
                std::array<char, 8> buf{};
                auto [re, n] = co_await c.read_some(capy::mutable_buffer(buf.data(), buf.size()));
                closed_cleanly = bool(re) || n == 0;
            }
            c.close();
        };
        capy::run_async(io_ctx.get_executor(), [] {}, [](std::exception_ptr) noexcept {})(probe_after_destroy());
        io_ctx.restart();
        for (int i = 0; i < 100 && !closed_cleanly; ++i) (void)io_ctx.run_for(std::chrono::milliseconds(10));
        (*front2)->stop();
        return closed_cleanly;
    }
}

auto main() -> int {
    for (bool uring:{false,true}) {
        if (uring && !io::has_uring) continue;
        for (bool ipv6:{false,true}) if (!run(uring,ipv6)) return 1;
    }
    for (bool ipv6 : {false, true}) if (!test_listener_options(ipv6)) return 2;
    if (!test_inbound_detour_handoff()) return 3;
    std::println("TCP keepalive, listener socket options (TCP/UDP), inbound detour handoff, validation and errors passed on both address families/backends");
}
