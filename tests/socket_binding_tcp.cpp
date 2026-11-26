import std;
import net.tcp_connect;
import platform.network_state;
import platform.network_selection;
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
    template<int Name,int Level=platform::linux_socket_abi::tcp_level>
    auto read(io::tcp_socket& socket,int expected) -> bool {
        auto [error,option]=socket.get_option<ProbeOption<Name,Level>>();
        return !error && option.value==expected;
    }
    auto verify(io::tcp_socket& socket,platform::TcpSocketOptions const& options) -> bool {
        auto [error,enabled]=socket.get_option<io::socket_option::keep_alive>();
        return !error && enabled.value()==options.keepalive.value_or(true) &&
            (!options.keepalive_idle_seconds || read<4>(socket,static_cast<int>(*options.keepalive_idle_seconds))) &&
            (!options.keepalive_interval_seconds || read<5>(socket,static_cast<int>(*options.keepalive_interval_seconds))) &&
            (!options.keepalive_count || read<6>(socket,static_cast<int>(*options.keepalive_count)));
    }
    struct InterfaceOption {
        std::array<char,16> bytes{};
        template<class Family> auto level(Family) const noexcept -> int { return 1; }
        template<class Family> auto name(Family) const noexcept -> int { return 25; }
        template<class Family> auto data(Family) noexcept -> void* { return bytes.data(); }
        template<class Family> auto size(Family) const noexcept -> std::size_t { return bytes.size(); }
        template<class Family> auto resize(Family,std::size_t) noexcept -> void {}
    };
    auto binding(io::tcp_socket& socket,io::endpoint const& endpoint,bool ipv6) -> bool {
        platform::TcpSocketOptions policy;
        policy.binding.bind_interface[0]='l'; policy.binding.bind_interface[1]='o';
        policy.binding.inet4_bind_address=std::array<std::uint8_t,4>{127,0,0,2};
        std::array<std::uint8_t,16> local6{};local6[15]=1;policy.binding.inet6_bind_address=local6;
        policy.binding.routing_mark=0x4201;policy.binding.reuse_addr=true;policy.bind_address_no_port=true;
        if (net::prepare_tcp_socket(socket,endpoint,policy)) return false;
        auto [interface_error,device]=socket.get_option<InterfaceOption>();
        auto [keepalive_error,keepalive]=socket.get_option<io::socket_option::keep_alive>();
        auto local=socket.local_endpoint();
        if (interface_error || device.bytes[0]!='l' || device.bytes[1]!='o' || device.bytes[2] ||
            keepalive_error || keepalive.value() || local.port()!=0 || local.is_v6()!=ipv6 ||
            !read<36,1>(socket,0x4201) || !read<2,1>(socket,1) || !read<15,1>(socket,0) || !read<24,0>(socket,1)) return false;
        if (ipv6) { if (local.address().to_v6().to_bytes()!=local6) return false; }
        else if (local.address().to_v4().to_bytes()!=*policy.binding.inet4_bind_address) return false;
        socket.close();
        policy.bind_address_no_port=false;
        if (net::prepare_tcp_socket(socket,endpoint,policy)) return false;
        auto bound=socket.local_endpoint();
        if (!bound.port() || !read<24,0>(socket,0)) return false;
        socket.close();
        auto wrong=policy;wrong.binding.bind_interface.fill('x');
        if (net::prepare_tcp_socket(socket,endpoint,wrong)!=std::errc::invalid_argument || socket.is_open()) return false;
        policy.binding.bind_interface={};std::ranges::copy(std::string_view("nexus-missing0"),policy.binding.bind_interface.begin());
        if (net::prepare_tcp_socket(socket,endpoint,policy)!=std::errc::no_such_device) return false;
        socket.close();
        policy.binding.bind_interface={};policy.binding.inet4_bind_address=std::array<std::uint8_t,4>{203,0,113,99};
        std::array<std::uint8_t,16> absent6{};absent6[0]=0x20;absent6[1]=0x01;absent6[2]=0x0d;absent6[3]=0xb8;absent6[15]=1;
        policy.binding.inet6_bind_address=absent6;
        if (net::prepare_tcp_socket(socket,endpoint,policy)!=std::errc::address_not_available) return false;
        socket.close();return true;
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
        platform::TcpSocketOptions implicit; implicit.keepalive_idle_seconds=32767; implicit.keepalive_interval_seconds=32767; implicit.keepalive_count=127;
        if (net::prepare_tcp_socket(socket,endpoint,implicit) || !verify(socket,implicit)) return false;
        socket.close();
        if (platform::apply_tcp_options(-1,{}) || platform::apply_tcp_options(-1,enabled)!=std::errc::bad_file_descriptor) return false;
        invalid=enabled; invalid.keepalive=false;
        if (platform::apply_tcp_options(-1,invalid)!=std::errc::invalid_argument) return false;
        socket.close();
        return binding(socket,endpoint,ipv6);
    }
    auto test_interface_plan() -> bool {
        auto mem = std::make_shared<platform::network::FallbackMemory>();
        platform::TcpSocketOptions opts;
        opts.binding.network = std::make_shared<platform::network::InterfaceSelection>(
            [mem](bool) noexcept -> platform::network::InterfaceCandidates {
                platform::network::InterfaceCandidates c{};
                c.indices.push_back(10); c.tiers.push_back(0);
                c.indices.push_back(20); c.tiers.push_back(1);
                c.fallback_delay = std::chrono::milliseconds(300);
                c.parallel_fallback = true;
                c.fallback_memory = mem;
                return c;
            });
        auto p0 = net::detail::plan_tcp_interfaces(opts, true, true, 1000);
        if (p0.entries.size() != 2 || p0.entries[0].index != 10 || p0.entries[1].index != 20 ||
            !p0.entries[0].supports_v4 || !p0.entries[0].supports_v6 || p0.entries[0].all_degraded)
            return false;
        mem->mark_failed(10, 1000, true); // IPv6 degraded only
        auto p1 = net::detail::plan_tcp_interfaces(opts, true, true, 2000);
        if (p1.entries.size() != 2 || p1.entries[0].index != 10 || p1.entries[0].all_degraded) return false;
        auto p2 = net::detail::plan_tcp_interfaces(opts, false, true, 2000);
        if (p2.entries.size() != 2 || p2.entries[0].index != 20 || p2.entries[1].index != 10 || !p2.entries[1].all_degraded)
            return false;
        mem->mark_failed(10, 1000, false); // Both v4 and v6 degraded
        auto p3 = net::detail::plan_tcp_interfaces(opts, true, true, 2000);
        if (p3.entries.size() != 2 || p3.entries[0].index != 20 || p3.entries[1].index != 10 || !p3.entries[1].all_degraded)
            return false;
        net::detail::InterfacePlan zero_delay{};
        zero_delay.fallback_delay = std::chrono::milliseconds(0);
        auto now = std::chrono::steady_clock::now();
        auto far = now + std::chrono::seconds(10);
        auto d1 = net::detail::tcp_planned_deadline(far, zero_delay, true, false, false, false);
        auto d2 = net::detail::tcp_planned_deadline(far, zero_delay, false, false, false, true);
        return d1 > now + std::chrono::milliseconds(100) && d1 < far &&
            d2 > now + std::chrono::milliseconds(100) && d2 < far;
    }

    auto test_auto_detect_and_hybrid() -> bool {
        using namespace platform::network;
        namespace abi = platform::network::constants;
        Snapshot snap{};
        snap.links = {
            {.index = 1, .flags = abi::iff_up | abi::iff_lower_up, .name = "lo"},
            {.index = 2, .flags = abi::iff_up | abi::iff_lower_up, .name = "eth0"},
            {.index = 3, .flags = abi::iff_up | abi::iff_lower_up, .name = "wlan0"},
            {.index = 4, .flags = abi::iff_up, .name = "eth1"}, // no carrier
        };
        Address a2v4{.index = 2, .family = abi::af_inet, .prefix = 24, .scope = abi::rt_scope_universe};
        a2v4.local[0] = 192; a2v4.local[1] = 168; a2v4.local[2] = 1; a2v4.local[3] = 2;
        Address a3v4{.index = 3, .family = abi::af_inet, .prefix = 24, .scope = abi::rt_scope_universe};
        a3v4.local[0] = 10; a3v4.local[3] = 2;
        Address a3v6{.index = 3, .family = abi::af_inet6, .prefix = 64, .scope = abi::rt_scope_universe};
        a3v6.local[0] = 0x20; a3v6.local[1] = 0x01; a3v6.local[15] = 2;
        snap.addresses = {a2v4, a3v4, a3v6};
        snap.routes = {
            {.table = abi::rt_table_main, .priority = 50, .index = 4, .family = abi::af_inet, .type = abi::rtn_unicast}, // down carrier ignored
            {.table = abi::rt_table_main, .priority = 200, .index = 3, .family = abi::af_inet, .type = abi::rtn_unicast},
            {.table = abi::rt_table_main, .priority = 100, .index = 2, .family = abi::af_inet, .type = abi::rtn_unicast},
            {.table = abi::rt_table_main, .priority = 100, .index = 3, .family = abi::af_inet6, .type = abi::rtn_unicast},
        };
        if (net::select_default_egress_interface(snap, false) != 2) return false;
        if (net::select_default_egress_interface(snap, true) != 3) return false;

        Policy hybrid_auto{Strategy::hybrid, Type::wifi, std::nullopt, {}, std::chrono::milliseconds(0)};
        auto hc = select_interfaces(snap, hybrid_auto, false);
        if (!hc.hybrid_race || !hc.parallel_fallback || hc.indices.size() != 2 || hc.indices[0] != 3 || hc.indices[1] != 2)
            return false;

        // Live connect_tcp_candidates with auto_detect_interface (loopback safe) and hybrid concurrent race.
        auto ctx = io::make_io_context(false);
        io::tcp_acceptor srv(ctx);
        if (srv.open(io::family::v4) || srv.bind(io::endpoint(io::ipv4_address::loopback(), 0)) || srv.listen(8))
            return false;
        auto ep = srv.local_endpoint();
        bool ok_auto = false, ok_hybrid = false, ok_deadline = false, ok_cancel = false;
        auto run_client = [&]() -> capy::task<> {
            std::array<io::endpoint, 1> eps{ep};
            bool prep_failed = false;
            auto cond = [](std::error_code const&, io::endpoint const&) { return true; };
            {
                io::tcp_socket sock(ctx);
                platform::TcpSocketOptions opt;
                opt.binding.auto_detect_interface = true;
                auto [ec, got] = co_await net::connect_tcp_candidates(
                    sock, eps, cond, opt, prep_failed, std::chrono::steady_clock::now() + std::chrono::seconds(2));
                ok_auto = !ec && !prep_failed && got == ep && sock.is_open();
                sock.close();
            }
            {
                io::tcp_socket sock(ctx);
                platform::TcpSocketOptions opt;
                opt.binding.network = std::make_shared<InterfaceSelection>([](bool) noexcept -> InterfaceCandidates {
                    InterfaceCandidates c{};
                    c.indices.push_back(999999); c.tiers.push_back(0); // non-existent interface
                    c.indices.push_back(0); c.tiers.push_back(1);      // unbound succeeds concurrently
                    c.hybrid_race = true;
                    c.parallel_fallback = true;
                    return c;
                });
                auto [ec, got] = co_await net::connect_tcp_candidates(
                    sock, eps, cond, opt, prep_failed, std::chrono::steady_clock::now() + std::chrono::seconds(2));
                ok_hybrid = !ec && !prep_failed && got == ep && sock.is_open();
                sock.close();
            }
            // Hybrid stagger delay clamped to tight deadline (must not sleep full 5s fallback_delay).
            {
                io::tcp_socket sock(ctx);
                platform::TcpSocketOptions opt;
                opt.binding.network = std::make_shared<InterfaceSelection>([](bool) noexcept -> InterfaceCandidates {
                    InterfaceCandidates c{};
                    c.indices.push_back(999998); c.tiers.push_back(0);
                    c.indices.push_back(999999); c.tiers.push_back(1);
                    c.fallback_delay = std::chrono::milliseconds(5000);
                    c.hybrid_race = true;
                    return c;
                });
                auto t0 = std::chrono::steady_clock::now();
                auto [ec, got] = co_await net::connect_tcp_candidates(
                    sock, eps, cond, opt, prep_failed, t0 + std::chrono::milliseconds(80));
                auto elapsed = std::chrono::steady_clock::now() - t0;
                ok_deadline = bool(ec) && elapsed < std::chrono::milliseconds(1000);
                sock.close();
            }
            srv.close();
        };
        auto accept_two = [&]() -> capy::task<> {
            for (int i = 0; i < 2; ++i) {
                auto [ec, peer] = co_await srv.accept();
                if (ec) break;
                peer.close();
            }
        };
        // External stop_token cancellation propagates capy::cond::canceled from hybrid race.
        std::stop_source cancel_src;
        auto cancel_race = [&]() -> capy::task<> {
            std::array<io::endpoint, 1> eps{ep};
            bool prep_failed = false;
            io::tcp_socket sock(ctx);
            platform::TcpSocketOptions opt;
            opt.binding.network = std::make_shared<InterfaceSelection>([](bool) noexcept -> InterfaceCandidates {
                InterfaceCandidates c{};
                c.indices.push_back(999998); c.tiers.push_back(0);
                c.indices.push_back(999999); c.tiers.push_back(1);
                c.fallback_delay = std::chrono::milliseconds(5000);
                c.hybrid_race = true;
                return c;
            });
            auto [ec, got] = co_await net::connect_tcp_candidates(
                sock, eps, [](std::error_code const&, io::endpoint const&) { return true; },
                opt, prep_failed, std::chrono::steady_clock::now() + std::chrono::seconds(5));
            ok_cancel = (ec == capy::cond::canceled);
            sock.close();
        };
        auto trigger_cancel = [&]() -> capy::task<> {
            (void)co_await corosio::delay(std::chrono::milliseconds(20));
            cancel_src.request_stop();
        };
        capy::run_async(ctx.get_executor(), [] {}, [](std::exception_ptr) noexcept {})(accept_two());
        capy::run_async(ctx.get_executor(), [] {}, [](std::exception_ptr) noexcept {})(run_client());
        capy::run_async(ctx.get_executor(), cancel_src.get_token(), [] {}, [](std::exception_ptr) noexcept {})(cancel_race());
        capy::run_async(ctx.get_executor(), [] {}, [](std::exception_ptr) noexcept {})(trigger_cancel());
        (void)ctx.run_for(std::chrono::seconds(3));
        return ok_auto && ok_hybrid && ok_deadline && ok_cancel;
    }
}

auto main() -> int {
    if (!test_interface_plan()) return 1;
    if (!test_auto_detect_and_hybrid()) return 2;
    for (bool uring:{false,true}) {
        if (uring && !io::has_uring) continue;
        for (bool ipv6:{false,true}) if (!run(uring,ipv6)) return 1;
    }
    std::println("TCP keepalive and physical bindings, no-port/source/mark/interface/reuse, auto-detect, hybrid race and explicit failures passed: two address families, {} backend(s)",io::has_uring ? 2 : 1);
}
