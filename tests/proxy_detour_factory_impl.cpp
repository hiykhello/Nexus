module proxy;
import std;
import proxy.v4;
import nexus.thirdparty.corosio;
import nexus.thirdparty.capy;
import net.datagram_frame;

namespace {
    struct Allocation { void (*budget)(std::ptrdiff_t) noexcept; std::size_t (*live)() noexcept; };
    struct Failure {
        Allocation const& allocation;
        Failure(Allocation const& source,std::size_t count) : allocation(source) { allocation.budget(static_cast<std::ptrdiff_t>(count)); }
        ~Failure() { allocation.budget(-1); }
    };
    // The default process-wide frame pool retains freed blocks. Use direct
    // allocation here so each frame is injected and released by this fixture.
    struct FrameAllocator {
        std::pmr::memory_resource* previous=nex::capy::get_current_frame_allocator();
        FrameAllocator() { nex::capy::set_current_frame_allocator(std::pmr::new_delete_resource()); }
        ~FrameAllocator() { nex::capy::set_current_frame_allocator(previous); }
    };
    // Fail every successive ordinary C++ allocation until construction can
    // finish. Each failure must unwind without retaining a partial profile,
    // callback, stop state or proxy object, and leave the factory reusable.
    template<class Construct>
    auto failures(Allocation const& allocation,Construct&& construct) -> bool {
        for (std::size_t count=0;count<256;++count) {
            auto before=allocation.live();
            bool complete=false;
            try {
                Failure failure(allocation,count);
                complete=construct();
            } catch (std::bad_alloc const&) {}
            if (allocation.live()!=before) return false;
            if (complete) return count>0;
        }
        return false;
    }
    template<class Initialize,class Cleanup>
    auto start_failures(Allocation const& allocation,Initialize&& initialize,Cleanup&& cleanup) -> bool {
        for (std::size_t count=0;count<256;++count) {
            auto before=allocation.live(); bool complete=false;
            try { Failure failure(allocation,count); complete=initialize(); }
            catch (std::bad_alloc const&) {}
            // Cleanup runs outside the injected allocation budget and must
            // also handle tasks posted before a later startup failure.
            cleanup();
            if (allocation.live()!=before) return false;
            if (complete) return count>0;
        }
        return false;
    }
}

extern "C" int nexus_test_detour_factory(char const* uuid,char const* ca,
    void (*budget)(std::ptrdiff_t) noexcept,std::size_t (*live)() noexcept) {
    using namespace proxy;
    Allocation allocation{budget,live};
    std::array<std::uint8_t,16> key{};
    auto ss=[&] { return make_shadowsocks_factory("127.0.0.1",443,key,{},true,10000); };
    auto vless=[&] { return make_vless_factory("127.0.0.1",443,uuid,"cover.example",ca,TlsKeyExchange::x25519,{}, {},true,10000); };
    auto upgrade=[&] {
        HttpUpgradeTransport transport{"cover.example","/upgrade?test=1",{{"X-Test","factory"}}};
        return make_vless_factory("127.0.0.1",443,uuid,"cover.example",ca,TlsKeyExchange::x25519,{}, {},false,10000,{},std::move(transport));
    };
#ifdef NEXUS_ENABLE_GRPC_VLESS
    auto grpc=[&] {
        GrpcTransport transport;transport.service_name="nexus.Service";transport.authority="cover.example";
        return make_vless_factory("127.0.0.1",443,uuid,"cover.example",ca,TlsKeyExchange::x25519,{}, {},false,10000,{},{},transport);
    };
#endif
#ifdef NEXUS_ENABLE_TROJAN
    auto trojan=[&] { return make_trojan_factory("127.0.0.1",443,uuid,"cover.example",ca,TlsKeyExchange::x25519,{},10000,{}); };
#endif
#ifdef NEXUS_ENABLE_ANYTLS
    auto anytls=[&] { return make_anytls_factory("127.0.0.1",443,uuid,"cover.example",ca,TlsKeyExchange::x25519,{},10000,{},{}); };
#endif
    // Warm lazy library state before comparing the number of live allocations.
    { auto a=ss(); auto b=vless(); auto c=upgrade(); if (!a || !b || !c) return 2; }
#ifdef NEXUS_ENABLE_GRPC_VLESS
    {auto d=grpc();if (!d) return 2;}
    if (!failures(allocation,[&] {auto factory=grpc();return factory.has_value();})) return 3;
#endif
#ifdef NEXUS_ENABLE_TROJAN
    { auto c=trojan(); if (!c) return 2; }
    if (!failures(allocation,[&] { auto factory=trojan(); return factory.has_value(); })) return 3;
#endif
#ifdef NEXUS_ENABLE_ANYTLS
    { auto factory=anytls(); if (!factory) return 2; }
    if (!failures(allocation,[&] { auto factory=anytls(); return factory.has_value(); })) return 3;
#endif
    if (!failures(allocation,[&] { auto factory=ss(); return factory.has_value(); }) ||
        !failures(allocation,[&] { auto factory=vless(); return factory.has_value(); }) ||
        !failures(allocation,[&] { auto factory=upgrade(); return factory.has_value(); })) return 3;
    auto before=allocation.live();
    {
        FrameAllocator frames;
        auto context=nex::corosio::make_io_context(false);
        context.set_frame_allocator(std::pmr::new_delete_resource());
        { Session warm(context); }
        {
            std::vector<TunnelFactory> original;
            {
                auto a=ss(); auto b=vless();
                if (!a || !b) return 2;
                original.push_back(std::move(*a)); original.push_back(std::move(*b));
                auto upgraded=upgrade(); if (!upgraded) return 2;
                original.push_back(std::move(*upgraded));
#ifdef NEXUS_ENABLE_GRPC_VLESS
                auto g=grpc();if (!g) return 2;original.push_back(std::move(*g));
#endif
    #ifdef NEXUS_ENABLE_TROJAN
                auto c=trojan(); if (!c) return 2;
                original.push_back(std::move(*c));
    #endif
    #ifdef NEXUS_ENABLE_ANYTLS
                auto d=anytls(); if (!d) return 2;
                original.push_back(std::move(*d));
    #endif
            }
            // Relocation must preserve the profiles borrowed by through callbacks.
            auto factories=std::move(original);
            factories.reserve(16);
            Session session(context);
            session.tunnel_factories=&factories;
            TcpSocketOptions options;
            OutboundContext environment{context,nullptr,nullptr,&factories,&options};
            for (std::size_t index=0;index<factories.size();++index) {
                auto& factory=factories[index];
                for (bool layer:{false,true}) {
                    if (layer) factory.detour=(index+1)%factories.size();
                    else factory.detour.reset();
                    auto initialize=[&] {
                        auto* lower=layer ? &factories[*factory.detour] : nullptr;
                        return !factory.start_context || factory.start_context(environment,lower,false);
                    };
                    auto cleanup=[&] {
                        if (factory.stop_context) factory.stop_context(context);
                        context.restart(); context.run();
                        if (factory.finish_context) factory.finish_context(context);
                    };
                    if (factory.start_context) {
                        // Warm executor/coroutine machinery before exact live
                        // allocation comparisons, then test every startup point.
                        if (!initialize()) return 6;
                        cleanup();
                        if (!start_failures(allocation,initialize,cleanup)) return 7;
                        if (!initialize()) return 6;
                    }
                    for (bool relay_local:{false,true}) {
                        if (!failures(allocation,[&] {
                            auto tunnel=factory(session,context,relay_local);
                            if (!tunnel || tunnel->packet_transport().kind==net::PacketTransportKind::none) return false;
                            tunnel->cancel();
                            return true;
                        })) return 4;
                    }
                    cleanup();
                    factory.detour.reset();
                }
            }
        }
    }
    if (allocation.live()!=before) return 5;
    std::println("Enabled protocol factories, worker startup and layer allocation failures release resources and preserve moved profiles");
    return 0;
}
