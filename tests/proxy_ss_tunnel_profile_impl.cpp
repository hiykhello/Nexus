module;
#include <boost/corosio/io_context.hpp>
module nexus.proxy;
import std;
import proxy.v4;
extern "C" bool nexus_test_tunnel_profile_is_alive();
extern "C" int nexus_test_ss_tunnel_profile() {
    using namespace nexus::proxy;
    io::io_context context;
    {
        Session session(context);
        auto factories=std::make_shared<std::vector<TunnelFactory>>();
        std::array<std::uint8_t,16> key{};
        {
            auto factory=make_shadowsocks_factory("127.0.0.1",12345,key,{});
            if (!factory) return 1;
            factories->push_back(std::move(*factory));
        }
        session.tunnel_factories=factories;
        session.tunnel=(*session.tunnel_factories)[0](session,context);
        factories.reset();
        if (!session.tunnel || !nexus_test_tunnel_profile_is_alive()) return 2;
    }
    return 0;
}
