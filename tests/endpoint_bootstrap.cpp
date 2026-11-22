import std;
import endpoint.config;
import endpoint.credentials;
import endpoint.process_signals;
import endpoint.bootstrap;
import nexus.thirdparty.corosio;
import net.udp_socket;
auto main(int argc,char**argv) -> int {
    if(argc!=5)return 2;
    if(std::string_view(argv[2])=="uring" && !nex::corosio::has_uring)return 77;
    auto input=std::ifstream(argv[1]);std::string text((std::istreambuf_iterator<char>(input)),{});
    auto config=endpoint::parse_kdl(text);if(!config){std::cerr<<config.error()<<'\n';return 1;}
    endpoint::process::Signals signals;if(!signals.install())return 1;
    auto deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(std::stoul(argv[3]));
    auto material=endpoint::prepare_credentials(config->wireguard,deadline);
    if(!material){std::cerr<<material.error()<<'\n';return 1;}
    auto resolved=endpoint::bootstrap(config->wireguard,*material,deadline,signals,std::string_view(argv[2])=="uring");
    if(!resolved){std::cerr<<resolved.error()<<'\n';return signals.requested() ? 3:1;}
    for(std::size_t i=0;i<material->count;++i) {
        if(!material->peers[i].selected)return 1;
        auto const& value=*material->peers[i].selected;
        std::cout<<static_cast<unsigned>(value.family)<<' ';
        for(auto byte:value.address)std::cout<<std::hex<<static_cast<unsigned>(byte)<<'.';
        std::cout<<'\n';
    }
    if(std::string_view(argv[4])=="race") {
        std::cout<<"resolved"<<std::endl;
        std::string barrier;std::getline(std::cin,barrier);
        return signals.requested() ? 0:5;
    }
    // Verify the original process handler remains installed after bootstrap.
    if(std::string_view(argv[4])=="raise") {
        std::raise(15);
        if(!signals.requested())return 4;
    }
    return 0;
}
