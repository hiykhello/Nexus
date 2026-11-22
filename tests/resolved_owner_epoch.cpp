import std;
import platform.resolved_bus;
import platform.resolved_client;
namespace r = ::platform::resolved;
struct Hooks {
    static auto canceled() noexcept -> bool {return false;}
    static auto before_owner_watch() noexcept -> void {
        std::println("watch-gap");std::fflush(nullptr);
        std::string line;if(!std::getline(std::cin,line) || line!="replaced")std::terminate();
    }
};
auto main()->int {
    r::Client<Hooks> client;
    auto opened=client.open(2,r::Clock::now()+std::chrono::seconds(4));
    if(opened || opened.error().code!=r::Error::ownership || client.native_handle()!=-1)return 1;
    std::println("service relinquished well-known name while its original unique connection stayed live in pre-watch gap; recheck rejects stale epoch before any GetLink/settings RPC");
}
