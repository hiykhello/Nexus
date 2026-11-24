import std;
import platform.resolved_bus;
namespace r = ::platform::resolved;
struct Hooks {
    static inline r::Clock::time_point cancel_at=r::Clock::time_point::max();
    static auto canceled() noexcept -> bool {return r::Clock::now()>=cancel_at;}
};
auto main(int argc,char**argv)->int {
    if(argc!=3)return 1;
    std::string_view mode=argv[1];int index=0;
    auto parsed=std::from_chars(argv[2],argv[2]+std::char_traits<char>::length(argv[2]),index);if(parsed.ec!=std::errc{} || index<=0)return 1;
    r::Bus<Hooks> bus;auto deadline=r::Clock::now()+std::chrono::seconds(2);
    auto opened=bus.open(deadline);if(!opened){std::println("open {} {}",int(opened.error().code),opened.error().system.value());return 2;}
    auto request=bus.message("org.freedesktop.DBus","/org/freedesktop/DBus","org.freedesktop.DBus","GetNameOwner");
    if(!request || !request->append_string("org.freedesktop.resolve1"))return 3;
    auto response=bus.call(*request,deadline);if(!response){std::println("owner {} {}",int(response.error().code),response.error().system.value());return 4;}
    std::string_view unique;auto r1=response->reader();
    if(response->signature()!="s" || !r1.read_string(unique) || !r1.at_end() || !unique.starts_with(':'))return 5;
    std::array<char,64> owner{};if(unique.size()>=owner.size())return 5;std::ranges::copy(unique,owner.begin());
    auto lookup=[&](r::Clock::time_point until)->std::expected<r::Message,r::Failure>{
        auto message=bus.message(owner.data(),"/org/freedesktop/resolve1","org.freedesktop.resolve1.Manager","GetLink");
        if(!message)return std::unexpected(message.error());if(!message->append_i32(index))return r::fail(r::Error::capacity);return bus.call(*message,until);
    };
    if(mode=="timeout" || mode=="cancel") {
        auto begin=r::Clock::now();Hooks::cancel_at=mode=="cancel" ? begin+std::chrono::milliseconds(40) : r::Clock::time_point::max();
        auto failed=lookup(begin+std::chrono::milliseconds(160));auto elapsed=std::chrono::duration_cast<std::chrono::milliseconds>(r::Clock::now()-begin).count();
        if(failed || failed.error().code!=(mode=="cancel" ? r::Error::canceled : r::Error::timeout) || elapsed>300){std::println("unexpected bounded result {} elapsed {}",failed ? -1 : int(failed.error().code),elapsed);return 6;}
        std::println("{{\"mode\":\"{}\",\"elapsed_ms\":{},\"callback_removed\":true}}",mode,elapsed);std::fflush(nullptr);
        std::string line;if(!std::getline(std::cin,line) || line!="resume")return 7;Hooks::cancel_at=r::Clock::time_point::max();
    } else if(mode!="read")return 1;
    auto link=lookup(r::Clock::now()+std::chrono::seconds(2));if(!link){std::println("link {} {}",int(link.error().code),link.error().system.value());return 8;}
    std::string_view path;auto r2=link->reader();if(link->signature()!="o" || !r2.read_object_path(path) || !r2.at_end() || !path.starts_with("/org/freedesktop/resolve1/link/"))return 9;
    std::println("real resolved direct async GetNameOwner/GetLink, unique owner {}, link {}, same-bus late-reply recovery passed",owner.data(),path);
    bus.close();if(bus.native_handle()!=-1)return 10;
}
