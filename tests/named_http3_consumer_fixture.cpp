import std;
import config;
import http.named_client;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

namespace {
    namespace capy=nex::capy;
    namespace io=nex::corosio;
    namespace http=http;
    using Clock=std::chrono::steady_clock;
    using namespace std::chrono_literals;

    auto read_file(char const* path) -> std::string {
        std::ifstream input(path,std::ios::binary);
        return {std::istreambuf_iterator<char>(input),{}};
    }

    auto check_resumption(http::NamedHttpClient& client) -> capy::task<bool> {
        auto body=[](std::string_view,Clock::time_point) -> capy::task<bool> {co_return true;};
        auto first=co_await client.get({.target="/resume",.deadline=Clock::now()+2s},body);
        if (first!=200) co_return false;
        auto [error]=co_await io::delay(16s);
        if (error) co_return false;
        auto next=co_await client.get({.target="/resume",.deadline=Clock::now()+2s},body);
        co_return next==200;
    }

    auto check(http::NamedHttpClient& client,std::string const& expected) -> capy::task<bool> {
        auto deadline=Clock::now()+3s;
        auto discard=[](std::string_view,Clock::time_point) -> capy::task<bool> {co_return true;};
        auto warm=co_await client.get({.target="/consumer-warm",.deadline=deadline},discard);
        if (warm!=200) co_return false;
        bool accepted=false,rejected=false,headers_seen=false;
        std::string response;
        auto consume=[&](std::string_view bytes,Clock::time_point) -> capy::task<bool> {
            if (!headers_seen) co_return false;
            auto [error]=co_await io::delay(4ms);
            if (error) co_return false;
            response.append(bytes);
            co_return true;
        };
        auto reject=[&](std::string_view bytes,Clock::time_point) -> capy::task<bool> {
            rejected=!bytes.empty();
            co_return false;
        };
        auto headers=[&](std::string_view name,std::string_view) {
            if (name=="content-type") headers_seen=true;
        };
        auto slow=[&]() -> capy::task<capy::results<>> {
            auto reply=co_await client.get({.target="/consumer-slow",.deadline=deadline},consume,headers);
            accepted=reply==200;
            co_return capy::results<>{};
        };
        auto canceled=[&]() -> capy::task<capy::results<>> {
            auto reply=co_await client.get({.target="/consumer-reject",.deadline=deadline},reject);
            rejected=rejected && !reply;
            co_return capy::results<>{};
        };
        (void)co_await capy::when_all(slow(),canceled());
        auto next=co_await client.get({.target="/consumer-after",.deadline=deadline},discard);
        co_return accepted && rejected && response==expected && next==200;
    }
}

auto main(int argc,char** argv) -> int {
    if (argc!=4 && (argc!=5 || std::string_view(argv[4])!="--resume")) return 2;
    auto resume=argc==5;
    auto config=config::parse_kdl(read_file(argv[1]));
    if (!config) {std::cerr<<config.error()<<'\n';return 2;}
    auto client=http::NamedHttpClient::create(std::move(*config),"updates",argv[2]);
    if (!client) {std::cerr<<client.error()<<'\n';return 2;}
    auto expected=read_file(argv[3]);
    auto& io=(*client)->executor();
    std::optional<bool> passed;
    capy::run_async(io.get_executor(),[&](bool value){passed=value;},
        [&](std::exception_ptr){passed=false;})(resume ? check_resumption(**client) : check(**client,expected));
    auto deadline=Clock::now()+(resume ? 21s : 4s);
    while (!passed && Clock::now()<deadline) (void)io.run_for(20ms);
    if (!passed.value_or(false)) return 1;
    if (resume) return 0;
    std::cout<<"Named HTTP/3 asynchronously consumed one stream while rejecting its sibling\n";
    return 0;
}
