import std;
import dns.local_config;
namespace d=dns;
int main(int argc, char** argv) {
    if (argc==4 && std::string_view(argv[1])=="--watch") {
        using namespace std::chrono_literals;
        auto write=[](char const* path,std::string_view text) { std::ofstream file(path,std::ios::binary|std::ios::trunc); file << text; return static_cast<bool>(file); };
        if (!write(argv[2],"nameserver 127.0.0.1\n") || !write(argv[3],"127.0.0.1 old.test\n")) return 12;
        d::LocalSnapshotSource source(argv[2],argv[3],20ms);
        auto old=source.acquire();
        if (!old || old->hosts.size()!=1 || old->hosts[0].name!="old.test") return 13;
        auto wait=[&](auto predicate) {
            auto deadline=std::chrono::steady_clock::now()+3s;
            do { auto current=source.acquire(); if (current && predicate(*current)) return true; std::this_thread::sleep_for(10ms); }
            while (std::chrono::steady_clock::now()<deadline);
            return false;
        };
        if (!write(argv[3],"127.0.0.2 new.test\n") || !wait([](auto const& s) { return s.hosts.size()==1 && s.hosts[0].name=="new.test"; })) return 14;
        if (old->hosts[0].name!="old.test" || old->hosts[0].address.address[3]!=1) return 15;
        if (!write(argv[2],"nameserver invalid\n") || !wait([](auto const& s) { return s.config.servers.empty() && s.hosts.empty(); })) return 16;
        if (!write(argv[2],"nameserver 127.0.0.3\n") || !wait([](auto const& s) { return s.config.servers.size()==1 && s.config.servers[0].address[3]==3 && s.hosts.size()==1; })) return 17;
        auto replacement=std::string(argv[2])+".new";
        if (!write(replacement.c_str(),"nameserver 127.0.0.4\n")) return 18;
        std::error_code error; std::filesystem::rename(replacement,argv[2],error);
        if (error || !wait([](auto const& s) { return s.config.servers.size()==1 && s.config.servers[0].address[3]==4; })) return 19;
        return 0;
    }
    if (argc==3) {
        auto loaded=d::load_local_snapshot(argv[1],argv[2]);
        return loaded && loaded->config.servers.size()==1 && loaded->hosts.size()==1 && loaded->hosts[0].name=="example.test" ? 0 : 8;
    }
    if (argc!=1) return 9;
    auto config=d::parse_local_resolv("# comment\nnameserver 127.0.0.53\nnameserver 2001:db8::1\nsearch Example.Test. local.test\noptions timeout:3 attempts:2 ndots:3 rotate use-vc\n");
    if (!config || config->servers.size()!=2 || config->servers[0].ipv6 || !config->servers[1].ipv6 ||
        config->servers[0].address[3]!=53 || config->search!=std::vector<std::string>{"example.test","local.test"} ||
        config->timeout_seconds!=3 || config->attempts!=2 || config->ndots!=3 || !config->rotate || !config->use_tcp) return 1;
    auto override=d::parse_local_resolv("nameserver 1.1.1.1\nsearch first.test second.test\ndomain Last.Test\n");
    if (!override || override->search!=std::vector<std::string>{"last.test"}) return 2;
    auto root=d::parse_local_resolv("nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch .\n");
    if (!root || root->search!=std::vector<std::string>{""}) return 7;
    auto zero=d::parse_local_resolv("nameserver 127.0.0.1\noptions ndots:0\n");
    auto capped=d::parse_local_resolv("nameserver 127.0.0.1\noptions ndots:99\n");
    if (!zero || zero->ndots!=0 || !capped || capped->ndots!=15 || d::parse_local_resolv("nameserver 127.0.0.1\noptions ndots:x\n")) return 11;
    if (d::parse_local_resolv("nameserver fe80::1%eth0\n") || d::parse_local_resolv("nameserver bad\n") ||
        d::parse_local_resolv("options attempts:0\nnameserver 1.1.1.1\n") || d::parse_local_resolv("search only.test\n") ||
        d::parse_local_resolv(std::string(1024*1024+1,'x'))) return 3;
    auto hosts=d::parse_local_hosts("127.0.0.1 LOCALHOST local.alias # comment\n::1 localhost\n192.0.2.2 my.test\n");
    if (!hosts || hosts->size()!=4 || (*hosts)[0].name!="localhost" || (*hosts)[1].name!="local.alias" ||
        !(*hosts)[2].address.ipv6 || (*hosts)[3].address.address[0]!=192) return 4;
    if (d::parse_local_hosts("bad host.test\n") || d::parse_local_hosts("127.0.0.1 bad..name\n")) return 5;
    std::string many; for (int i=0;i<4097;++i) many+="127.0.0.1 a.test\n";
    auto full=d::parse_local_hosts(many);
    if (full || full.error()!=d::LocalConfigError::too_many_records) return 6;
    if (d::load_local_snapshot("/definitely-missing-nexus-resolv", "/definitely-missing-nexus-hosts")) return 10;
    std::println("local DNS configuration and hosts parsing passed");
}
