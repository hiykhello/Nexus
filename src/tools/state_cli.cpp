import std;
import config;
import rulefile;
import state.dns_cache;
import state.ruleset_cache;
import state.maintenance;
import state.file;

namespace {
    auto help(std::ostream& out) -> void {
        out << "usage: nexus state inspect --config <file>\n"
               "       nexus state clear-cache --config <file> [--dns] [--rulesets]\n"
               "       nexus state reset --config <file> --target fakeip|selectors --confirm\n";
    }

    auto report(::state::StateError const& error) -> int {
        std::cerr << "state: " << ::state::describe(error.stage);
        if (error.os) std::cerr << " (errno=" << error.os.value() << ')';
        std::cerr << '\n';
        return 1;
    }

    auto inventory(config::Config const& config) -> void {
        auto fake=config.dns ? config.dns->fakeip : std::nullopt;
        auto root=config.state ? config.state->cache_directory : std::string{};
        auto dns=config.dns ? config.dns->message_cache_directory : std::string{};
        auto row=[](unsigned tier,std::string_view name,::state::Inventory info) {
            std::cout << std::format("tier={} component={} version={} entries={} bytes={} health={}\n",
                tier,name,info.version,info.entries,info.bytes,info.health);
        };
        row(1,"selectors",::state::inspect_selectors(config.selector_state_directory));
        row(2,"fakeip",::state::inspect_fakeip(fake ? fake->state_directory : std::string{},fake && fake->unified));
        row(3,"dns",::state::inspect_dns(root,dns,config.dns ? config.dns->servers.size() : 0));
        row(3,"rulesets",::state::inspect_rules(root));
    }

    auto clear(config::Config const& config,bool dns,bool rules) -> int {
        auto options=config.state.value_or(config::StateOptions{});
        if (!options.cache_directory.empty()) {
            auto directory=::state::ensure_private_directory(options.cache_directory);
            if (!directory) return report(directory.error());
            if (dns) {
                auto done=::state::DnsCache(options.cache_directory,options.dns_cache_max_bytes).clear();
                if (!done) return report(done.error());
            }
            if (rules) {
                auto done=::state::RulesetCache(options.cache_directory,{options.ruleset_cache_max_bytes}).clear();
                if (!done) return report(done.error());
            }
        }
        if (dns && config.dns && !config.dns->message_cache_directory.empty()) {
            auto done=::state::clear_legacy_dns(config.dns->message_cache_directory);
            if (!done) return report(done.error());
        }
        return 0;
    }
}

auto nexus_state(int argc,char** argv) -> int {
    if (argc==2 && std::string_view(argv[1])=="--help") {help(std::cout);return 0;}
    auto usage=[] {help(std::cerr);return 2;};
    if (argc<2) return usage();
    auto command=std::string_view(argv[1]);
    if (command!="inspect" && command!="clear-cache" && command!="reset") return usage();
    std::string_view config_name,target;
    bool dns=false,rules=false,confirm=false;
    for (int i=2;i<argc;++i) {
        auto option=std::string_view(argv[i]);
        if (option=="--config" && config_name.empty() && i+1<argc) config_name=argv[++i];
        else if (command=="clear-cache" && option=="--dns" && !dns) dns=true;
        else if (command=="clear-cache" && option=="--rulesets" && !rules) rules=true;
        else if (command=="reset" && option=="--target" && target.empty() && i+1<argc) target=argv[++i];
        else if (command=="reset" && option=="--confirm" && !confirm) confirm=true;
        else return usage();
    }
    if (config_name.empty()) return usage();
    if (command=="reset" && !confirm) {
        std::cerr << "state reset requires --confirm\n";
        return 2;
    }
    if (command=="reset" && target!="fakeip" && target!="selectors") return usage();
    auto text=::rulefile::read_regular_file(config_name);
    if (!text) {std::cerr << "state: cannot read configuration\n";return 1;}
    auto config=config::parse_kdl(*text);
    if (!config) {std::cerr << "state: invalid configuration\n";return 1;}
    if (command=="inspect") {inventory(*config);return 0;}
    if (command=="clear-cache") return clear(*config,dns || !rules,rules || !dns);

    auto legacy=config->dns && config->dns->fakeip && !config->dns->fakeip->unified;
    if (target=="fakeip" && (!config->dns || !config->dns->fakeip || legacy)) {
        std::cerr << "state reset fakeip requires a configured unified FakeIP store\n";
        return 1;
    }
    if (target=="selectors" && config->selector_state_directory.empty()) {
        std::cerr << "state reset requires a configured selector state directory\n";
        return 1;
    }
    auto done=target=="selectors" ? ::state::reset_selectors(config->selector_state_directory) :
        ::state::reset_fakeip(config->state->directory);
    if (!done) return report(done.error());
    std::cout << "backup=" << *done << '\n';
    return 0;
}
