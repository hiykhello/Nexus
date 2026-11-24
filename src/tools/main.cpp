import std;
import cli.endpoint;
import cli.control;
import cli.route_files;
import cli.tun_enabled;
import cli.gen_tools;

auto nexus_run(int argc, char** argv) -> int;
auto nexus_check(int argc, char** argv) -> int;
auto nexus_rule_explain(int argc,char** argv) -> int;
auto nexus_rule_convert(int argc, char** argv) -> int;
auto nexus_rule_merge(int argc, char** argv) -> int;
auto nexus_rule_fetch(int argc, char** argv) -> int;
auto nexus_state(int argc, char** argv) -> int;
auto nexus_rule_watch(int argc, char** argv) -> int;
auto nexus_convert_config(int argc, char** argv) -> int;
auto nexus_provider(int argc, char** argv) -> int;
auto nexus_system_proxy(int argc, char** argv) -> int;
auto nexus_service(int argc, char** argv) -> int;

namespace {
    enum class Command { run, check, rule, endpoint, control, state, generate, tools, convert_config, provider, system_proxy, service };
    enum class RuleCommand { convert, merge, explain, fetch, watch };

    template<class T>
    struct CommandEntry {
        std::string_view name;
        T value;
    };

    template<class T>
    struct CommandTable;

    template<>
    struct CommandTable<Command> {
        static constexpr auto entries = std::to_array<CommandEntry<Command>>({
            {"run", Command::run},
            {"check", Command::check},
            {"rule", Command::rule},
            {"endpoint", Command::endpoint},
            {"control", Command::control},
            {"state", Command::state},
            {"generate", Command::generate},
            {"tools", Command::tools},
            {"convert-config", Command::convert_config},
            {"provider", Command::provider},
            {"system-proxy", Command::system_proxy},
            {"service", Command::service},
        });
    };

    template<>
    struct CommandTable<RuleCommand> {
        static constexpr auto entries = std::to_array<CommandEntry<RuleCommand>>({
            {"convert", RuleCommand::convert},
            {"merge", RuleCommand::merge},
            {"explain", RuleCommand::explain},
            {"fetch", RuleCommand::fetch},
            {"watch", RuleCommand::watch},
        });
    };

    template<class T>
    auto command(std::string_view text) -> std::optional<T> {
        for (const auto& entry : CommandTable<T>::entries) {
            if (text == entry.name) return entry.value;
        }
        return {};
    }

    template<class T>
    auto list_commands(std::ostream& out) -> void {
        for (const auto& entry : CommandTable<T>::entries) {
            out << "  " << entry.name << '\n';
        }
    }

    auto help(std::ostream& out) -> void {
        out << "usage: nexus [-D <dir>] <command> [arguments]\ncommands:\n";
        list_commands<Command>(out);
        out << "Use nexus <command> --help for details.\n";
    }

    auto rule(int argc, char** argv) -> int {
        if (argc == 1 || (argc == 2 && std::string_view(argv[1]) == "--help")) {
            auto& out = argc == 1 ? std::cerr : std::cout;
            out << "usage: nexus rule <command> [arguments]\ncommands:\n";
            list_commands<RuleCommand>(out);
            return argc == 1 ? 2 : 0;
        }
        auto selected = command<RuleCommand>(argv[1]);
        if (!selected) { std::cerr << "unknown rule command: " << argv[1] << '\n'; return 2; }
        switch (*selected) {
        case RuleCommand::convert: return nexus_rule_convert(argc - 1, argv + 1);
        case RuleCommand::merge: return nexus_rule_merge(argc - 1, argv + 1);
        case RuleCommand::explain: return nexus_rule_explain(argc - 1, argv + 1);
        case RuleCommand::fetch: return nexus_rule_fetch(argc - 1, argv + 1);
        case RuleCommand::watch: return nexus_rule_watch(argc - 1, argv + 1);
        }
        return 2;
    }
}

int main(int argc, char** argv) {
    cli::ensure_http_fetchers_registered();
    if (argc==2 && std::string_view(argv[1])=="--internal-tun-network-owner")
        return cli::tun_enabled::run_strict_tun_owner();
    while (argc>=2 && (std::string_view(argv[1])=="-D" || std::string_view(argv[1])=="--directory")) {
        if (argc<3) { std::cerr << "-D/--directory requires a directory path\n"; return 2; }
        std::error_code ec;
        auto dir=std::filesystem::canonical(argv[2],ec);
        if (ec || !std::filesystem::is_directory(dir,ec)) {
            std::cerr << "working directory is not accessible: " << argv[2] << '\n';
            return 2;
        }
        cli::set_working_directory(std::move(dir));
        argc-=2; argv+=2;
    }
    if (argc == 1 || (argc == 2 && std::string_view(argv[1]) == "--help")) {
        help(argc == 1 ? std::cerr : std::cout);
        return argc == 1 ? 2 : 0;
    }
    auto selected = command<Command>(argv[1]);
    if (!selected) { std::cerr << "unknown command: " << argv[1] << '\n'; help(std::cerr); return 2; }
    switch (*selected) {
    case Command::state: return nexus_state(argc-1,argv+1);
    case Command::control: return cli::run_control(argc-1,argv+1);
    case Command::run: return nexus_run(argc - 1, argv + 1);
    case Command::check: return nexus_check(argc - 1, argv + 1);
    case Command::rule: return rule(argc - 1, argv + 1);
    case Command::endpoint: return cli::endpoint::run(argc-1,argv+1);
    case Command::generate: return cli::nexus_generate(argc-1,argv+1);
    case Command::tools: return cli::nexus_tools(argc-1,argv+1);
    case Command::convert_config: return nexus_convert_config(argc-1,argv+1);
    case Command::provider: return nexus_provider(argc-1,argv+1);
    case Command::system_proxy: return nexus_system_proxy(argc-1,argv+1);
    case Command::service: return nexus_service(argc-1,argv+1);
    }
    return 2;
}
