import std;
import cli.endpoint;
import cli.control;
import cli.route_files;
import cli.tun_enabled;
import cli.gen_tools;
import encoding.json;

auto nexus_run(int argc, char** argv) -> int;
auto nexus_check(int argc, char** argv) -> int;
auto nexus_rule_explain(int argc,char** argv) -> int;
auto nexus_rule_convert(int argc, char** argv) -> int;
auto nexus_rule_merge(int argc, char** argv) -> int;
auto nexus_rule_fetch(int argc, char** argv) -> int;
auto nexus_state(int argc, char** argv) -> int;
auto nexus_rule_watch(int argc, char** argv) -> int;
auto nexus_convert_config(int argc, char** argv) -> int;
auto nexus_workspace(int argc, char** argv) -> int;
auto nexus_provider(int argc, char** argv) -> int;
auto nexus_system_proxy(int argc, char** argv) -> int;
auto nexus_service(int argc, char** argv) -> int;

namespace {
    enum class Command { run, check, rule, endpoint, control, state, generate, tools, convert_config, workspace, provider, system_proxy, service, version };
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
            {"workspace", Command::workspace},
            {"provider", Command::provider},
            {"system-proxy", Command::system_proxy},
            {"service", Command::service},
            {"version", Command::version},
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
        out << "usage: nexus [-D <dir>] <command> [arguments]\n"
            << "       nexus --version | -V | version [--json]\ncommands:\n";
        list_commands<Command>(out);
        out << "Use nexus <command> --help for details.\n";
    }

    auto print_version(int argc, char** argv) -> int {
        bool as_json = false;
        for (int i = 1; i < argc; ++i) {
            std::string_view arg(argv[i]);
            if (arg == "--json") as_json = true;
            else if (arg == "--help") {
                std::cout << "usage: nexus version [--json]\n       nexus --version | -V [--json]\n";
                return 0;
            } else {
                std::cerr << "version: unknown option: " << arg << '\n';
                return 2;
            }
        }
        constexpr std::string_view kVersion = "0.1.0";
#if defined(__linux__)
        constexpr std::string_view kOs = "linux";
#elif defined(__APPLE__)
        constexpr std::string_view kOs = "darwin";
#elif defined(_WIN32)
        constexpr std::string_view kOs = "windows";
#elif defined(__FreeBSD__)
        constexpr std::string_view kOs = "freebsd";
#else
        constexpr std::string_view kOs = "unknown";
#endif
#if defined(__x86_64__) || defined(_M_X64)
        constexpr std::string_view kArch = "x86_64";
#elif defined(__aarch64__) || defined(_M_ARM64)
        constexpr std::string_view kArch = "aarch64";
#elif defined(__riscv) && (__riscv_xlen == 64)
        constexpr std::string_view kArch = "riscv64";
#elif defined(__arm__) || defined(_M_ARM)
        constexpr std::string_view kArch = "arm";
#else
        constexpr std::string_view kArch = "unknown";
#endif
#if defined(__APPLE__) || defined(__FreeBSD__)
        constexpr std::string_view kBackend = "kqueue";
#elif defined(_WIN32)
        constexpr std::string_view kBackend = "iocp";
#elif defined(BOOST_COROSIO_HAVE_LIBURING) && BOOST_COROSIO_HAVE_LIBURING
        constexpr std::string_view kBackend = "io_uring";
#elif defined(__linux__)
        constexpr std::string_view kBackend = "epoll";
#else
        constexpr std::string_view kBackend = "unknown";
#endif
#if defined(__clang_version__)
        constexpr std::string_view kCompiler = "clang " __clang_version__;
#elif defined(__GNUC__)
        constexpr std::string_view kCompiler = "gcc";
#elif defined(_MSC_VER)
        constexpr std::string_view kCompiler = "msvc";
#else
        constexpr std::string_view kCompiler = "unknown";
#endif
        std::vector<std::string_view> features;
#if defined(BOOST_COROSIO_HAVE_LIBURING) && BOOST_COROSIO_HAVE_LIBURING
        features.push_back("io-uring");
#endif
#ifdef NEXUS_ENABLE_CONTROL_HTTP
        features.push_back("control-http");
#endif
#ifdef NEXUS_ENABLE_FAKEIP
        features.push_back("dns-fakeip");
#endif
#ifdef NEXUS_ENABLE_TUN
        features.push_back("tun-inbound");
#endif
#ifdef NEXUS_ENABLE_VLESS
        features.push_back("vless");
#endif
#ifdef NEXUS_ENABLE_TROJAN
        features.push_back("trojan");
#endif
#ifdef NEXUS_ENABLE_ANYTLS
        features.push_back("anytls");
#endif
#ifdef NEXUS_ENABLE_HY2
        features.push_back("hy2");
#endif
#ifdef NEXUS_ENABLE_TUIC
        features.push_back("tuic");
#endif
#ifdef NEXUS_ENABLE_MASQUE
        features.push_back("masque");
#endif
#ifdef NEXUS_ENABLE_MASQUE_OUTBOUND
        features.push_back("masque-outbound");
#endif
#ifdef NEXUS_ENABLE_WIREGUARD
        features.push_back("wireguard");
#endif
#ifdef NEXUS_ENABLE_SHADOWTLS
        features.push_back("shadowtls");
#endif
#ifdef NEXUS_ENABLE_SSH
        features.push_back("ssh");
#endif
#ifdef NEXUS_ENABLE_NAIVE
        features.push_back("naive");
#endif
#ifdef NEXUS_ENABLE_KTLS
        features.push_back("ktls");
#endif
#ifdef NEXUS_ENABLE_NTP
        features.push_back("ntp");
#endif
#ifdef NEXUS_ENABLE_OPENVPN
        features.push_back("openvpn");
#endif
#ifdef NEXUS_ENABLE_OPENCONNECT
        features.push_back("openconnect");
#endif
#ifdef NEXUS_ENABLE_TOR
        features.push_back("tor");
#endif
#ifdef NEXUS_ENABLE_GRPC_VLESS
        features.push_back("grpc-vless");
#endif
#ifdef NEXUS_ENABLE_XHTTP_VLESS
        features.push_back("xhttp-vless");
#endif
#ifdef NEXUS_DNS_RESPONSE
        features.push_back("dns-response");
#endif
#ifdef NEXUS_ENABLE_SOCKS_UDP
        features.push_back("socks-udp");
#endif
        if (as_json) {
            std::string fl = "[";
            for (std::size_t i = 0; i < features.size(); ++i) {
                if (i) fl.push_back(',');
                fl += encoding::json_quote(features[i]);
            }
            fl.push_back(']');
            std::cout << std::format(
                "{{\"version\":{},\"os\":{},\"arch\":{},\"backend\":{},\"cpp_standard\":\"C++26\",\"cplusplus\":{},\"compiler\":{},\"features\":{}}}\n",
                encoding::json_quote(kVersion), encoding::json_quote(kOs), encoding::json_quote(kArch),
                encoding::json_quote(kBackend), static_cast<long>(__cplusplus),
                encoding::json_quote(kCompiler), fl);
            return 0;
        }
        std::cout << std::format("nexus {} ({}/{})\nbackend: {}\nstandard: C++26 ({})\ncompiler: {}\nfeatures:",
            kVersion, kOs, kArch, kBackend, static_cast<long>(__cplusplus), kCompiler);
        if (features.empty()) std::cout << " none";
        else for (auto f : features) std::cout << ' ' << f;
        std::cout << '\n';
        return 0;
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
    if (argc >= 2 && (std::string_view(argv[1]) == "--version" || std::string_view(argv[1]) == "-V")) {
        return print_version(argc - 1, argv + 1);
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
    case Command::workspace: return nexus_workspace(argc-1,argv+1);
    case Command::provider: return nexus_provider(argc-1,argv+1);
    case Command::system_proxy: return nexus_system_proxy(argc-1,argv+1);
    case Command::service: return nexus_service(argc-1,argv+1);
    case Command::version: return print_version(argc - 1, argv + 1);
    }
    return 2;
}
