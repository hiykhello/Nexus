import std;
import platform.service_manager;

namespace {
    constexpr std::string_view usage =
        "usage:\n"
        "  nexus service install --config <path> [--name <name>] [--binary <path>] [--workdir <dir>] [--log <path>] [--user] [--output-dir <dir>] [--render-target systemd|launchd|windows] [--dry-run]\n"
        "  nexus service uninstall [--name <name>] [--user] [--dry-run]\n"
        "  nexus service start|stop|restart|status [--name <name>] [--user] [--json]\n";

    auto state_name(platform::ServiceState st) noexcept -> std::string_view {
        switch (st) {
        case platform::ServiceState::not_installed: return "not-installed";
        case platform::ServiceState::stopped: return "stopped";
        case platform::ServiceState::running: return "running";
        case platform::ServiceState::unknown: return "unknown";
        }
        return "unknown";
    }

    auto default_binary_path() -> std::string {
        std::error_code ec;
        auto self = std::filesystem::read_symlink("/proc/self/exe", ec);
        if (!ec && !self.empty()) return self.string();
        return "/usr/bin/nexus";
    }
}

auto nexus_service(int argc, char** argv) -> int {
    if (argc == 1 || (argc == 2 && (std::string_view(argv[1]) == "--help" || std::string_view(argv[1]) == "-h"))) {
        (argc == 1 ? std::cerr : std::cout) << usage;
        return argc == 1 ? 2 : 0;
    }
    std::string_view sub(argv[1]);
    if (sub == "install") {
        platform::ServiceSpec spec{};
        spec.binary_path = default_binary_path();
        std::string output_dir;
        auto target = platform::ServiceTarget::native;
        bool dry_run = false;
        for (int i = 2; i < argc; ++i) {
            std::string_view a(argv[i]);
            auto next = [&]() -> std::expected<std::string_view, int> {
                if (i + 1 >= argc) { std::cerr << "missing value for " << a << '\n'; return std::unexpected(2); }
                return std::string_view(argv[++i]);
            };
            if (a == "--config" || a == "-c") { auto v = next(); if (!v) return v.error(); spec.config_path = std::string(*v); }
            else if (a == "--name") { auto v = next(); if (!v) return v.error(); spec.name = std::string(*v); }
            else if (a == "--binary") { auto v = next(); if (!v) return v.error(); spec.binary_path = std::string(*v); }
            else if (a == "--workdir") { auto v = next(); if (!v) return v.error(); spec.working_dir = std::string(*v); }
            else if (a == "--log") { auto v = next(); if (!v) return v.error(); spec.log_path = std::string(*v); }
            else if (a == "--description") { auto v = next(); if (!v) return v.error(); spec.description = std::string(*v); }
            else if (a == "--output-dir") { auto v = next(); if (!v) return v.error(); output_dir = std::string(*v); }
            else if (a == "--user") spec.user_scope = true;
            else if (a == "--dry-run") dry_run = true;
            else if (a == "--render-target") {
                auto v = next(); if (!v) return v.error();
                if (*v == "systemd") target = platform::ServiceTarget::systemd;
                else if (*v == "launchd") target = platform::ServiceTarget::launchd;
                else if (*v == "windows") target = platform::ServiceTarget::windows;
                else if (*v == "native") target = platform::ServiceTarget::native;
                else { std::cerr << "unsupported --render-target: " << *v << '\n'; return 2; }
            } else if (a == "--help" || a == "-h") { std::cout << usage; return 0; }
            else { std::cerr << "unknown option: " << a << '\n' << usage; return 2; }
        }
        if (dry_run && target != platform::ServiceTarget::native) {
            std::expected<std::string, std::string> rendered =
                target == platform::ServiceTarget::systemd ? platform::render_systemd_unit(spec) :
                target == platform::ServiceTarget::launchd ? platform::render_launchd_plist(spec) :
                platform::render_windows_service_command(spec);
            if (!rendered) { std::cerr << "service install: " << rendered.error() << '\n'; return 2; }
            std::cout << *rendered;
            if (!rendered->ends_with('\n')) std::cout << '\n';
            return 0;
        }
        auto res = platform::install_service(spec, output_dir, dry_run);
        if (!res) { std::cerr << "service install: " << res.error() << '\n'; return 1; }
        std::cout << *res;
        if (!res->ends_with('\n')) std::cout << '\n';
        return 0;
    }
    if (sub == "uninstall" || sub == "start" || sub == "stop" || sub == "restart" || sub == "status") {
        std::string name = "nexus";
        bool user_scope = false, dry_run = false, as_json = false;
        for (int i = 2; i < argc; ++i) {
            std::string_view a(argv[i]);
            if (a == "--name") {
                if (i + 1 >= argc) { std::cerr << "missing value for --name\n"; return 2; }
                name = argv[++i];
            } else if (a == "--user") user_scope = true;
            else if (a == "--dry-run" && sub == "uninstall") dry_run = true;
            else if (a == "--json" && sub == "status") as_json = true;
            else if (a == "--help" || a == "-h") { std::cout << usage; return 0; }
            else { std::cerr << "unknown option: " << a << '\n' << usage; return 2; }
        }
        if (sub == "status") {
            auto st = platform::query_service_status(name, user_scope);
            if (as_json) {
                std::cout << std::format(
                    "{{\"installed\":{},\"state\":\"{}\",\"backend\":\"{}\",\"unit_path\":\"{}\"}}\n",
                    st.installed ? "true" : "false", state_name(st.state), st.backend, st.unit_path);
            } else {
                std::cout << std::format("installed: {}\nstate: {}\nbackend: {}\nunit: {}\n",
                    st.installed ? "yes" : "no", state_name(st.state), st.backend, st.unit_path);
            }
            return 0;
        }
        auto res = sub == "uninstall"
            ? platform::uninstall_service(name, user_scope, dry_run)
            : platform::control_service(name, sub, user_scope);
        if (!res) { std::cerr << "service " << sub << ": " << res.error() << '\n'; return 1; }
        return 0;
    }
    std::cerr << "unknown service subcommand: " << sub << '\n' << usage;
    return 2;
}
