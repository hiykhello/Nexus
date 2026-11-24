import std;
import cli.proxy_providers;
import cli.route_files;
import config;

namespace {
    constexpr std::string_view usage =
        "usage: nexus provider inspect --config|-c <file> | --config-dir|-C <dir> [--offline-cache]\n"
        "       nexus provider sync --config|-c <file> | --config-dir|-C <dir> [--offline-cache] [-o <out.kdl>]\n";

    auto print_summaries(std::vector<cli::ProviderSummary> const& list) -> void {
        if (list.empty()) { std::cout << "no proxy-providers configured\n"; return; }
        for (auto const& p : list) {
            std::cout << "provider=" << p.name
                      << " type=" << (p.type == config::ProxyProviderType::http ? "http" : "file")
                      << " proxies=" << p.proxy_count;
            if (!p.etag.empty()) std::cout << " etag=" << p.etag;
            if (p.userinfo) {
                if (p.userinfo->upload) std::cout << " upload=" << *p.userinfo->upload;
                if (p.userinfo->download) std::cout << " download=" << *p.userinfo->download;
                if (p.userinfo->total) std::cout << " total=" << *p.userinfo->total;
                if (p.userinfo->expire) std::cout << " expire=" << *p.userinfo->expire;
            }
            std::cout << '\n';
            for (auto const& w : p.warnings) std::cerr << "warning: " << w << '\n';
        }
    }
}

auto nexus_provider(int argc, char** argv) -> int {
    if (argc == 1 || (argc == 2 && std::string_view(argv[1]) == "--help")) {
        (argc == 1 ? std::cerr : std::cout) << usage;
        return argc == 1 ? 2 : 0;
    }
    std::string_view sub(argv[1]);
    if (sub != "inspect" && sub != "sync") {
        std::cerr << "unknown provider command: " << sub << '\n' << usage;
        return 2;
    }
    std::string cfg_path, out_path;
    bool is_dir = false, offline = false;
    for (int i = 2; i < argc; ++i) {
        std::string_view a(argv[i]);
        if (a == "--offline-cache") { offline = true; continue; }
        if ((a == "-c" || a == "--config" || a == "-C" || a == "--config-dir") && i + 1 < argc) {
            is_dir = (a == "-C" || a == "--config-dir");
            cfg_path = argv[++i];
        } else if ((a == "-o" || a == "--output") && i + 1 < argc && sub == "sync") {
            out_path = argv[++i];
        } else {
            std::cerr << "invalid option: " << a << '\n' << usage;
            return 2;
        }
    }
    if (cfg_path.empty()) { std::cerr << usage; return 2; }
    auto raw = cli::read_config_source(cfg_path, is_dir);
    if (!raw) { std::cerr << "provider: " << raw.error() << '\n'; return 1; }
    cli::ProxyProviderManager mgr;
    auto expanded = mgr.prepare_initial(*raw, cfg_path, offline);
    if (!expanded) { std::cerr << "provider: " << expanded.error() << '\n'; return 1; }
    print_summaries(mgr.summaries());
    if (sub == "sync" && !out_path.empty()) {
        std::ofstream out(out_path, std::ios::out | std::ios::trunc);
        if (!out) { std::cerr << "provider: cannot write " << out_path << '\n'; return 1; }
        out << *expanded;
        out.close();
        if (!out) { std::cerr << "provider: write failed\n"; return 1; }
    }
    return 0;
}
