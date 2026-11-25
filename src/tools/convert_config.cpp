import std;
import provider;
import rulefile;

namespace {
    constexpr std::string_view usage =
        "usage: nexus convert-config [--emit-nodes-json] [--from auto|uri|base64|clash|sing-box|sip008] "
        "[--secrets-dir <dir>] [--inline-placeholders] [--inbound-listen <host:port>] "
        "[--inbound-type mixed|socks5|http] [--default-group <name>] [--ca-file <path>] "
        "[--include <regex>] [--exclude <regex>] [--tag-prefix <prefix>] "
        "[-o <output>] <input|->\n";

    auto parse_format(std::string_view s) -> std::optional<provider::ProviderFormat> {
        using F = provider::ProviderFormat;
        if (s == "auto") return F::auto_detect;
        if (s == "uri" || s == "uri-list") return F::uri_list;
        if (s == "base64") return F::base64_uri;
        if (s == "clash" || s == "clash-yaml") return F::clash_yaml;
        if (s == "sing-box" || s == "singbox" || s == "singbox-json") return F::singbox_json;
        if (s == "sip008") return F::sip008_json;
        return std::nullopt;
    }
}

auto nexus_convert_config(int argc, char** argv) -> int {
    if (argc == 1 || (argc == 2 && std::string_view(argv[1]) == "--help")) {
        (argc == 1 ? std::cerr : std::cout) << usage;
        return argc == 1 ? 2 : 0;
    }
    provider::ConvertOptions opts{};
    bool emit_nodes_json = false;
    std::string input_path, output_path;
    for (int i = 1; i < argc; ++i) {
        std::string_view arg(argv[i]);
        auto next = [&]() -> std::expected<std::string_view, int> {
            if (i + 1 >= argc) { std::cerr << "missing value for " << arg << '\n'; return std::unexpected(2); }
            return std::string_view(argv[++i]);
        };
        if (arg == "--emit-nodes-json") emit_nodes_json = true;
        else if (arg == "--inline-placeholders") opts.inline_placeholders = true;
        else if (arg == "--from") {
            auto v = next(); if (!v) return v.error();
            auto f = parse_format(*v);
            if (!f) { std::cerr << "unsupported --from format: " << *v << '\n'; return 2; }
            opts.format = *f;
        } else if (arg == "--secrets-dir") {
            auto v = next(); if (!v) return v.error();
            opts.secrets_dir = std::string(*v);
        } else if (arg == "--inbound-listen") {
            auto v = next(); if (!v) return v.error();
            opts.inbound_listen = std::string(*v);
        } else if (arg == "--inbound-type") {
            auto v = next(); if (!v) return v.error();
            opts.inbound_type = std::string(*v);
        } else if (arg == "--default-group") {
            auto v = next(); if (!v) return v.error();
            opts.default_group = std::string(*v);
        } else if (arg == "--ca-file") {
            auto v = next(); if (!v) return v.error();
            opts.ca_file = std::string(*v);
        } else if (arg == "--include") {
            auto v = next(); if (!v) return v.error();
            opts.filter.include_regex = std::string(*v);
        } else if (arg == "--exclude") {
            auto v = next(); if (!v) return v.error();
            opts.filter.exclude_regex = std::string(*v);
        } else if (arg == "--tag-prefix") {
            auto v = next(); if (!v) return v.error();
            opts.filter.tag_prefix = std::string(*v);
        } else if (arg == "-o" || arg == "--output") {
            auto v = next(); if (!v) return v.error();
            output_path = std::string(*v);
        } else if (!arg.starts_with('-') || arg == "-") {
            if (!input_path.empty()) { std::cerr << "multiple input paths specified\n"; return 2; }
            input_path = std::string(arg);
        } else {
            std::cerr << "unknown option: " << arg << '\n' << usage;
            return 2;
        }
    }
    if (input_path.empty()) { std::cerr << usage; return 2; }
    std::string raw;
    if (input_path == "-") {
        constexpr std::size_t max_bytes = ::rulefile::max_file_bytes;
        std::array<char, 65536> buf{};
        while (std::cin) {
            std::cin.read(buf.data(), static_cast<std::streamsize>(buf.size()));
            auto got = static_cast<std::size_t>(std::cin.gcount());
            if (got == 0) break;
            if (raw.size() + got > max_bytes) {
                std::cerr << "convert-config: input exceeds maximum size\n";
                return 1;
            }
            raw.append(buf.data(), got);
        }
        if (std::cin.bad()) { std::cerr << "convert-config: failed reading stdin\n"; return 1; }
    } else {
        auto data = ::rulefile::read_regular_file(input_path);
        if (!data) { std::cerr << "convert-config: " << data.error() << '\n'; return 1; }
        raw = std::move(*data);
    }
    auto res = emit_nodes_json ? provider::convert_config_to_nodes_json(raw, opts)
                               : provider::convert_config_to_kdl(raw, opts);
    if (!res) { std::cerr << "convert-config: " << res.error() << '\n'; return 1; }
    for (auto const& w : res->second) std::cerr << "warning: " << w << '\n';
    if (output_path.empty() || output_path == "-") {
        std::cout << res->first;
    } else {
        std::ofstream out(output_path, std::ios::out | std::ios::trunc);
        if (!out) { std::cerr << "convert-config: cannot write " << output_path << '\n'; return 1; }
        out << res->first;
        out.close();
        if (!out) { std::cerr << "convert-config: write failed for " << output_path << '\n'; return 1; }
    }
    return 0;
}
