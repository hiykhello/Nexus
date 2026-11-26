// Pure URL/argument parser and result formatters for `nexus tools fetch`.
export module cli.tools_fetch;
import std;
import encoding.json;
import http.connect;
import http.header;

export namespace cli::fetch {
    enum class HttpVersionPref : std::uint8_t { automatic, http1_1, http2, http3 };

    struct FetchHeader {
        std::string name;
        std::string value;
    };

    struct FetchOptions {
        std::string url;
        std::string config_path;
        std::string outbound;
        std::string method{"GET"};
        std::string body;
        std::vector<FetchHeader> headers;
        HttpVersionPref http_pref = HttpVersionPref::automatic;
        std::uint32_t timeout_ms = 10000;
        std::size_t max_body_preview = 2048;
        std::string ca_file;
        bool json = false;
        bool help = false;
    };

    struct ParsedFetchUrl {
        bool https = false;
        http::ConnectRequest destination{};
        std::string authority;
        std::string target;
    };

    struct FetchResult {
        std::string url;
        std::string method;
        std::string outbound;
        std::string protocol;
        std::string resolved_ip;
        unsigned status = 0;
        double ttfb_ms = 0.0;
        double total_ms = 0.0;
        std::size_t body_bytes = 0;
        std::vector<FetchHeader> headers;
        std::string body_preview;
        bool body_truncated = false;
    };

    inline constexpr std::string_view kFetchUsage =
        "usage: nexus tools fetch <url> [options]\n"
        "options:\n"
        "  -c, --config <path>          Optional KDL config file (default: direct)\n"
        "  -o, --outbound <tag>         Route through configured outbound or group\n"
        "  -X, --method <GET|HEAD|POST> HTTP method (default: GET)\n"
        "  -d, --body <text>            Request body (for POST)\n"
        "  -H, --header <\"K: V\">        Extra request header (repeatable)\n"
        "      --http <auto|1.1|2|3>    HTTP protocol preference (default: auto)\n"
        "      --timeout-ms <N>         Request timeout in milliseconds (default: 10000)\n"
        "      --max-body-preview <N>   Max body preview bytes (default: 2048)\n"
        "      --ca-file <path>         Custom CA bundle for HTTPS verification\n"
        "      --json                   Emit structured JSON output\n";

    inline auto parse_fetch_url(std::string_view text) -> std::expected<ParsedFetchUrl, std::string> {
        if (text.empty() || std::ranges::any_of(text, [](unsigned char c) {
            return c <= 0x20 || c >= 0x7f || c == '#' || c == '\\';
        })) return std::unexpected("invalid URL");
        bool https = false;
        if (text.starts_with("https://")) { https = true; text.remove_prefix(8); }
        else if (text.starts_with("http://")) { https = false; text.remove_prefix(7); }
        else return std::unexpected("URL must start with http:// or https://");

        auto sep = text.find_first_of("/?");
        auto authority = text.substr(0, sep);
        if (authority.empty() || authority.contains('@')) return std::unexpected("invalid URL authority");
        std::string addr(authority);
        if (authority.ends_with(']') || !authority.contains(':'))
            addr += https ? ":443" : ":80";
        auto dest = http::parse_destination_authority(addr);
        if (dest.status != http::ConnectStatus::accepted)
            return std::unexpected("invalid URL host or port");
        std::string target = "/";
        if (sep != std::string_view::npos) {
            if (text[sep] == '/') target.clear();
            target += text.substr(sep);
        }
        return ParsedFetchUrl{https, std::move(dest), std::string(authority), std::move(target)};
    }

    inline auto parse_header_line(std::string_view line) -> std::expected<FetchHeader, std::string> {
        auto colon = line.find(':');
        if (colon == std::string_view::npos) return std::unexpected("header must be in \"Name: Value\" form");
        auto name = line.substr(0, colon);
        auto value = line.substr(colon + 1);
        while (!name.empty() && (name.back() == ' ' || name.back() == '\t')) name.remove_suffix(1);
        while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.remove_prefix(1);
        while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.remove_suffix(1);
        if (name.empty() || !std::ranges::all_of(name, [](char c) { return http::header_token(c); }))
            return std::unexpected("invalid header name");
        if (!http::valid_header_field_value(value))
            return std::unexpected("invalid header value");
        return FetchHeader{std::string(name), std::string(value)};
    }

    inline auto parse_fetch_args(int argc, char** argv) -> std::expected<FetchOptions, std::string> {
        FetchOptions opts{};
        auto parse_u64 = [](std::string_view s) -> std::optional<std::uint64_t> {
            std::uint64_t v = 0;
            auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
            if (ec != std::errc{} || end != s.data() + s.size()) return std::nullopt;
            return v;
        };
        for (int i = 1; i < argc; ++i) {
            std::string_view arg(argv[i]);
            if (arg == "--help" || arg == "-h") { opts.help = true; return opts; }
            if (arg == "--json") { opts.json = true; continue; }
            auto need_val = [&](std::string_view flag) -> std::expected<std::string_view, std::string> {
                if (i + 1 >= argc) return std::unexpected(std::format("{} requires a value", flag));
                return std::string_view(argv[++i]);
            };
            if (arg == "--config" || arg == "-c") {
                auto v = need_val(arg); if (!v) return std::unexpected(v.error());
                opts.config_path = std::string(*v);
            } else if (arg == "--outbound" || arg == "-o") {
                auto v = need_val(arg); if (!v) return std::unexpected(v.error());
                opts.outbound = std::string(*v);
            } else if (arg == "--method" || arg == "-X") {
                auto v = need_val(arg); if (!v) return std::unexpected(v.error());
                std::string m(*v);
                for (char& c : m) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
                if (m != "GET" && m != "HEAD" && m != "POST")
                    return std::unexpected("--method must be GET, HEAD, or POST");
                opts.method = std::move(m);
            } else if (arg == "--body" || arg == "-d") {
                auto v = need_val(arg); if (!v) return std::unexpected(v.error());
                opts.body = std::string(*v);
            } else if (arg == "--header" || arg == "-H") {
                auto v = need_val(arg); if (!v) return std::unexpected(v.error());
                auto hdr = parse_header_line(*v); if (!hdr) return std::unexpected(hdr.error());
                if (opts.headers.size() >= 64) return std::unexpected("too many --header arguments");
                opts.headers.push_back(std::move(*hdr));
            } else if (arg == "--http") {
                auto v = need_val(arg); if (!v) return std::unexpected(v.error());
                if (*v == "auto") opts.http_pref = HttpVersionPref::automatic;
                else if (*v == "1.1" || *v == "1") opts.http_pref = HttpVersionPref::http1_1;
                else if (*v == "2") opts.http_pref = HttpVersionPref::http2;
                else if (*v == "3") opts.http_pref = HttpVersionPref::http3;
                else return std::unexpected("--http must be auto, 1.1, 2, or 3");
            } else if (arg == "--timeout-ms") {
                auto v = need_val(arg); if (!v) return std::unexpected(v.error());
                auto n = parse_u64(*v);
                if (!n || *n < 100 || *n > 120000) return std::unexpected("--timeout-ms must be 100..120000");
                opts.timeout_ms = static_cast<std::uint32_t>(*n);
            } else if (arg == "--max-body-preview") {
                auto v = need_val(arg); if (!v) return std::unexpected(v.error());
                auto n = parse_u64(*v);
                if (!n || *n > 65536) return std::unexpected("--max-body-preview must be 0..65536");
                opts.max_body_preview = static_cast<std::size_t>(*n);
            } else if (arg == "--ca-file") {
                auto v = need_val(arg); if (!v) return std::unexpected(v.error());
                opts.ca_file = std::string(*v);
            } else if (arg.starts_with('-')) {
                return std::unexpected(std::format("unknown option: {}", arg));
            } else if (opts.url.empty()) {
                opts.url = std::string(arg);
            } else {
                return std::unexpected(std::format("unexpected positional argument: {}", arg));
            }
        }
        if (opts.url.empty()) return std::unexpected("missing required <url>");
        if (!opts.outbound.empty() && opts.config_path.empty())
            return std::unexpected("--outbound requires --config <path>");
        if (!opts.body.empty() && opts.method == "HEAD")
            return std::unexpected("--body cannot be used with --method HEAD");
        return opts;
    }

    inline auto format_fetch_json(FetchResult const& r) -> std::string {
        std::string hdrs = "[";
        for (std::size_t i = 0; i < r.headers.size(); ++i) {
            if (i) hdrs.push_back(',');
            hdrs += std::format("{{\"name\":{},\"value\":{}}}",
                encoding::json_quote(r.headers[i].name), encoding::json_quote(r.headers[i].value));
        }
        hdrs.push_back(']');
        return std::format(
            "{{\"url\":{},\"method\":{},\"outbound\":{},\"protocol\":{},\"resolved_ip\":{},"
            "\"status\":{},\"ttfb_ms\":{:.2f},\"total_ms\":{:.2f},\"body_bytes\":{},"
            "\"body_truncated\":{},\"headers\":{},\"body_preview\":{}}}\n",
            encoding::json_quote(r.url), encoding::json_quote(r.method),
            encoding::json_quote(r.outbound), encoding::json_quote(r.protocol),
            encoding::json_quote(r.resolved_ip), r.status, r.ttfb_ms, r.total_ms,
            r.body_bytes, r.body_truncated ? "true" : "false", hdrs,
            encoding::json_quote(r.body_preview));
    }

    inline auto format_fetch_text(FetchResult const& r) -> std::string {
        std::string out = std::format(
            "URL: {}\nMethod: {}\nOutbound: {}\nProtocol: {}\nResolved IP: {}\n"
            "Status: {}\nTTFB: {:.2f} ms\nTotal: {:.2f} ms\nBody Bytes: {}\n",
            r.url, r.method, r.outbound, r.protocol,
            r.resolved_ip.empty() ? "n/a" : r.resolved_ip,
            r.status, r.ttfb_ms, r.total_ms, r.body_bytes);
        if (!r.headers.empty()) {
            out += "Headers:\n";
            for (auto const& h : r.headers) out += std::format("  {}: {}\n", h.name, h.value);
        }
        if (!r.body_preview.empty()) {
            out += std::format("Body Preview ({} bytes{}):\n{}\n",
                r.body_preview.size(), r.body_truncated ? ", truncated" : "", r.body_preview);
        }
        return out;
    }

    [[nodiscard]] auto run_fetch(FetchOptions const& opts) -> std::expected<FetchResult, std::string>;
    auto tools_fetch_main(int argc, char** argv) -> int;
}
