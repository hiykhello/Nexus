// Dump actual Nexus TLS ClientHello wire bytes as JSON for offline browser fingerprint auditing.
import std;
import tls.fingerprint;
import tls.certificate_compression;

namespace {
    auto hex_encode(std::span<std::uint8_t const> bytes) -> std::string {
        static constexpr char kHex[] = "0123456789abcdef";
        std::string out;
        out.reserve(bytes.size() * 2);
        for (auto b : bytes) {
            out.push_back(kHex[b >> 4]);
            out.push_back(kHex[b & 0x0f]);
        }
        return out;
    }

    auto json_escape(std::string_view s) -> std::string {
        std::string out;
        out.reserve(s.size() + 2);
        out.push_back('"');
        for (char c : s) {
            if (c == '"' || c == '\\') out.push_back('\\');
            out.push_back(c);
        }
        out.push_back('"');
        return out;
    }

    auto split_csv(std::string_view csv) -> std::vector<std::string_view> {
        std::vector<std::string_view> out;
        while (!csv.empty()) {
            auto pos = csv.find(',');
            auto tok = pos == std::string_view::npos ? csv : csv.substr(0, pos);
            if (!tok.empty()) out.push_back(tok);
            if (pos == std::string_view::npos) break;
            csv.remove_prefix(pos + 1);
        }
        return out;
    }
}

auto main(int argc, char** argv) -> int {
    std::string_view only_profile;
    std::string_view transport_arg = "tcp";
    std::string_view group_arg = "hybrid";
    std::string_view sni = "example.com";
    std::string_view alpn_arg;
    bool real_ech = false;

    for (int i = 1; i < argc; ++i) {
        std::string_view arg = argv[i];
        auto next = [&](std::string_view flag) -> std::string_view {
            if (i + 1 >= argc) {
                std::println(std::cerr, "missing value for {}", flag);
                std::exit(2);
            }
            return argv[++i];
        };
        if (arg == "--profile") only_profile = next(arg);
        else if (arg == "--transport") transport_arg = next(arg);
        else if (arg == "--group") group_arg = next(arg);
        else if (arg == "--sni") sni = next(arg);
        else if (arg == "--alpn") alpn_arg = next(arg);
        else if (arg == "--real-ech") real_ech = true;
        else {
            std::println(std::cerr, "usage: utls-dump [--profile NAME] [--transport tcp|quic] [--group hybrid|x25519] [--sni HOST] [--alpn CSV] [--real-ech]");
            return 2;
        }
    }

    tls::HandshakeTransport transport = tls::HandshakeTransport::tcp;
    if (transport_arg == "quic") transport = tls::HandshakeTransport::quic;
    else if (transport_arg != "tcp") {
        std::println(std::cerr, "invalid --transport: {}", transport_arg);
        return 2;
    }

    std::uint16_t primary_group = 0x11ec;
    if (group_arg == "x25519") primary_group = 0x001d;
    else if (group_arg != "hybrid") {
        std::println(std::cerr, "invalid --group: {}", group_arg);
        return 2;
    }

    if (alpn_arg.empty()) alpn_arg = (transport == tls::HandshakeTransport::quic) ? "h3" : "h2,http/1.1";
    auto alpn = split_csv(alpn_arg);

    std::vector<tls::Fingerprint> profiles;
    if (!only_profile.empty()) {
        auto parsed = tls::parse_fingerprint(only_profile);
        if (!parsed) {
            std::println(std::cerr, "unknown --profile: {}", only_profile);
            return 2;
        }
        profiles.push_back(*parsed);
    } else {
        profiles = {
            tls::Fingerprint::chrome, tls::Fingerprint::edge,
            tls::Fingerprint::firefox, tls::Fingerprint::safari,
            tls::Fingerprint::ios, tls::Fingerprint::android,
        };
    }

    constexpr std::array<std::uint8_t, 3> quic_params{0x04, 0x01, 0x20};
    auto quic_opt = (transport == tls::HandshakeTransport::quic)
        ? std::optional<std::span<std::uint8_t const>>(quic_params)
        : std::nullopt;

    std::print("{{\"cert_compression_enabled\":{},\"transport\":{},\"group\":{},\"profiles\":[",
        tls::certificate_compression_enabled() ? "true" : "false",
        json_escape(transport_arg), json_escape(group_arg));

    for (std::size_t idx = 0; idx < profiles.size(); ++idx) {
        auto fp = profiles[idx];
        auto cfg = tls::make_profile_fingerprint_config(fp, primary_group, false, transport);
        auto res = tls::make_fingerprint_hello(sni, alpn, cfg, transport, quic_opt, {}, real_ech);
        if (!res) {
            std::println(std::cerr, "failed to build ClientHello for {}", tls::fingerprint_name(fp));
            return 1;
        }
        auto wire = res->hello.encode();
        if (!wire) {
            std::println(std::cerr, "failed to encode ClientHello for {}", tls::fingerprint_name(fp));
            return 1;
        }
        if (idx > 0) std::print(",");
        std::print("{{\"name\":{},\"baseline\":{},\"hello_hex\":{}}}",
            json_escape(tls::fingerprint_name(fp)),
            json_escape(tls::fingerprint_baseline(fp)),
            json_escape(hex_encode(*wire)));
    }
    std::println("]}}");
    return 0;
}
