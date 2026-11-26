export module cli.gen_tools;
import std;

export namespace cli {
    struct EchKeypairOutput {
        std::string private_key_base64;
        std::string config_list_base64;
        std::vector<std::uint8_t> config_list_wire;
    };

    [[nodiscard]] auto generate_uuid() -> std::expected<std::string, std::string>;
    [[nodiscard]] auto generate_x25519_keypair(bool url_safe = false)
        -> std::expected<std::pair<std::string, std::string>, std::string>;
    [[nodiscard]] auto generate_ss2022_key(std::size_t key_bytes = 32)
        -> std::expected<std::string, std::string>;
    [[nodiscard]] auto generate_self_signed_tls(std::string_view common_name = "localhost", int days = 365)
        -> std::expected<std::pair<std::string, std::string>, std::string>;
    [[nodiscard]] auto generate_ech_keypair(std::string_view public_name = "cloudflare-ech.com",
        std::uint8_t config_id = 1) -> std::expected<EchKeypairOutput, std::string>;

    [[nodiscard]] auto probe_tcp_connect(std::string_view host, std::uint16_t port, std::uint32_t timeout_ms = 5000)
        -> std::expected<double, std::string>;
    [[nodiscard]] auto probe_stun_server(std::string_view host, std::uint16_t port, std::uint32_t timeout_ms = 5000)
        -> std::expected<std::string, std::string>;

    struct UdpProbeOptions {
        std::string kind;
        std::string target;
        std::string socks5_proxy;
        std::uint32_t timeout_ms = 3000;
        std::uint32_t attempts = 2;
    };

    struct UdpProbeResult {
        bool ok = false;
        std::string kind;
        bool via_socks5 = false;
        std::uint64_t rtt_ms = 0;
        std::uint32_t attempts = 0;
        std::string detail;
        std::string error;
    };

    [[nodiscard]] auto run_udp_probe(UdpProbeOptions const& opts) -> UdpProbeResult;
    [[nodiscard]] auto serialize_udp_probe_json(UdpProbeResult const& res) -> std::string;
    auto nexus_tools_udp_probe(int argc, char** argv) -> int;
    auto nexus_tools_fetch(int argc, char** argv) -> int;

    auto nexus_generate(int argc, char** argv) -> int;
    auto nexus_tools(int argc, char** argv) -> int;
}
