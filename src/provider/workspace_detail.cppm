// Internal helpers & shared state for the workspace compiler.
module provider.workspace_compose:detail;
import std;
import encoding.base64;
import encoding.hex;
import platform.ip_address;
import provider.workspace_types;

namespace provider::ws_detail {
    inline auto trim(std::string_view s) noexcept -> std::string_view {
        while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.remove_prefix(1);
        while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.remove_suffix(1);
        return s;
    }

    inline auto lower_ascii(std::string_view s) -> std::string {
        std::string out(s);
        for (char& c : out) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
        return out;
    }

    inline auto kdl_quote(std::string_view s) -> std::string {
        std::string out;
        out.reserve(s.size() + 2);
        out.push_back('"');
        for (char c : s) {
            if (c == '\\' || c == '"') out.push_back('\\');
            if (c != '\r' && c != '\n' && c != '\0') out.push_back(c);
        }
        out.push_back('"');
        return out;
    }

    inline auto json_quote(std::string_view s) -> std::string {
        std::string out;
        out.reserve(s.size() + 2);
        out.push_back('"');
        auto cont = [](unsigned char b) noexcept { return (b & 0xC0u) == 0x80u; };
        for (std::size_t i = 0; i < s.size();) {
            auto c = static_cast<unsigned char>(s[i]);
            if (c < 0x80u) {
                switch (c) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\b': out += "\\b"; break;
                case '\f': out += "\\f"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (c < 0x20u) out += std::format("\\u{:04x}", unsigned(c));
                    else out.push_back(static_cast<char>(c));
                    break;
                }
                ++i;
            } else if (c >= 0xC2u && c <= 0xDFu && i + 1 < s.size() && cont(static_cast<unsigned char>(s[i + 1]))) {
                out.append(s.data() + i, 2); i += 2;
            } else if (c >= 0xE0u && c <= 0xEFu && i + 2 < s.size()) {
                auto b1 = static_cast<unsigned char>(s[i + 1]), b2 = static_cast<unsigned char>(s[i + 2]);
                if (cont(b1) && cont(b2) && !(c == 0xE0u && b1 < 0xA0u) && !(c == 0xEDu && b1 >= 0xA0u)) {
                    out.append(s.data() + i, 3); i += 3;
                } else { out += "\\ufffd"; ++i; }
            } else if (c >= 0xF0u && c <= 0xF4u && i + 3 < s.size()) {
                auto b1 = static_cast<unsigned char>(s[i + 1]), b2 = static_cast<unsigned char>(s[i + 2]), b3 = static_cast<unsigned char>(s[i + 3]);
                if (cont(b1) && cont(b2) && cont(b3) && !(c == 0xF0u && b1 < 0x90u) && !(c == 0xF4u && b1 >= 0x90u)) {
                    out.append(s.data() + i, 4); i += 4;
                } else { out += "\\ufffd"; ++i; }
            } else { out += "\\ufffd"; ++i; }
        }
        out.push_back('"');
        return out;
    }

    inline auto sha256_hex_16(std::string_view input) -> std::string {
        static constexpr std::array<std::uint32_t, 64> K{
            0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
            0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
            0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
            0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
            0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
            0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
            0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
            0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
        };
        std::array<std::uint32_t, 8> h{0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
        std::vector<std::uint8_t> buf(input.begin(), input.end());
        std::uint64_t bit_len = static_cast<std::uint64_t>(buf.size()) * 8u;
        buf.push_back(0x80u);
        while ((buf.size() % 64u) != 56u) buf.push_back(0u);
        for (int i = 7; i >= 0; --i) buf.push_back(static_cast<std::uint8_t>((bit_len >> (i * 8)) & 0xffu));
        auto rotr = [](std::uint32_t x, unsigned n) noexcept { return (x >> n) | (x << (32u - n)); };
        for (std::size_t off = 0; off < buf.size(); off += 64u) {
            std::uint32_t w[64]{};
            for (int i = 0; i < 16; ++i)
                w[i] = (std::uint32_t(buf[off + i * 4]) << 24) | (std::uint32_t(buf[off + i * 4 + 1]) << 16) |
                       (std::uint32_t(buf[off + i * 4 + 2]) << 8) | std::uint32_t(buf[off + i * 4 + 3]);
            for (int i = 16; i < 64; ++i) {
                std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
                std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16] + s0 + w[i - 7] + s1;
            }
            auto [a, b, c, d, e, f, g, hh] = h;
            for (int i = 0; i < 64; ++i) {
                std::uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
                std::uint32_t ch = (e & f) ^ ((~e) & g);
                std::uint32_t t1 = hh + S1 + ch + K[i] + w[i];
                std::uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
                std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
                std::uint32_t t2 = S0 + maj;
                hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
            }
            h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
        }
        std::array<std::uint8_t, 8> prefix{};
        for (int i = 0; i < 2; ++i) {
            prefix[i * 4 + 0] = static_cast<std::uint8_t>((h[i] >> 24) & 0xffu);
            prefix[i * 4 + 1] = static_cast<std::uint8_t>((h[i] >> 16) & 0xffu);
            prefix[i * 4 + 2] = static_cast<std::uint8_t>((h[i] >> 8) & 0xffu);
            prefix[i * 4 + 3] = static_cast<std::uint8_t>(h[i] & 0xffu);
        }
        return encoding::hex_encode(prefix);
    }

    inline auto is_valid_hostname(std::string_view name) noexcept -> bool {
        if (name.empty() || name.size() > 253) return false;
        std::size_t start = 0;
        for (std::size_t i = 0; i <= name.size(); ++i) {
            if (i == name.size() || name[i] == '.') {
                if (i == start || i - start > 63 || name[start] == '-' || name[i - 1] == '-') return false;
                start = i + 1;
            } else {
                auto c = static_cast<unsigned char>(name[i]);
                if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-')) return false;
            }
        }
        return true;
    }

    inline auto is_loopback_host(std::string_view host) noexcept -> bool {
        auto l = lower_ascii(host);
        if (l == "localhost" || l == "::1") return true;
        if (auto ip = platform::parse_ip_address(l)) {
            if (ip->size == 4) return ip->bytes[0] == 127;
            return std::ranges::all_of(std::span(ip->bytes).first<15>(), [](auto b) { return b == 0; }) && ip->bytes[15] == 1;
        }
        return false;
    }

    inline auto sanitize_tag(std::string_view raw, std::string_view fallback) -> std::string {
        std::string out;
        for (unsigned char c : raw) {
            if (std::isalnum(c) || c == '-' || c == '_') out.push_back(static_cast<char>(c));
            else if (c == ' ' || c == '.' || c == '+' || c == '/') out.push_back('-');
        }
        while (!out.empty() && out.front() == '-') out.erase(out.begin());
        while (!out.empty() && out.back() == '-') out.pop_back();
        if (out.empty()) out = std::string(fallback);
        if (out.size() > 56) out.resize(56);
        if (out == "direct" || out == "block" || out == "proxy") out += "-node";
        return out;
    }

    inline auto normalize_reality_pbk(std::string_view pbk) -> std::optional<std::string> {
        if (pbk.size() == 64 && std::ranges::all_of(pbk, [](char c) { return encoding::hex_value(c) >= 0; }))
            return lower_ascii(pbk);
        if (auto raw = encoding::decode_base64_flexible(pbk); raw && raw->size() == 32)
            return encoding::hex_encode({reinterpret_cast<std::uint8_t const*>(raw->data()), raw->size()});
        return std::nullopt;
    }

    inline auto system_ca_path() -> std::string {
        for (std::string_view p : {"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem"}) {
            std::error_code ec;
            if (std::filesystem::is_regular_file(p, ec) && !ec) return std::string(p);
        }
        return {};
    }

    struct ComposeContext {
        Workspace const& ws;
        HostConfig const& host;
        WorkspaceComposeOptions const& opts;
        std::map<std::string, WorkspaceProfile const*, std::less<>> profile_by_id;
        std::map<std::string, WorkspaceSubscription const*, std::less<>> sub_by_id;
        std::map<std::string, WorkspaceRuleSetAsset const*, std::less<>> asset_by_tag;
        std::set<std::string> used_tags{"direct", "block", "proxy"};
        std::map<std::string, std::string> base_tag_for_id;
        std::vector<std::string> protect_domains;
        std::set<std::string> protect_domain_set;
        std::vector<std::string> warnings;
        std::vector<std::string> errors;
        std::vector<std::string> secret_files;
        std::set<std::string> secret_file_set;
        std::vector<std::string> created_secrets;
        std::vector<std::string> emitted_outbound_kdl;
        std::set<std::string> emitted_tags;
        std::size_t physical_outbound_count = 0;
        bool proxy_datagram_capable = true;
        bool fake_ip_active = false;
        bool dns_emitted = false;
        std::string resolved_ca_file;
        std::string direct_dns_primary;
        std::string remote_dns_primary;

        struct Checkpoint {
            std::size_t created_n, secret_n, outbound_n, protect_n, phys_n;
            bool dgram_capable;
        };

        auto checkpoint() const noexcept -> Checkpoint {
            return {created_secrets.size(), secret_files.size(), emitted_outbound_kdl.size(),
                    protect_domains.size(), physical_outbound_count, proxy_datagram_capable};
        }

        auto rollback_to(Checkpoint const& cp) noexcept -> void {
            std::error_code ec;
            while (created_secrets.size() > cp.created_n) {
                std::filesystem::remove(created_secrets.back(), ec);
                created_secrets.pop_back();
            }
            while (secret_files.size() > cp.secret_n) {
                secret_file_set.erase(secret_files.back());
                secret_files.pop_back();
            }
            emitted_outbound_kdl.resize(cp.outbound_n);
            while (protect_domains.size() > cp.protect_n) {
                protect_domain_set.erase(protect_domains.back());
                protect_domains.pop_back();
            }
            physical_outbound_count = cp.phys_n;
            proxy_datagram_capable = cp.dgram_capable;
        }

        auto alloc_tag(std::string_view preferred, std::string_view fallback) -> std::string {
            auto base = sanitize_tag(preferred, fallback);
            std::string candidate = base;
            for (unsigned n = 2; !used_tags.insert(candidate).second; ++n)
                candidate = base + "-" + std::to_string(n);
            return candidate;
        }

        auto tag_for_profile(WorkspaceProfile const& p) -> std::string {
            if (auto it = base_tag_for_id.find(p.id); it != base_tag_for_id.end()) return it->second;
            auto t = alloc_tag(!p.remarks.empty() ? p.remarks : p.id, "node");
            base_tag_for_id.emplace(p.id, t);
            return t;
        }

        auto note_protect_host(std::string_view host_str) -> void {
            auto h = lower_ascii(trim(host_str));
            if (h.empty() || platform::parse_ip_address(h) || is_loopback_host(h) || !is_valid_hostname(h)) return;
            if (protect_domain_set.insert(h).second) protect_domains.push_back(std::move(h));
        }

        auto write_hashed_secret(std::string_view kind, std::string_view content, std::string_view ext = ".secret")
            -> std::expected<std::string, std::string>;

        auto rollback_secrets() noexcept -> void {
            std::error_code ec;
            for (auto const& f : created_secrets) std::filesystem::remove(f, ec);
            created_secrets.clear();
            secret_files.clear();
            secret_file_set.clear();
        }
    };

    // Implemented in workspace_emit.cpp
    auto node_is_xhttp_vless(WorkspaceProfile const& p) noexcept -> bool;
    auto node_is_datagram_capable(WorkspaceNode const& n) noexcept -> bool;
    auto emit_node_outbound(ComposeContext& ctx, WorkspaceNode const& n, std::string_view tag,
                            std::string_view detour, bool note_datagram) -> std::expected<std::string, std::string>;

    // Implemented in workspace_host.cpp
    auto emit_direct_and_block(ComposeContext& ctx, std::ostringstream& out) -> void;
    auto emit_custom_outbound(ComposeContext& ctx, std::string_view raw_kdl, std::string_view tag,
                              std::string_view detour) -> std::expected<std::string, std::string>;
    auto emit_policy_group_outbound(ComposeContext& ctx, WorkspaceProfile const& p, std::string_view tag,
                                    std::vector<std::string> const& member_tags) -> std::string;
    auto emit_host_header(ComposeContext const& ctx, std::ostringstream& out) -> void;
    auto emit_host_inbounds(ComposeContext& ctx, std::ostringstream& out) -> std::expected<void, std::string>;
    auto compose_full_custom_kdl(ComposeContext& ctx, WorkspaceProfile const& active) -> std::expected<std::string, std::string>;
    auto apply_full_template(WorkspaceFullTemplate const& tmpl, std::string_view compiled_kdl)
        -> std::expected<std::string, std::string>;

    // Implemented in workspace_route_dns.cpp
    auto emit_routing_and_dns(ComposeContext& ctx, WorkspaceRoutingProfile const& rp,
                              std::map<std::string, std::string> const& rule_profile_tags,
                              std::ostringstream& routing_out, std::ostringstream& dns_out,
                              std::ostringstream& http_clients_out) -> std::expected<void, std::string>;
}
