module dns.dhcp_upstream;
import std;
import containers.inplace_vector;
import platform.ip_address;

namespace dns {
    namespace {
        auto trim(std::string_view s) noexcept -> std::string_view {
            while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r' || s.front() == ';')) s.remove_prefix(1);
            while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == ';')) s.remove_suffix(1);
            return s;
        }

        auto append_unique(containers::inplace_vector<DhcpServerEntry, 8>& out, platform::IpAddress addr, std::uint32_t ttl) -> void {
            for (auto const& e : out) {
                if (e.address.size == addr.size && std::ranges::equal(e.address.view(), addr.view())) return;
            }
            (void)out.try_emplace_back(DhcpServerEntry{addr, ttl});
        }

        auto parse_token_addresses(std::string_view list_text, std::uint32_t ttl, containers::inplace_vector<DhcpServerEntry, 8>& out) -> void {
            while (!list_text.empty()) {
                auto sep = list_text.find_first_of(", \t");
                auto tok = trim(sep == std::string_view::npos ? list_text : list_text.substr(0, sep));
                if (!tok.empty()) {
                    if (auto pct = tok.find('%'); pct != std::string_view::npos) tok = tok.substr(0, pct);
                    if (auto ip = platform::parse_ip_address(tok)) append_unique(out, *ip, ttl);
                }
                if (sep == std::string_view::npos) break;
                list_text.remove_prefix(sep + 1);
            }
        }
    }

    auto parse_dhcp_option6(std::span<std::uint8_t const> bytes, std::uint32_t lease_ttl_seconds)
        -> containers::inplace_vector<DhcpServerEntry, 8> {
        containers::inplace_vector<DhcpServerEntry, 8> out;
        if (bytes.size() < 4 || (bytes.size() % 4) != 0) return out;
        for (std::size_t off = 0; off < bytes.size(); off += 4) {
            platform::IpAddress ip{.size = 4};
            std::copy_n(bytes.begin() + off, 4, ip.bytes.begin());
            append_unique(out, ip, lease_ttl_seconds);
        }
        return out;
    }

    auto parse_dhcp_lease_text(std::string_view text) -> containers::inplace_vector<DhcpServerEntry, 8> {
        containers::inplace_vector<DhcpServerEntry, 8> out;
        std::uint32_t current_ttl = 3600;
        std::size_t pos = 0;
        while (pos < text.size()) {
            auto nl = text.find('\n', pos);
            auto line = trim(nl == std::string_view::npos ? text.substr(pos) : text.substr(pos, nl - pos));
            pos = (nl == std::string_view::npos) ? text.size() : (nl + 1);
            if (line.empty() || line.front() == '#') continue;

            if (line.starts_with("option domain-name-servers ")) {
                parse_token_addresses(line.substr(27), current_ttl, out);
            } else if (line.starts_with("DNS=")) {
                parse_token_addresses(line.substr(4), current_ttl, out);
            } else if (line.starts_with("nameserver ")) {
                parse_token_addresses(line.substr(11), current_ttl, out);
            } else if (line.starts_with("LIFETIME_SEC=")) {
                std::uint32_t sec = 0;
                auto v = line.substr(13);
                if (auto [p, ec] = std::from_chars(v.data(), v.data() + v.size(), sec); ec == std::errc{} && sec > 0)
                    current_ttl = sec;
            }
        }
        return out;
    }

    auto discover_dhcp_dns_servers(std::span<std::string_view const> candidate_paths)
        -> containers::inplace_vector<DhcpServerEntry, 8> {
        static constexpr std::array<std::string_view, 3> kDefaults{
            "/run/systemd/netif/leases",
            "/var/lib/dhcp/dhclient.leases",
            "/etc/resolv.conf",
        };
        static constexpr std::size_t kMaxLeaseFiles = 64;
        static constexpr std::size_t kMaxLeaseFileBytes = 1024 * 1024;
        auto paths = candidate_paths.empty() ? std::span<std::string_view const>(kDefaults) : candidate_paths;
        containers::inplace_vector<DhcpServerEntry, 8> out;
        for (auto raw_path : paths) {
            std::filesystem::path p(raw_path);
            std::error_code ec;
            auto merge_file = [&](std::filesystem::path const& file) {
                std::ifstream in(file, std::ios::binary);
                if (!in) return;
                std::string content(kMaxLeaseFileBytes + 1, '\0');
                in.read(content.data(), static_cast<std::streamsize>(content.size()));
                auto got = static_cast<std::size_t>(in.gcount());
                if (got == 0 || got > kMaxLeaseFileBytes) return;
                content.resize(got);
                for (auto const& e : parse_dhcp_lease_text(content)) append_unique(out, e.address, e.lease_ttl_seconds);
            };
            if (std::filesystem::is_directory(p, ec)) {
                std::size_t scanned = 0;
                for (auto const& ent : std::filesystem::directory_iterator(p, ec)) {
                    if (scanned >= kMaxLeaseFiles) break;
                    if (ent.is_regular_file(ec)) { ++scanned; merge_file(ent.path()); }
                }
            } else if (std::filesystem::is_regular_file(p, ec)) {
                merge_file(p);
            }
        }
        return out;
    }
}
