module;
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <iphlpapi.h>
#include <netioapi.h>
#pragma comment(lib, "iphlpapi.lib")
#else
#include <net/if.h>
#endif
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

        auto unquote(std::string_view s) noexcept -> std::string_view {
            s = trim(s);
            if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
                s.remove_prefix(1);
                s.remove_suffix(1);
            }
            return s;
        }

        auto is_all_digits(std::string_view s) noexcept -> bool {
            return !s.empty() && std::ranges::all_of(s, [](char c) { return c >= '0' && c <= '9'; });
        }

        auto append_unique(containers::inplace_vector<DhcpServerEntry, 8>& out, platform::IpAddress addr,
            std::uint32_t ttl, std::string_view scope = {}) -> void {
            std::string_view effective_scope = (addr.size == 16) ? scope : std::string_view{};
            for (auto const& e : out) {
                if (e.address.size == addr.size && std::ranges::equal(e.address.view(), addr.view()) &&
                    e.scope == effective_scope) {
                    return;
                }
            }
            (void)out.try_emplace_back(DhcpServerEntry{addr, ttl, std::string(effective_scope)});
        }

        auto parse_token_addresses(std::string_view list_text, std::uint32_t ttl,
            containers::inplace_vector<DhcpServerEntry, 8>& out) -> void {
            while (!list_text.empty()) {
                auto sep = list_text.find_first_of(", \t");
                auto tok = trim(sep == std::string_view::npos ? list_text : list_text.substr(0, sep));
                if (!tok.empty()) {
                    std::string_view zone;
                    if (auto pct = tok.find('%'); pct != std::string_view::npos) {
                        zone = tok.substr(pct + 1);
                        tok = tok.substr(0, pct);
                    }
                    if (auto ip = platform::parse_ip_address(tok)) {
                        append_unique(out, *ip, ttl, ip->size == 16 ? zone : std::string_view{});
                    }
                }
                if (sep == std::string_view::npos) break;
                list_text.remove_prefix(sep + 1);
            }
        }

        auto effective_entry_scope(DhcpServerEntry const& entry, std::string_view fallback_scope) noexcept -> std::string_view {
            if (entry.address.size != 16) return {};
            if (!entry.scope.empty()) return entry.scope;
            return is_ipv6_link_local(entry.address) ? fallback_scope : std::string_view{};
        }

        auto parse_lease_text_impl(std::string_view text, std::string_view interface_filter,
            bool allow_untagged_flat, std::string_view fallback_scope = {})
            -> containers::inplace_vector<DhcpServerEntry, 8> {
            containers::inplace_vector<DhcpServerEntry, 8> out;
            containers::inplace_vector<DhcpServerEntry, 8> flat_servers;
            struct BlockEntry {
                std::string iface;
                bool ipv6 = false;
                containers::inplace_vector<DhcpServerEntry, 8> servers;
            };
            std::vector<BlockEntry> latest_blocks;
            std::size_t block_depth = 0;
            bool block_ipv6 = false;
            std::string block_iface;
            std::string flat_iface;
            containers::inplace_vector<DhcpServerEntry, 8> block_servers;
            std::uint32_t current_ttl = 3600;
            std::size_t pos = 0;
            auto commit_block = [&] {
                if (!block_servers.empty()) {
                    auto it = std::ranges::find_if(latest_blocks, [&](BlockEntry const& entry) {
                        return entry.iface == block_iface && entry.ipv6 == block_ipv6;
                    });
                    if (it != latest_blocks.end()) it->servers = block_servers;
                    else latest_blocks.push_back({block_iface, block_ipv6, block_servers});
                }
                block_depth = 0;
                block_ipv6 = false;
                block_iface.clear();
                block_servers.clear();
            };
            auto update_depth = [&](std::string_view sv) {
                for (char c : sv) {
                    if (c == '{') ++block_depth;
                    else if (c == '}' && block_depth > 0) --block_depth;
                }
            };
            while (pos < text.size()) {
                auto nl = text.find('\n', pos);
                auto line = trim(nl == std::string_view::npos ? text.substr(pos) : text.substr(pos, nl - pos));
                pos = (nl == std::string_view::npos) ? text.size() : (nl + 1);
                if (line.empty() || line.front() == '#') continue;

                if (block_depth == 0 && (line.starts_with("lease {") || line == "lease{" ||
                                         line.starts_with("lease6 {") || line == "lease6{")) {
                    block_ipv6 = line.starts_with("lease6");
                    block_iface.clear();
                    block_servers.clear();
                    update_depth(line);
                    if (block_depth == 0) commit_block();
                    continue;
                }
                if (block_depth > 0) {
                    if (line.starts_with("interface ")) {
                        block_iface = std::string(unquote(line.substr(10)));
                    } else if (line.starts_with("option domain-name-servers ")) {
                        block_servers.clear();
                        parse_token_addresses(line.substr(27), current_ttl, block_servers);
                    } else if (line.starts_with("option dhcp6.name-servers ")) {
                        block_servers.clear();
                        parse_token_addresses(line.substr(26), current_ttl, block_servers);
                    }
                    update_depth(line);
                    if (block_depth == 0) commit_block();
                    continue;
                }

                if (line.starts_with("INTERFACE=")) {
                    flat_iface = std::string(unquote(line.substr(10)));
                } else if (line.starts_with("option domain-name-servers ")) {
                    parse_token_addresses(line.substr(27), current_ttl, flat_servers);
                } else if (line.starts_with("option dhcp6.name-servers ")) {
                    parse_token_addresses(line.substr(26), current_ttl, flat_servers);
                } else if (line.starts_with("DNS=")) {
                    parse_token_addresses(line.substr(4), current_ttl, flat_servers);
                } else if (line.starts_with("nameserver ")) {
                    parse_token_addresses(line.substr(11), current_ttl, flat_servers);
                } else if (line.starts_with("LIFETIME_SEC=")) {
                    std::uint32_t sec = 0;
                    auto v = line.substr(13);
                    if (auto [p, ec] = std::from_chars(v.data(), v.data() + v.size(), sec); ec == std::errc{} && sec > 0)
                        current_ttl = sec;
                }
            }
            if (block_depth > 0) commit_block();
            for (auto const& entry : latest_blocks) {
                if (!interface_filter.empty() && entry.iface != interface_filter) continue;
                std::string_view block_scope = !entry.iface.empty()
                    ? std::string_view(entry.iface)
                    : (!interface_filter.empty() ? interface_filter : fallback_scope);
                for (auto const& e : entry.servers) {
                    append_unique(out, e.address, e.lease_ttl_seconds, effective_entry_scope(e, block_scope));
                }
            }
            bool flat_ok = interface_filter.empty() ||
                (!flat_iface.empty() ? flat_iface == interface_filter : allow_untagged_flat);
            if (flat_ok) {
                std::string_view flat_scope = !flat_iface.empty()
                    ? std::string_view(flat_iface)
                    : (!interface_filter.empty() ? interface_filter : fallback_scope);
                for (auto const& e : flat_servers) {
                    append_unique(out, e.address, e.lease_ttl_seconds, effective_entry_scope(e, flat_scope));
                }
            }
            return out;
        }
    }

    auto is_ipv6_link_local(platform::IpAddress const& addr) noexcept -> bool {
        return addr.size == 16 && addr.bytes[0] == 0xfeu && (addr.bytes[1] & 0xc0u) == 0x80u;
    }

    auto resolve_ipv6_scope_id(std::string_view scope) noexcept -> std::uint32_t {
        if (scope.empty() || scope.find('\0') != std::string_view::npos) return 0;
        std::uint32_t numeric = 0;
        auto [end, ec] = std::from_chars(scope.data(), scope.data() + scope.size(), numeric);
        if (ec == std::errc{} && end == scope.data() + scope.size()) return numeric;
        if (scope.size() >= 64) return 0;
        std::array<char, 64> name{};
        std::ranges::copy(scope, name.begin());
        return static_cast<std::uint32_t>(::if_nametoindex(name.data()));
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

    auto parse_dhcp_lease_text(std::string_view text, std::string_view interface_filter)
        -> containers::inplace_vector<DhcpServerEntry, 8> {
        return parse_lease_text_impl(text, interface_filter, interface_filter.empty(), interface_filter);
    }

    auto discover_dhcp_dns_servers(std::span<std::string_view const> candidate_paths, std::string_view interface_filter)
        -> containers::inplace_vector<DhcpServerEntry, 8> {
        static constexpr std::array<std::string_view, 3> kDefaults{
            "/run/systemd/netif/leases",
            "/var/lib/dhcp/dhclient.leases",
            "/etc/resolv.conf",
        };
        static constexpr std::size_t kMaxLeaseFiles = 64;
        static constexpr std::size_t kMaxLeaseFileBytes = 1024 * 1024;
        bool const using_defaults = candidate_paths.empty();
        auto paths = using_defaults ? std::span<std::string_view const>(kDefaults) : candidate_paths;
        std::string idx_name;
        if (!interface_filter.empty()) {
            if (auto idx = resolve_ipv6_scope_id(interface_filter); idx != 0) idx_name = std::to_string(idx);
        }
        containers::inplace_vector<DhcpServerEntry, 8> out;
        for (auto raw_path : paths) {
            if (using_defaults && raw_path == "/etc/resolv.conf" && (!out.empty() || !interface_filter.empty()))
                continue;
            std::filesystem::path p(raw_path);
            std::error_code ec;
            auto merge_file = [&](std::filesystem::path const& file, bool allow_untagged_flat, std::string_view fallback_scope) {
                std::ifstream in(file, std::ios::binary);
                if (!in) return;
                std::string content(kMaxLeaseFileBytes + 1, '\0');
                in.read(content.data(), static_cast<std::streamsize>(content.size()));
                auto got = static_cast<std::size_t>(in.gcount());
                if (got == 0 || got > kMaxLeaseFileBytes) return;
                content.resize(got);
                for (auto const& e : parse_lease_text_impl(content, interface_filter, allow_untagged_flat, fallback_scope))
                    append_unique(out, e.address, e.lease_ttl_seconds, e.scope);
            };
            if (std::filesystem::is_directory(p, ec)) {
                std::size_t scanned = 0;
                for (auto const& ent : std::filesystem::directory_iterator(p, ec)) {
                    if (scanned >= kMaxLeaseFiles) break;
                    if (!ent.is_regular_file(ec)) continue;
                    auto fname = ent.path().filename().string();
                    if (!interface_filter.empty()) {
                        bool name_match = (fname == interface_filter) || (!idx_name.empty() && fname == idx_name);
                        if (!name_match && is_all_digits(fname)) continue;
                        ++scanned;
                        merge_file(ent.path(), name_match, interface_filter);
                    } else {
                        ++scanned;
                        std::string_view dir_scope = (is_all_digits(fname) || resolve_ipv6_scope_id(fname) != 0)
                            ? std::string_view(fname) : std::string_view{};
                        merge_file(ent.path(), true, dir_scope);
                    }
                }
            } else if (std::filesystem::is_regular_file(p, ec)) {
                auto fname = p.filename().string();
                bool name_match = interface_filter.empty() || fname == interface_filter ||
                    (!idx_name.empty() && fname == idx_name);
                merge_file(p, name_match, interface_filter);
            }
        }
        return out;
    }
}
