module rules;
import std;
import platform.ip_address;
import rules.domain_pattern;
import rules.regex;
import rules.any_index;

namespace rules {
    namespace matcher_detail {
        constexpr unsigned af_inet = 4;
        constexpr unsigned af_inet6 = 6;

        auto address(std::string_view text, std::array<std::uint8_t, 16>& out) -> unsigned {
            auto parsed = platform::parse_ip_address(text);
            if (!parsed) return 0;
            out = parsed->bytes;
            return parsed->size == 4 ? af_inet : af_inet6;
        }

        auto network_address(std::array<std::uint8_t, 16> candidate, unsigned bits) noexcept
            -> std::array<std::uint8_t, 16> {
            auto bytes = bits / 8;
            auto remaining = bits % 8;
            if (remaining) {
                candidate[bytes] &= static_cast<std::uint8_t>(0xffU << (8 - remaining));
                ++bytes;
            }
            std::fill(candidate.begin() + bytes, candidate.end(), 0);
            return candidate;
        }

        auto prefix_matches(std::array<std::uint8_t, 16> const& network,
                            std::array<std::uint8_t, 16> const& candidate, unsigned bits) noexcept -> bool {
            auto bytes = bits / 8;
            if (!std::equal(network.begin(), network.begin() + bytes, candidate.begin())) return false;
            auto remaining = bits % 8;
            if (remaining == 0) return true;
            auto mask = static_cast<std::uint8_t>(0xffU << (8 - remaining));
            return (network[bytes] & mask) == (candidate[bytes] & mask);
        }

        auto private_address(std::array<std::uint8_t, 16> const& bytes, unsigned family) noexcept -> bool {
            auto mapped = family == af_inet6 &&
                std::all_of(bytes.begin(), bytes.begin() + 10, [](auto byte) { return byte == 0; }) &&
                bytes[10] == 0xff && bytes[11] == 0xff;
            if (family == af_inet || mapped) {
                auto offset = mapped ? 12u : 0u;
                auto a = bytes[offset], b = bytes[offset + 1];
                return a == 10 || (a == 172 && (b & 0xf0) == 16) || (a == 192 && b == 168) ||
                    a == 127 || (a == 169 && b == 254) || (a & 0xf0) == 0xe0 ||
                    (!mapped && a == 0 && b == 0 && bytes[2] == 0 && bytes[3] == 0);
            }
            auto zero_prefix = std::all_of(bytes.begin(), bytes.end() - 1, [](auto byte) { return byte == 0; });
            return (bytes[0] & 0xfe) == 0xfc || (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80) || bytes[0] == 0xff ||
                (zero_prefix && (bytes[15] == 0 || bytes[15] == 1));
        }

        auto cgnat_address(std::array<std::uint8_t, 16> const& bytes, unsigned family) noexcept -> bool {
            auto mapped = family == af_inet6 &&
                std::all_of(bytes.begin(), bytes.begin() + 10, [](auto b) { return b == 0; }) &&
                bytes[10] == 0xff && bytes[11] == 0xff;
            if (family != af_inet && !mapped) return false;
            auto off = mapped ? 12u : 0u;
            return bytes[off] == 100 && (bytes[off + 1] & 0xc0) == 64;
        }

        auto cidr_matches_addr(std::array<std::uint8_t, 16> const& net, unsigned prefix, unsigned net_family,
                               std::array<std::uint8_t, 16> const& addr, unsigned addr_family, bool mapped_v4) noexcept -> bool {
            if (net_family == addr_family && prefix_matches(net, addr, prefix)) return true;
            if (mapped_v4 && net_family == af_inet && addr_family == af_inet6 &&
                std::all_of(addr.begin(), addr.begin() + 10, [](auto b) { return b == 0; }) &&
                addr[10] == 0xff && addr[11] == 0xff) {
                std::array<std::uint8_t, 16> mapped{};
                std::copy(addr.begin() + 12, addr.end(), mapped.begin());
                return prefix_matches(net, mapped, prefix);
            }
            return false;
        }

        auto iequals_ascii(std::string_view a, std::string_view b) noexcept -> bool {
            if (a.size() != b.size()) return false;
            for (std::size_t i = 0; i < a.size(); ++i) {
                unsigned char ca = static_cast<unsigned char>(a[i]);
                unsigned char cb = static_cast<unsigned char>(b[i]);
                if (ca >= 'A' && ca <= 'Z') ca = static_cast<unsigned char>(ca + ('a' - 'A'));
                if (cb >= 'A' && cb <= 'Z') cb = static_cast<unsigned char>(cb + ('a' - 'A'));
                if (ca != cb) return false;
            }
            return true;
        }

        auto valid_meta_string(std::optional<std::string_view> value) noexcept -> bool {
            return !value || (!value->empty() && value->size() <= 255 && value->find('\0') == std::string_view::npos);
        }
    }

    auto Matcher::prepare(MatchInput input) -> std::expected<Prepared, Error> {
        using namespace matcher_detail;
        if (input.domain) {
            if (input.domain->ends_with('.')) input.domain->remove_suffix(1);
            if (!valid_domain(*input.domain))
                return std::unexpected(Error{ErrorCode::invalid_query, "invalid ASCII domain"});
        }
        Prepared prepared{input};
        if (input.ip && !(prepared.family = address(*input.ip, prepared.address)))
            return std::unexpected(Error{ErrorCode::invalid_query, "invalid IP address"});
        if (input.ip_bytes) {
            auto bytes = *input.ip_bytes;
            if (input.ip || (bytes.size() != 4 && bytes.size() != 16))
                return std::unexpected(Error{ErrorCode::invalid_query, "invalid IP address"});
            prepared.family = bytes.size() == 4 ? af_inet : af_inet6;
            std::ranges::copy(bytes, prepared.address.begin());
            // Mark destination IP present so Matcher/eval_mmap presence checks match binary bytes.
            prepared.input.ip = std::string_view{};
        }
        if (input.source_ip && !(prepared.source_family = address(*input.source_ip, prepared.source_address)))
            return std::unexpected(Error{ErrorCode::invalid_query, "invalid source IP address"});
        if (input.source_ip_bytes) {
            auto bytes = *input.source_ip_bytes;
            if (input.source_ip || (bytes.size() != 4 && bytes.size() != 16))
                return std::unexpected(Error{ErrorCode::invalid_query, "invalid source IP address"});
            prepared.source_family = bytes.size() == 4 ? af_inet : af_inet6;
            std::ranges::copy(bytes, prepared.source_address.begin());
        }
        if (input.default_interface_addresses) {
            if (input.default_interface_addresses->size() > 64)
                return std::unexpected(Error{ErrorCode::invalid_query, "too many default interface addresses"});
            for (auto const& addr : *input.default_interface_addresses)
                if (addr.size != 4 && addr.size != 16)
                    return std::unexpected(Error{ErrorCode::invalid_query, "invalid default interface address"});
        }
        if (input.process_paths && input.process_paths->size() > 64)
            return std::unexpected(Error{ErrorCode::invalid_query, "too many process paths"});
        if (input.source_port && !*input.source_port)
            return std::unexpected(Error{ErrorCode::invalid_query, "invalid source port"});
        if (input.port && !*input.port)
            return std::unexpected(Error{ErrorCode::invalid_query, "invalid destination port"});
        if (input.dscp && *input.dscp > 63)
            return std::unexpected(Error{ErrorCode::invalid_query, "invalid DSCP"});
        if (input.query_type && !*input.query_type)
            return std::unexpected(Error{ErrorCode::invalid_query, "invalid DNS query type"});
        if (input.network && *input.network != Network::tcp && *input.network != Network::udp)
            return std::unexpected(Error{ErrorCode::invalid_query, "invalid network"});
        if (input.protocol && (*input.protocol < Protocol::http || *input.protocol > Protocol::tls_ech))
            return std::unexpected(Error{ErrorCode::invalid_query, "invalid protocol"});
        if (!valid_meta_string(input.inbound))
            return std::unexpected(Error{ErrorCode::invalid_query, "invalid inbound name"});
        if (!valid_meta_string(input.auth_user))
            return std::unexpected(Error{ErrorCode::invalid_query, "invalid authenticated user"});
        if (!valid_meta_string(input.wifi_ssid))
            return std::unexpected(Error{ErrorCode::invalid_query, "invalid wifi SSID"});
        if (!valid_meta_string(input.source_user))
            return std::unexpected(Error{ErrorCode::invalid_query, "invalid source user"});
        if (!valid_meta_string(input.package_name))
            return std::unexpected(Error{ErrorCode::invalid_query, "invalid package name"});
        if (input.client && !valid_client_name(*input.client))
            return std::unexpected(Error{ErrorCode::invalid_query, "invalid client name"});
        if (input.route_mode && *input.route_mode > RouteMode::direct)
            return std::unexpected(Error{ErrorCode::invalid_query, "invalid route mode"});
        if (input.network_type && *input.network_type > NetworkType::other)
            return std::unexpected(Error{ErrorCode::invalid_query, "invalid network type"});
        return prepared;
    }

    auto Matcher::evaluate(std::size_t index, Prepared const& input) const noexcept -> Truth {
        using namespace matcher_detail;
        auto const& entry = entries_[index];
        if (input.candidates && (entry.kind == Kind::ip || entry.kind == Kind::ip_version ||
            entry.kind == Kind::ip_is_private || entry.kind == Kind::ip_is_cgnat)) {
            auto candidate = input;
            candidate.candidates.reset();
            for (auto const& addr : *input.candidates) {
                candidate.address = addr.bytes;
                candidate.family = addr.size == 4 ? af_inet : af_inet6;
                candidate.input.ip = std::string_view{};
                if (evaluate(index, candidate) == Truth::yes) return Truth::yes;
            }
            return Truth::no;
        }
        switch (entry.kind) {
        case Kind::process_name:
        case Kind::process_path: {
            auto matches_one = [&](std::string_view path) noexcept {
                auto sep = path.find_last_of("/\\");
                auto value = entry.kind == Kind::process_path ? path : (sep == std::string_view::npos ? path : path.substr(sep + 1));
                return value == entry.text;
            };
            bool has_any = false;
            if (input.input.process_paths && !input.input.process_paths->empty()) {
                has_any = true;
                for (std::string const& candidate : *input.input.process_paths)
                    if (matches_one(candidate)) return Truth::yes;
            }
            if (input.input.process_path) {
                has_any = true;
                if (matches_one(*input.input.process_path)) return Truth::yes;
            }
            return has_any ? Truth::no : Truth::unknown;
        }
        case Kind::domain_regex:
            if (!input.input.domain) return input.domain_absent ? Truth::no : Truth::unknown;
            return regexes_[entry.regex].search(*input.input.domain, true) ? Truth::yes : Truth::no;
        case Kind::process_path_regex: {
            bool has_valid = false, saw_oversized = false;
            auto check_one = [&](std::string_view path) noexcept -> bool {
                if (path.size() > 4095) { saw_oversized = true; return false; }
                has_valid = true;
                return regexes_[entry.regex].search(path);
            };
            if (input.input.process_paths && !input.input.process_paths->empty()) {
                for (std::string const& candidate : *input.input.process_paths)
                    if (check_one(candidate)) return Truth::yes;
            }
            if (input.input.process_path && check_one(*input.input.process_path)) return Truth::yes;
            return (has_valid && !saw_oversized) ? Truth::no : Truth::unknown;
        }
        case Kind::source_interface:
            if (!input.input.source_interface) return Truth::unknown;
            return *input.input.source_interface == entry.text ? Truth::yes : Truth::no;
        case Kind::inbound:
            if (!input.input.inbound) return Truth::unknown;
            return *input.input.inbound == entry.text ? Truth::yes : Truth::no;
        case Kind::auth_user:
            if (!input.input.auth_user) return Truth::unknown;
            return *input.input.auth_user == entry.text ? Truth::yes : Truth::no;
        case Kind::wifi_ssid:
            if (!input.input.wifi_ssid) return Truth::unknown;
            return *input.input.wifi_ssid == entry.text ? Truth::yes : Truth::no;
        case Kind::source_user:
            if (!input.input.source_user) return Truth::unknown;
            return *input.input.source_user == entry.text ? Truth::yes : Truth::no;
        case Kind::package_name:
            if (!input.input.package_name) return Truth::unknown;
            return *input.input.package_name == entry.text ? Truth::yes : Truth::no;
        case Kind::client:
            if (!input.input.client) return Truth::unknown;
            return iequals_ascii(*input.input.client, entry.text) ? Truth::yes : Truth::no;
        case Kind::domain:
        case Kind::suffix:
        case Kind::keyword:
        case Kind::wildcard: {
            if (!input.input.domain) return input.domain_absent ? Truth::no : Truth::unknown;
            auto kind = entry.kind == Kind::domain ? DomainPattern::exact :
                entry.kind == Kind::suffix ? DomainPattern::suffix :
                entry.kind == Kind::keyword ? DomainPattern::keyword : DomainPattern::wildcard;
            return domain_pattern_matches(kind, *input.input.domain, entry.text) ? Truth::yes : Truth::no;
        }
        case Kind::ip:
        case Kind::source_ip: {
            bool source = entry.kind == Kind::source_ip;
            if (source ? !input.source_family : !input.input.ip) return Truth::unknown;
            auto const& addr = source ? input.source_address : input.address;
            auto family = source ? input.source_family : input.family;
            return cidr_matches_addr(entry.ip.address, entry.ip.prefix, entry.ip.family, addr, family, input.match_mapped_ipv4)
                ? Truth::yes : Truth::no;
        }
        case Kind::default_interface_ip: {
            if (!input.input.default_interface_addresses) return Truth::unknown;
            for (auto const& addr : *input.input.default_interface_addresses) {
                auto fam = addr.size == 4 ? af_inet : af_inet6;
                if (cidr_matches_addr(entry.ip.address, entry.ip.prefix, entry.ip.family, addr.bytes, fam, input.match_mapped_ipv4))
                    return Truth::yes;
            }
            return Truth::no;
        }
        case Kind::ip_accept_any:
            if (input.candidates) return input.candidates->empty() ? Truth::no : Truth::yes;
            return input.input.ip ? Truth::yes : Truth::unknown;
        case Kind::source_ip_accept_any:
            return input.source_family ? Truth::yes : Truth::unknown;
        case Kind::ip_version:
            if (!input.input.ip) return Truth::unknown;
            return (entry.ip_version == 4 ? input.family == af_inet : input.family == af_inet6) ? Truth::yes : Truth::no;
        case Kind::ip_is_private:
            if (!input.input.ip) return Truth::unknown;
            return private_address(input.address, input.family) ? Truth::yes : Truth::no;
        case Kind::source_private:
            if (!input.source_family) return Truth::unknown;
            return private_address(input.source_address, input.source_family) ? Truth::yes : Truth::no;
        case Kind::ip_is_cgnat:
            if (!input.input.ip) return Truth::unknown;
            return cgnat_address(input.address, input.family) ? Truth::yes : Truth::no;
        case Kind::source_cgnat:
            if (!input.source_family) return Truth::unknown;
            return cgnat_address(input.source_address, input.source_family) ? Truth::yes : Truth::no;
        case Kind::port:
            if (!input.input.port) return Truth::unknown;
            return *input.input.port >= entry.port.first && *input.input.port <= entry.port.last ? Truth::yes : Truth::no;
        case Kind::source_uid:
            if (!input.input.source_uid) return Truth::unknown;
            return *input.input.source_uid == entry.source_uid ? Truth::yes : Truth::no;
        case Kind::source_gid:
            if (!input.input.source_gid) return Truth::unknown;
            return *input.input.source_gid == entry.source_uid ? Truth::yes : Truth::no;
        case Kind::source_port:
            if (!input.input.source_port) return Truth::unknown;
            return *input.input.source_port >= entry.port.first && *input.input.source_port <= entry.port.last ? Truth::yes : Truth::no;
        case Kind::network:
            if (!input.input.network) return Truth::unknown;
            return *input.input.network == entry.network ? Truth::yes : Truth::no;
        case Kind::network_type:
            if (!input.input.network_type) return Truth::unknown;
            return *input.input.network_type == entry.network_type ? Truth::yes : Truth::no;
        case Kind::network_is_expensive:
            if (!input.input.network_is_expensive) return Truth::unknown;
            return *input.input.network_is_expensive == entry.offered ? Truth::yes : Truth::no;
        case Kind::network_is_constrained:
            if (!input.input.network_is_constrained) return Truth::unknown;
            return *input.input.network_is_constrained == entry.offered ? Truth::yes : Truth::no;
        case Kind::dscp:
            if (!input.input.dscp) return Truth::unknown;
            return (entry.dscp_mask & (std::uint64_t{1} << *input.input.dscp)) ? Truth::yes : Truth::no;
        case Kind::source_mac:
        case Kind::gateway_mac:
        case Kind::wifi_bssid: {
            auto const& addr = entry.kind == Kind::source_mac ? input.input.source_mac :
                entry.kind == Kind::gateway_mac ? input.input.gateway_mac : input.input.wifi_bssid;
            return !addr ? Truth::unknown : *addr == entry.mac ? Truth::yes : Truth::no;
        }
        case Kind::tls_ech:
            if (input.input.protocol != Protocol::tls || !input.input.tls_ech) return Truth::unknown;
            return *input.input.tls_ech == entry.offered ? Truth::yes : Truth::no;
        case Kind::protocol:
            if (!input.input.protocol) return Truth::unknown;
            return *input.input.protocol == entry.protocol ? Truth::yes : Truth::no;
        case Kind::query_type:
            if (!input.input.query_type) return Truth::unknown;
            return *input.input.query_type == entry.query_type ? Truth::yes : Truth::no;
        case Kind::route_mode:
            if (!input.input.route_mode) return Truth::unknown;
            return *input.input.route_mode == entry.route_mode ? Truth::yes : Truth::no;
        case Kind::negate: {
            auto child = evaluate(children_[entry.children.first], input);
            return child == Truth::unknown ? child : child == Truth::yes ? Truth::no : Truth::yes;
        }
        case Kind::all:
        case Kind::any: {
            bool unknown = false;
            if (entry.kind == Kind::any && entry.children.any_index < any_indexes_.size()) {
                auto const& idx = any_indexes_[entry.children.any_index];
                if (idx.has_domain) {
                    if (input.input.domain) {
                        if (any_detail::match_any_domain(entries_, idx, *input.input.domain)) return Truth::yes;
                    } else if (!input.domain_absent) unknown = true;
                }
                if (idx.has_ip) {
                    if (input.candidates) {
                        for (auto const& c : *input.candidates)
                            if (any_detail::match_any_ip_one(idx, c.bytes, c.size == 4 ? af_inet : af_inet6, input.match_mapped_ipv4))
                                return Truth::yes;
                    } else if (input.input.ip) {
                        if (any_detail::match_any_ip_one(idx, input.address, input.family, input.match_mapped_ipv4))
                            return Truth::yes;
                    } else unknown = true;
                }
                for (auto cid : idx.remainder) {
                    auto value = evaluate(cid, input);
                    if (value == Truth::yes) return Truth::yes;
                    unknown |= value == Truth::unknown;
                }
                return unknown ? Truth::unknown : Truth::no;
            }
            auto last = entry.children.first + entry.children.count;
            for (auto child = entry.children.first; child < last; ++child) {
                auto value = evaluate(children_[child], input);
                if (entry.kind == Kind::all && value == Truth::no) return Truth::no;
                if (entry.kind == Kind::any && value == Truth::yes) return Truth::yes;
                unknown |= value == Truth::unknown;
            }
            return unknown ? Truth::unknown : entry.kind == Kind::all ? Truth::yes : Truth::no;
        }
        }
        std::terminate();
    }

    auto Matcher::first_indexed_match(Prepared const& prepared, std::size_t first, std::size_t last) const noexcept
        -> std::size_t {
        auto best = last;
        auto domain_lookup = [&](auto const& index, std::string_view key) {
            auto found = std::lower_bound(index.begin(), index.end(), key,
                [first](IndexedDomain const& item, std::string_view value) {
                    return item.text < value || (item.text == value && item.rule < first);
                });
            if (found != index.end() && found->text == key && found->rule < last) best = std::min(best, found->rule);
        };
        if (prepared.input.domain && (!domains_.empty() || !suffixes_.empty())) {
            std::array<char, 253> normalized;
            auto name = *prepared.input.domain;
            if (std::ranges::any_of(name, [](char c) { return c >= 'A' && c <= 'Z'; })) {
                for (std::size_t i = 0; i < name.size(); ++i) {
                    auto c = name[i];
                    normalized[i] = c >= 'A' && c <= 'Z' ? static_cast<char>(c + ('a' - 'A')) : c;
                }
                name = std::string_view(normalized.data(), name.size());
            }
            domain_lookup(domains_, name);
            if (!suffixes_.empty()) for (;;) {
                domain_lookup(suffixes_, name);
                auto dot = name.find('.');
                if (dot == std::string_view::npos) break;
                name.remove_prefix(dot + 1);
            }
        }
        auto ip_lookup = [&](IpIndex const& index, std::array<std::uint8_t, 16> const& address) {
            for (auto const& group : index) {
                auto network = matcher_detail::network_address(address, group.prefix);
                auto found = std::lower_bound(group.entries.begin(), group.entries.end(), network,
                    [first](IndexedIp const& item, auto const& value) {
                        return item.address < value || (item.address == value && item.rule < first);
                    });
                if (found != group.entries.end() && found->address == network && found->rule < last)
                    best = std::min(best, found->rule);
            }
        };
        if (prepared.input.ip) {
            if (prepared.family == matcher_detail::af_inet) ip_lookup(ipv4_, prepared.address);
            else {
                ip_lookup(ipv6_, prepared.address);
                if (prepared.match_mapped_ipv4 &&
                    std::all_of(prepared.address.begin(), prepared.address.begin() + 10, [](auto byte) { return byte == 0; }) &&
                    prepared.address[10] == 0xff && prepared.address[11] == 0xff) {
                    std::array<std::uint8_t, 16> mapped{};
                    std::copy(prepared.address.begin() + 12, prepared.address.end(), mapped.begin());
                    ip_lookup(ipv4_, mapped);
                }
            }
        }
        return best;
    }

    auto Matcher::has_ip_root(std::size_t first, std::size_t last) const noexcept -> bool {
        auto it = std::lower_bound(ip_roots_.begin(), ip_roots_.end(), first);
        return it != ip_roots_.end() && *it < last;
    }

    auto Matcher::has_domain_root(std::size_t first, std::size_t last) const noexcept -> bool {
        auto it = std::lower_bound(domain_roots_.begin(), domain_roots_.end(), first);
        return it != domain_roots_.end() && *it < last;
    }

    auto Matcher::first_match(Prepared const& prepared) const noexcept -> std::optional<std::size_t> {
        if (mmap_ && eval_mmap(*mmap_, nullptr, prepared, mmap_->ip_cidr_match_source()) == Truth::yes) return 0;
        return first_match(prepared, 0, roots_.size());
    }

    auto Matcher::first_match(Prepared const& prepared, std::size_t first, std::size_t last) const noexcept
        -> std::optional<std::size_t> {
        if (last - first <= 4) {
            for (auto i = first; i < last; ++i)
                if (evaluate(roots_[i], prepared) == Truth::yes) return i;
            return {};
        }
        auto best = first_indexed_match(prepared, first, last);
        for (auto it = std::lower_bound(unindexed_.begin(), unindexed_.end(), first); it != unindexed_.end(); ++it) {
            if (*it >= best) break;
            if (evaluate(roots_[*it], prepared) == Truth::yes) { best = *it; break; }
        }
        return best == last ? std::optional<std::size_t>{} : best;
    }
}
