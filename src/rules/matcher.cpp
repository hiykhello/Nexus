module rules;
import std;
import platform.ip_address;
import rules.regex;
import rules.any_index;

namespace rules {
    namespace matcher_detail {
        auto address(std::string_view text, std::array<std::uint8_t, 16>& out) -> unsigned;
        auto network_address(std::array<std::uint8_t, 16> candidate, unsigned bits) noexcept -> std::array<std::uint8_t, 16>;
        auto private_address(std::array<std::uint8_t, 16> const& bytes, unsigned family) noexcept -> bool;
        constexpr unsigned af_inet = 4;
        constexpr unsigned af_inet6 = 6;
    }

    auto normalize_matcher_set(RuleSet set, std::vector<BoundedRegex>& expressions) -> std::expected<RuleSet, Error>;

    auto Matcher::rebind_text_views() noexcept -> void {
        std::size_t text_index = 0;
        for (auto& entry : entries_)
            if (is_text_kind(entry.kind)) {
                auto [off, len] = text_spans_[text_index++];
                entry.text = std::string_view(text_arena_.data() + off, len);
            }
        for (auto* index : {&domains_, &suffixes_})
            for (auto& item : *index) item.text = entries_[roots_[item.rule]].text;
    }

    Matcher::Matcher() = default;
    Matcher::Matcher(Matcher const& other)
        : uses_source_uid_(other.uses_source_uid_), uses_process_(other.uses_process_),
          entries_(other.entries_), text_arena_(other.text_arena_), text_spans_(other.text_spans_),
          regexes_(other.regexes_), children_(other.children_), roots_(other.roots_),
          domains_(other.domains_), suffixes_(other.suffixes_), ipv4_(other.ipv4_), ipv6_(other.ipv6_),
          any_indexes_(other.any_indexes_), unindexed_(other.unindexed_),
          ip_roots_(other.ip_roots_), domain_roots_(other.domain_roots_), mmap_(other.mmap_) {
        rebind_text_views();
    }
    Matcher::Matcher(Matcher&& other) noexcept
        : uses_source_uid_(other.uses_source_uid_), uses_process_(other.uses_process_),
          entries_(std::move(other.entries_)), text_arena_(std::move(other.text_arena_)),
          text_spans_(std::move(other.text_spans_)), regexes_(std::move(other.regexes_)),
          children_(std::move(other.children_)), roots_(std::move(other.roots_)),
          domains_(std::move(other.domains_)), suffixes_(std::move(other.suffixes_)),
          ipv4_(std::move(other.ipv4_)), ipv6_(std::move(other.ipv6_)),
          any_indexes_(std::move(other.any_indexes_)), unindexed_(std::move(other.unindexed_)),
          ip_roots_(std::move(other.ip_roots_)), domain_roots_(std::move(other.domain_roots_)),
          mmap_(std::move(other.mmap_)) {
        rebind_text_views();
    }
    auto Matcher::operator=(Matcher const& other) -> Matcher& {
        if (this != &other) *this = Matcher(other);
        return *this;
    }
    auto Matcher::operator=(Matcher&& other) noexcept -> Matcher& {
        if (this != &other) {
            uses_source_uid_ = other.uses_source_uid_;
            uses_process_ = other.uses_process_;
            entries_ = std::move(other.entries_);
            text_arena_ = std::move(other.text_arena_);
            text_spans_ = std::move(other.text_spans_);
            regexes_ = std::move(other.regexes_);
            children_ = std::move(other.children_);
            roots_ = std::move(other.roots_);
            domains_ = std::move(other.domains_);
            suffixes_ = std::move(other.suffixes_);
            ipv4_ = std::move(other.ipv4_);
            ipv6_ = std::move(other.ipv6_);
            any_indexes_ = std::move(other.any_indexes_);
            unindexed_ = std::move(other.unindexed_);
            ip_roots_ = std::move(other.ip_roots_);
            domain_roots_ = std::move(other.domain_roots_);
            mmap_ = std::move(other.mmap_);
            rebind_text_views();
        }
        return *this;
    }
    Matcher::~Matcher() = default;

    auto is_private_address(std::span<std::uint8_t const> addr) noexcept -> bool {
        if (addr.size() != 4 && addr.size() != 16) return false;
        std::array<std::uint8_t, 16> bytes{};
        std::ranges::copy(addr, bytes.begin());
        return matcher_detail::private_address(bytes, addr.size() == 4 ? matcher_detail::af_inet : matcher_detail::af_inet6);
    }

    auto Matcher::text_rule_kind(std::string_view type) noexcept -> std::optional<Matcher::Kind> {
        if (type == "domain") return Kind::domain;
        if (type == "domain-suffix") return Kind::suffix;
        if (type == "domain-keyword") return Kind::keyword;
        if (type == "domain-wildcard") return Kind::wildcard;
        if (type == "inbound") return Kind::inbound;
        if (type == "auth-user") return Kind::auth_user;
        if (type == "process-name") return Kind::process_name;
        if (type == "process-path") return Kind::process_path;
        if (type == "source-interface") return Kind::source_interface;
        if (type == "wifi-ssid") return Kind::wifi_ssid;
        if (type == "source-user") return Kind::source_user;
        if (type == "package-name") return Kind::package_name;
        if (type == "client") return Kind::client;
        return {};
    }

    auto Matcher::parse_cidr_entry(std::string_view value) noexcept -> Matcher::IpPredicate {
        IpPredicate out{};
        auto slash = value.find('/');
        auto prefix = value.substr(slash + 1);
        out.family = matcher_detail::address(value.substr(0, slash), out.address);
        (void)std::from_chars(prefix.data(), prefix.data() + prefix.size(), out.prefix);
        return out;
    }

    auto Matcher::parse_net_if_cidr(std::string_view value) noexcept -> Matcher::NetworkInterfaceIp {
        auto colon = value.find(':');
        auto ip = parse_cidr_entry(value.substr(colon + 1));
        return {ip.address, static_cast<std::uint8_t>(ip.prefix), static_cast<std::uint8_t>(ip.family),
                *parse_network_type(value.substr(0, colon))};
    }

    auto Matcher::compile(RuleSet const& set) -> std::expected<Matcher, Error> {
        Matcher result;
        auto normalized = normalize_matcher_set(set, result.regexes_);
        if (!normalized) return std::unexpected(std::move(normalized.error()));
        static_assert(max_rules <= std::numeric_limits<std::uint32_t>::max());
        result.roots_.reserve(normalized->rules.size());
        std::size_t text_count = 0, text_bytes = 0;
        auto count_texts = [&](auto&& self, Rule const& rule) -> void {
            if (text_rule_kind(rule.type)) {
                ++text_count;
                text_bytes += rule.value.size();
            }
            for (auto const& child : rule.children) self(self, child);
        };
        for (auto const& rule : normalized->rules) count_texts(count_texts, rule);
        result.text_arena_.reserve(text_bytes);
        result.text_spans_.reserve(text_count);
        std::uint32_t regex_index = 0;
        auto append = [&](auto&& self, Rule const& rule) -> std::size_t {
            auto index = result.entries_.size();
            result.entries_.emplace_back();
            Entry entry;
            if (auto tk = text_rule_kind(rule.type)) {
                entry.kind = *tk;
                result.uses_process_ |= entry.kind == Kind::process_name || entry.kind == Kind::process_path ||
                    entry.kind == Kind::package_name;
                result.uses_source_uid_ |= entry.kind == Kind::source_user;
                auto off = static_cast<std::uint32_t>(result.text_arena_.size());
                auto len = static_cast<std::uint32_t>(rule.value.size());
                result.text_arena_.append(rule.value);
                result.text_spans_.emplace_back(off, len);
                entry.text = std::string_view(result.text_arena_.data() + off, len);
            } else if (rule.type == "domain-regex" || rule.type == "process-path-regex" || rule.type == "package-name-regex") {
                entry.kind = rule.type == "domain-regex" ? Kind::domain_regex :
                    rule.type == "process-path-regex" ? Kind::process_path_regex : Kind::package_name_regex;
                entry.regex = regex_index++;
                result.uses_process_ |= entry.kind == Kind::process_path_regex || entry.kind == Kind::package_name_regex;
            } else if (rule.type == "ip-cidr" || rule.type == "source-ip-cidr" || rule.type == "default-interface-address") {
                entry.kind = rule.type == "ip-cidr" ? Kind::ip :
                    rule.type == "source-ip-cidr" ? Kind::source_ip : Kind::default_interface_ip;
                entry.ip = parse_cidr_entry(rule.value);
            } else if (rule.type == "network-interface-address") {
                entry.kind = Kind::network_interface_ip;
                entry.net_if_ip = parse_net_if_cidr(rule.value);
            } else if (rule.type == "ip-version") {
                entry.kind = Kind::ip_version;
                entry.ip_version = rule.value == "4" ? 4 : 6;
            } else if (rule.type == "ip-is-private" || rule.type == "source-ip-is-private") {
                entry.kind = rule.type == "ip-is-private" ? Kind::ip_is_private : Kind::source_private;
            } else if (rule.type == "ip-is-cgnat" || rule.type == "source-ip-is-cgnat") {
                entry.kind = rule.type == "ip-is-cgnat" ? Kind::ip_is_cgnat : Kind::source_cgnat;
            } else if (rule.type == "ip-accept-any" || rule.type == "source-ip-accept-any") {
                entry.kind = rule.type == "ip-accept-any" ? Kind::ip_accept_any : Kind::source_ip_accept_any;
            } else if (rule.type == "port" || rule.type == "port-range" || rule.type == "source-port" || rule.type == "source-port-range") {
                entry.kind = rule.type.starts_with("source-") ? Kind::source_port : Kind::port;
                auto dash = rule.value.find('-');
                auto end = dash == std::string::npos ? rule.value.size() : dash;
                unsigned first = 0, last = 0;
                (void)std::from_chars(rule.value.data(), rule.value.data() + end, first);
                if (dash == std::string::npos) last = first;
                else (void)std::from_chars(rule.value.data() + dash + 1, rule.value.data() + rule.value.size(), last);
                entry.port = {static_cast<std::uint16_t>(first), static_cast<std::uint16_t>(last)};
            } else if (rule.type == "source-uid" || rule.type == "source-gid") {
                entry.kind = rule.type == "source-uid" ? Kind::source_uid : Kind::source_gid;
                entry.source_uid = *parse_source_uid(rule.value);
                result.uses_source_uid_ = true;
            } else if (rule.type == "query-type") {
                entry.kind = Kind::query_type;
                unsigned value = 0;
                (void)std::from_chars(rule.value.data(), rule.value.data() + rule.value.size(), value);
                entry.query_type = static_cast<std::uint16_t>(value);
            } else if (rule.type == "dscp") {
                entry.kind = Kind::dscp;
                entry.dscp_mask = *parse_dscp_list(rule.value);
            } else if (rule.type == "source-mac" || rule.type == "gateway-mac" || rule.type == "wifi-bssid") {
                entry.kind = rule.type == "source-mac" ? Kind::source_mac :
                    rule.type == "gateway-mac" ? Kind::gateway_mac : Kind::wifi_bssid;
                entry.mac = *parse_mac(rule.value);
            } else if (rule.type == "tls-ech" || (rule.type == "protocol" && rule.value == "tls-ech")) {
                entry.kind = Kind::tls_ech;
                entry.offered = rule.value != "false";
            } else if (rule.type == "protocol") {
                entry.kind = Kind::protocol;
                entry.protocol = *parse_protocol(rule.value);
            } else if (rule.type == "route-mode") {
                entry.kind = Kind::route_mode;
                entry.route_mode = *parse_route_mode(rule.value);
            } else if (rule.type == "network") {
                entry.kind = Kind::network;
                entry.network = rule.value == "tcp" ? Network::tcp : rule.value == "udp" ? Network::udp : Network::icmp;
            } else if (rule.type == "network-type") {
                entry.kind = Kind::network_type;
                entry.network_type = *parse_network_type(rule.value);
            } else if (rule.type == "network-is-expensive" || rule.type == "network-is-constrained") {
                entry.kind = rule.type == "network-is-expensive" ? Kind::network_is_expensive : Kind::network_is_constrained;
                entry.offered = rule.value == "true";
            } else {
                entry.kind = rule.type == "and" ? Kind::all : rule.type == "or" ? Kind::any : Kind::negate;
                auto first = result.children_.size();
                result.children_.resize(first + rule.children.size());
                for (std::size_t i = 0; i < rule.children.size(); ++i) {
                    auto child = self(self, rule.children[i]);
                    result.children_[first + i] = static_cast<std::uint32_t>(child);
                }
                auto any_idx = entry.kind == Kind::any && rule.children.size() >= 16 ?
                    any_detail::compile_any_index(result.entries_, result.children_, static_cast<std::uint32_t>(first),
                        static_cast<std::uint32_t>(rule.children.size()), Kind::ip, Kind::domain, Kind::suffix, result.any_indexes_) :
                    std::numeric_limits<std::uint32_t>::max();
                entry.children = {static_cast<std::uint32_t>(first), static_cast<std::uint32_t>(rule.children.size()), any_idx};
            }
            result.entries_[index] = std::move(entry);
            return index;
        };
        for (auto const& rule : normalized->rules) result.roots_.push_back(append(append, rule));
        for (std::size_t i = 0; i < result.roots_.size(); ++i) {
            auto const& entry = result.entries_[result.roots_[i]];
            if (entry.kind == Kind::domain) { result.domains_.push_back({entry.text, i}); result.domain_roots_.push_back(i); }
            else if (entry.kind == Kind::suffix) { result.suffixes_.push_back({entry.text, i}); result.domain_roots_.push_back(i); }
            else if (entry.kind == Kind::ip) {
                result.ip_roots_.push_back(i);
                auto& index = entry.ip.family == matcher_detail::af_inet ? result.ipv4_ : result.ipv6_;
                auto group = std::ranges::find(index, entry.ip.prefix, &IpGroup::prefix);
                if (group == index.end()) {
                    index.push_back({entry.ip.prefix, {}});
                    group = std::prev(index.end());
                }
                group->entries.push_back({matcher_detail::network_address(entry.ip.address, entry.ip.prefix), i});
            } else result.unindexed_.push_back(i);
        }
        auto sort_domain = [&](auto& index) {
            std::ranges::sort(index, [&](IndexedDomain const& a, IndexedDomain const& b) {
                return std::tie(a.text, a.rule) < std::tie(b.text, b.rule);
            });
        };
        sort_domain(result.domains_);
        sort_domain(result.suffixes_);
        auto sort_ip = [](IpIndex& index) {
            for (auto& group : index) {
                std::ranges::sort(group.entries, [](IndexedIp const& a, IndexedIp const& b) {
                    return std::tie(a.address, a.rule) < std::tie(b.address, b.rule);
                });
            }
        };
        sort_ip(result.ipv4_);
        sort_ip(result.ipv6_);
        return result;
    }
}
