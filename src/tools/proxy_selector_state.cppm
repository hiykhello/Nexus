// Persisted selector choices, probe target parsing, group tag mapping & session interruption.
export module cli.proxy_selector_state;
import std;
import cli.control;
import config;
import http.connect;
import relay;
import socks5;
import state.core;

export namespace cli::run_detail {
    struct ParsedProbeTarget {
        socks5::Request target;
        std::string request;
        bool use_tls = false;
        std::string host;
    };

    inline auto parse_probe_target(std::string_view url, config::OutboundProbeMode = config::OutboundProbeMode::http)
        -> std::expected<ParsedProbeTarget, std::string> {
        bool use_tls = url.starts_with("https://");
        if (url.size() > 2048 || (!use_tls && !url.starts_with("http://")) ||
            std::ranges::any_of(url, [](unsigned char c) { return c <= 0x20 || c >= 0x7f || c == '#' || c == '\\'; }))
            return std::unexpected("invalid outbound probe URL");
        url.remove_prefix(use_tls ? 8 : 7);
        auto sep = url.find_first_of("/?");
        auto authority = url.substr(0, sep);
        if (authority.empty() || authority.contains('@')) return std::unexpected("invalid outbound probe authority");
        auto dial = std::string(authority);
        if (!authority.contains(':') || authority.ends_with(']')) dial += use_tls ? ":443" : ":80";
        auto parsed = http::parse_destination_authority(dial);
        if (parsed.status != http::ConnectStatus::accepted) return std::unexpected("invalid outbound probe address");

        socks5::Request request;
        request.status = socks5::Status::accepted;
        request.port = parsed.port;
        std::string host_name;
        if (parsed.kind == http::HostKind::domain) {
            request.address_type = 3;
            request.address_length = static_cast<std::uint8_t>(parsed.host.size());
            std::ranges::copy(parsed.host, request.address.begin());
            host_name = std::string(parsed.host);
        } else {
            request.address_type = parsed.kind == http::HostKind::ipv4 ? 1 : 4;
            request.address_length = parsed.kind == http::HostKind::ipv4 ? 4 : 16;
            std::ranges::copy(parsed.address, request.address.begin());
            auto end = authority.starts_with('[') ? authority.find(']') : authority.rfind(':');
            host_name = authority.starts_with('[') && end != authority.npos ?
                std::string(authority.substr(1, end - 1)) :
                std::string(end != authority.npos ? authority.substr(0, end) : authority);
        }
        auto path = sep == url.npos ? std::string_view("/") : url.substr(sep);
        auto wire = "HEAD " + std::string(path.starts_with('/') ? "" : "/") + std::string(path) +
            " HTTP/1.1\r\nHost: " + std::string(authority) + "\r\nConnection: close\r\n\r\n";
        return ParsedProbeTarget{request, std::move(wire), use_tls, std::move(host_name)};
    }

    inline auto overlay_selector_state(config::Config& candidate, std::span<SelectorChoice const> choices)
        -> std::expected<void, std::string> {
        for (auto const& choice : choices) {
            auto group = std::ranges::find(candidate.selectors, choice.group, &config::OutboundSelector::name);
            if (group == candidate.selectors.end() || group->mode != config::OutboundGroupMode::select ||
                std::ranges::find(group->members, choice.member) == group->members.end())
                return std::unexpected("selector state does not match a configured manual group and member");
            group->selected = choice.member;
        }
        return {};
    }

    inline auto initialize_selector_state(SelectorState& state, config::Config& config)
        -> std::expected<void, std::string> {
        if (config.selector_state_directory.empty()) {
            if (config.state && !config.state->directory.empty())
                return state.open_route_mode_only(config.state->directory);
            return {};
        }
        auto opened = state.open(config.selector_state_directory);
        if (!opened || state.choices().empty()) return opened;
        auto requested = config;
        auto restored = overlay_selector_state(requested, state.choices());
        if (!restored) return restored;
        auto next = config::reselect_outbounds(config, requested);
        if (!next) return std::unexpected("selector state: " + next.error());
        config = std::move(*next);
        return {};
    }

    inline auto build_group_tag_map(config::Config const& config) -> std::shared_ptr<relay::GroupTagMap const> {
        if (config.selectors.empty()) return {};
        auto map = std::make_shared<relay::GroupTagMap>();
        map->selector_names.reserve(config.selectors.size());
        auto find_sel = [&](std::string_view name) -> std::optional<std::size_t> {
            auto it = std::ranges::find(config.selectors, name, &config::OutboundSelector::name);
            return it == config.selectors.end() ? std::nullopt :
                std::optional<std::size_t>(static_cast<std::size_t>(it - config.selectors.begin()));
        };
        for (auto const& s : config.selectors) map->selector_names.push_back(s.name);
        map->default_group = find_sel(config.default_outbound_name);
        map->indexed_rule_groups.reserve(config.routes.size());
        for (auto const& r : config.routes) map->indexed_rule_groups.push_back(find_sel(r.outbound_name));
        if (config.ordered_tcp) {
            map->ordered_rule_groups.reserve(config.ordered_tcp->rules.size());
            for (auto const& r : config.ordered_tcp->rules)
                map->ordered_rule_groups.push_back(r.outbound_name ? find_sel(*r.outbound_name) : std::nullopt);
        }
        std::size_t total = 2 + config.tunnel_count();
        map->unique_outbound_group.resize(total);
        std::vector<std::uint8_t> counts(total, 0);
        for (std::size_t i = 0; i < config.selectors.size(); ++i) {
            auto const& sel = config.selectors[i];
            if (sel.mode == config::OutboundGroupMode::load_balance) {
                for (auto const& m : sel.members)
                    if (auto ob = config::configured_outbound_index(config, m); ob && *ob < total) {
                        if (counts[*ob] < 2) ++counts[*ob];
                        if (counts[*ob] == 1) map->unique_outbound_group[*ob] = i;
                        else map->unique_outbound_group[*ob].reset();
                    }
            } else if (auto ob = config::configured_outbound_index(config, sel.selected_leaf); ob && *ob < total) {
                if (counts[*ob] < 2) ++counts[*ob];
                if (counts[*ob] == 1) map->unique_outbound_group[*ob] = i;
                else map->unique_outbound_group[*ob].reset();
            }
        }
        return map;
    }

    inline auto interrupt_group_sessions(auto const& listeners, config::Config const& prev,
        config::Config const& next, std::optional<std::size_t> only_group = {}) -> std::size_t {
        std::size_t closed = 0;
        for (std::size_t i = 0; i < next.selectors.size() && i < prev.selectors.size(); ++i) {
            if (only_group && *only_group != i) continue;
            auto const& ng = next.selectors[i];
            if (!ng.interrupt_exist_connections || prev.selectors[i].selected_leaf == ng.selected_leaf) continue;
            auto old_ob = config::configured_outbound_index(prev, prev.selectors[i].selected_leaf);
            for (auto const& listener : listeners)
                closed += listener.server->close_group_sessions(ng.name, old_ob);
        }
        return closed;
    }

    inline auto interrupt_balance_demoted(auto const& listeners, config::Config const& cfg,
        std::size_t group_idx, std::span<std::size_t const> demoted_members) -> std::size_t {
        if (group_idx >= cfg.selectors.size()) return 0;
        auto const& group = cfg.selectors[group_idx];
        if (!group.interrupt_exist_connections) return 0;
        std::size_t closed = 0;
        for (auto member_idx : demoted_members) {
            if (member_idx >= group.members.size()) continue;
            auto ob = config::configured_outbound_index(cfg, group.members[member_idx]);
            for (auto const& listener : listeners)
                closed += listener.server->close_group_sessions(group.name, ob);
        }
        return closed;
    }

    inline auto durable_fakeip_view(config::Config const& config) -> std::uint64_t {
        auto const& routing = *config.dns;
        auto material = routing.message_cache_policy + routing.cache_rule_fingerprints;
        for (auto const& group : config.selectors) {
            material.push_back('\0'); material += group.selected;
            material.push_back('\0'); material += group.selected_leaf;
        }
        auto digest = ::state::fingerprint(std::as_bytes(std::span(material)));
        std::uint64_t view = 0;
        for (auto byte : std::span(digest).first<8>()) view = (view << 8) | std::to_integer<unsigned>(byte);
        return view;
    }

    inline auto handle_network_generation_change(auto& listeners, auto& dns_messages, auto& reverse_cache,
        auto& group_health, auto& control_operations, auto const& network, std::uint64_t& last_gen) -> void {
        auto snap = network ? network->get() : nullptr;
        if (!snap || snap->generation == last_gen) return;
        bool const changed = last_gen != 0;
        last_gen = snap->generation;
        if (!changed) return;
        if (group_health) group_health->invalidate_network();
        for (auto& l : listeners) l.server->request_memory_reclaim(2);
        dns_messages.reclaim_memory(true);
        if (reverse_cache) (void)reverse_cache->clear();
        control_operations.record(std::remove_cvref_t<decltype(control_operations)>::EventKind::network_changed);
    }
}
