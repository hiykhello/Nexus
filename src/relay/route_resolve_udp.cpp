// Private UDP ordered routing implementation for proxy runtime.
module relay;
import std;
import capy;
import corosio;
import dns.message;
import dns.reverse;
import net.datagram_frame;
import net.ordered_datagram;
import platform.ip_address;
import rules;
import sniff.route_tcp;
import sniff.tcp;
import sniff.udp_quic;

namespace relay {
    auto ordered_datagram_router(Session& session, corosio::io_context& context, std::optional<net::UdpEndpoint> source,
        std::optional<bool> fakeip_alias)
        -> net::stream_datagrams::OrderedRouter {
        return [&session, &context, source, fakeip_alias](net::ProxyAddress const& target, std::span<std::uint8_t const> payload, Clock::time_point received,
            Clock::time_point& deadline, net::stream_datagrams::OrderedSniffer const& inspect)
            -> capy::task<std::optional<net::stream_datagrams::OrderedSelection>> {
            auto const* ordered = session.ordered_tcp;
            if (!ordered || !ordered->udp || session.closed || !target.port || target.length > target.bytes.size() || Clock::now() >= deadline) co_return std::nullopt;
            auto const& policy = *ordered;
            rules::ProgramInput input{.port = target.port, .network = rules::Network::udp};
            session.fill_program_input(input);
            if (policy.program.has_dns_hijack()) input.dns_query = dns::parse_query(payload).has_value();
            input = session.ingress.apply(input);
            if (fakeip_alias == false) input.domain_absent[static_cast<std::size_t>(rules::DomainSource::fakeip)] = true;
            if (source) {
                input.source_port = source->port;
                input.source_ip_bytes = std::span(source->address).first(source->family == 4 ? 4 : 16);
            }
            std::string address, sniffed, sniffed_client;
            std::optional<dns::ReverseName> reverse_name;
            std::vector<corosio::endpoint> endpoints;
            sniff::RouteCandidates candidates;
            if (target.family == net::ProxyAddressFamily::domain) {
                address.assign(reinterpret_cast<char const*>(target.bytes.data()), target.length);
                if (fakeip_alias == true) {
                    input.fakeip_domain = address;
                    input.domain_absent[static_cast<std::size_t>(rules::DomainSource::explicit_target)] = true;
                } else {
                    if (!rules::valid_domain(address)) co_return std::nullopt;
                    input.explicit_domain = address;
                }
                input.domain_absent[static_cast<std::size_t>(rules::DomainSource::reverse_dns)] = true;
            } else {
                corosio::endpoint endpoint;
                dns::Address rev_addr{};
                if (target.family == net::ProxyAddressFamily::ipv4 && target.length == 4) {
                    corosio::ipv4_address::bytes_type bytes{}; std::copy_n(target.bytes.begin(), 4, bytes.begin());
                    endpoint = {corosio::ipv4_address(bytes), target.port};
                    rev_addr.size = 4; std::copy_n(bytes.begin(), 4, rev_addr.bytes.begin());
                } else if (target.family == net::ProxyAddressFamily::ipv6 && target.length == 16) {
                    corosio::ipv6_address::bytes_type bytes{}; std::copy_n(target.bytes.begin(), 16, bytes.begin());
                    endpoint = {corosio::ipv6_address(bytes), target.port};
                    rev_addr.size = 16; std::copy_n(bytes.begin(), 16, rev_addr.bytes.begin());
                } else co_return std::nullopt;
                address = endpoint.address().to_string(); input.ip = address; endpoints.push_back(endpoint);
                input.domain_absent[static_cast<std::size_t>(rules::DomainSource::explicit_target)] = true;
                if (session.reverse_cache) {
                    auto now_ms = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                        received.time_since_epoch()).count());
                    if (auto found = session.reverse_cache->lookup(session.reverse_view, rev_addr, now_ms)) {
                        reverse_name = *found; input.reverse_domain = reverse_name->view();
                    } else input.domain_absent[static_cast<std::size_t>(rules::DomainSource::reverse_dns)] = true;
                } else input.domain_absent[static_cast<std::size_t>(rules::DomainSource::reverse_dns)] = true;
            }
            auto domain = input.fakeip_domain ? input.fakeip_domain : input.explicit_domain;
            bool override_with_sniff = false;
            auto resolve = [&](ResolveOverride ov = {}) -> capy::task<bool> {
                auto target_domain = (override_with_sniff && input.sniffed_domain) ? input.sniffed_domain : domain;
                if (!target_domain) co_return true;
                policy::DnsContext dns{.network = rules::Network::udp};
                if (source) { dns.source_port = source->port; dns.source_ip_bytes = std::span(source->address).first(source->family == 4 ? 4 : 16); }
                auto result = co_await resolve_destination(session, context, std::string(*target_domain), target.port, deadline, dns, ov);
                if (!result || session.closed || Clock::now() >= deadline) co_return false;
                if (!input.ip && !candidates.assign(*result, input)) co_return false;
                endpoints = std::move(*result); co_return true;
            };
            rules::ProgramCursor cursor;
            std::size_t selected = policy.fallback;
            std::optional<std::size_t> route_rule;
            std::optional<std::string> ov_addr;
            std::uint16_t ov_port = 0;
            auto capture_override = [&](rules::ProgramAction const& act) {
                if (act.override_address) ov_addr = act.override_address;
                if (act.override_port) ov_port = act.override_port;
            };
            input.route_mode = session.active_route_mode();
            if (input.route_mode == rules::RouteMode::rule || policy.program.has_dns_hijack()) for (;;) {
                auto step = cursor.poll(policy.program, input); if (!step) co_return std::nullopt;
                if (step->kind == rules::ProgramPreflightKind::uncertain) {
                    if (policy.unknown_policy != sniff::UnknownRoutePolicy::skip || !cursor.skip_unknown(step->rule_index)) co_return std::nullopt;
                    continue;
                }
                if (step->kind == rules::ProgramPreflightKind::exhausted) break;
                auto action = *step->step;
                if (action.action.kind == rules::ProgramActionKind::reject) {
                    if (input.route_mode != rules::RouteMode::rule) break;
                    co_return std::nullopt;
                }
                if (auto timeout = action.action.connect_timeout_ms) {
                    deadline = std::min(deadline, received + std::chrono::milliseconds(timeout));
                    if (Clock::now() >= deadline) co_return std::nullopt;
                }
                if (action.action.kind == rules::ProgramActionKind::hijack_dns) {
                    if (!source || fakeip_alias == true) co_return std::nullopt;
                    auto credit = session.reserve_principal_datagram(true, payload.size());
                    if (!credit) co_return std::nullopt;
                    credit->submit();
                    auto reply = co_await hijack_dns_query(session, context, payload, *source, deadline);
                    credit->complete(payload.size());
                    if (!reply) co_return std::nullopt;
                    session.count_traffic(true, payload.size());
                    co_return net::stream_datagrams::OrderedSelection{.outbound = 0, .rule = action.rule_index,
                        .dns_reply = std::move(reply)};
                }
                if (action.action.kind == rules::ProgramActionKind::route) {
                    capture_override(action.action);
                    selected = action.action.outbound;
                    route_rule = action.rule_index;
                    break;
                }
                if (action.action.kind == rules::ProgramActionKind::route_options) {
                    capture_override(action.action);
                    if (!cursor.complete(action)) co_return std::nullopt;
                } else if (action.action.kind == rules::ProgramActionKind::resolve) {
                    ResolveOverride ov{action.action.resolve_strategy, action.action.resolve_server, action.action.resolve_disable_cache, action.action.resolve_rewrite_ttl};
                    if (action.action.resolve_client_subnet) {
                        auto const& s = *action.action.resolve_client_subnet;
                        ov.client_subnet = dns::ClientSubnet{static_cast<std::uint16_t>(s.size == 4 ? 1 : 2), s.bits, s.address};
                    }
                    if (!co_await resolve(ov) || !cursor.complete(action)) co_return std::nullopt;
                } else if (action.action.kind == rules::ProgramActionKind::sniff) {
                    auto allowed = [&](rules::Protocol p) {
                        return action.action.sniff_protocols == 0 || (action.action.sniff_protocols & rules::protocol_mask(p)) != 0;
                    };
                    if (action.action.sniff_override_destination) override_with_sniff = true;
                    auto query = allowed(rules::Protocol::dns) ? dns::parse_query(payload)
                        : std::expected<dns::QueryMessage, dns::MessageError>(std::unexpected(dns::MessageError::truncated));
                    input.sniffed_domain.reset();
                    if (query) {
                        input.protocol = rules::Protocol::dns;
                        if (rules::valid_domain(query->question.name)) {
                            sniffed = std::move(query->question.name); input.sniffed_domain = sniffed;
                        }
                    } else if (allowed(rules::Protocol::stun) && sniff::stun_datagram(payload)) {
                        input.protocol = rules::Protocol::stun;
                        input.domain_absent[static_cast<std::size_t>(rules::DomainSource::sniffed)] = true;
                    } else if (allowed(rules::Protocol::dtls) && sniff::inspect_dtls_udp(payload)) {
                        input.protocol = rules::Protocol::dtls;
                        input.domain_absent[static_cast<std::size_t>(rules::DomainSource::sniffed)] = true;
                    } else if (allowed(rules::Protocol::ntp) && sniff::inspect_ntp_udp(payload)) {
                        input.protocol = rules::Protocol::ntp;
                        input.domain_absent[static_cast<std::size_t>(rules::DomainSource::sniffed)] = true;
                    } else if (allowed(rules::Protocol::bittorrent) && sniff::inspect_bittorrent_udp(payload)) {
                        input.protocol = rules::Protocol::bittorrent;
                        input.domain_absent[static_cast<std::size_t>(rules::DomainSource::sniffed)] = true;
                    } else if (allowed(rules::Protocol::quic)) {
                        auto to_ms = action.action.sniff_timeout_ms ? std::chrono::milliseconds(action.action.sniff_timeout_ms) : policy.sniff_timeout;
                        auto quic = co_await inspect(std::min(deadline, Clock::now() + to_ms));
                        if (quic.status == sniff::QuicProbeStatus::matched) {
                            input.protocol = rules::Protocol::quic;
                            if (quic.domain) {
                                sniffed = std::move(*quic.domain); input.sniffed_domain = sniffed;
                            }
                            if (quic.client) {
                                sniffed_client = std::move(*quic.client); input.client = sniffed_client;
                            }
                        }
                    }
                    if (!cursor.complete(action)) co_return std::nullopt;
                } else co_return std::nullopt;
                if (session.closed || Clock::now() >= deadline) co_return std::nullopt;
            }
            if (override_with_sniff && input.sniffed_domain && !ov_addr) domain = input.sniffed_domain;
            if (auto ov = session.mode_override_outbound(domain.value_or(input.ip.value_or("")))) {
                selected = *ov; route_rule.reset();
            } else if (session.route_snapshot)
                selected = session.route_snapshot->matcher.choose_outbound(selected, domain.value_or(input.ip.value_or("")));
            if (selected == 1) co_return std::nullopt;
            if (ov_addr) {
                auto port = ov_port ? ov_port : target.port;
                if (auto literal = platform::parse_ip_address(*ov_addr)) {
                    if (literal->size == 4) {
                        corosio::ipv4_address::bytes_type b{}; std::copy_n(literal->bytes.begin(), 4, b.begin());
                        endpoints = {corosio::endpoint(corosio::ipv4_address(b), port)};
                    } else {
                        endpoints = {corosio::endpoint(corosio::ipv6_address(literal->bytes), port)};
                    }
                } else {
                    policy::DnsContext dns{.network = rules::Network::udp};
                    if (source) { dns.source_port = source->port; dns.source_ip_bytes = std::span(source->address).first(source->family == 4 ? 4 : 16); }
                    auto result = co_await resolve_destination(session, context, *ov_addr, port, deadline, dns);
                    if (!result || session.closed || Clock::now() >= deadline) co_return std::nullopt;
                    endpoints = std::move(*result);
                }
            } else {
                if (domain && (override_with_sniff || !candidates.view()) && !co_await resolve()) co_return std::nullopt;
                if (ov_port) {
                    if (endpoints.empty() && !domain &&
                        (target.family == net::ProxyAddressFamily::ipv4 || target.family == net::ProxyAddressFamily::ipv6)) {
                        net::stream_datagrams::OrderedSelection result{selected, {}, route_rule};
                        net::UdpEndpoint peer{target.family == net::ProxyAddressFamily::ipv4 ? std::uint8_t{4} : std::uint8_t{6}, {}, ov_port};
                        std::copy_n(target.bytes.begin(), peer.family == 4 ? 4 : 16, peer.address.begin());
                        result.candidates.push_back(peer);
                        co_return result;
                    }
                    for (auto& ep : endpoints) ep = corosio::endpoint(ep.address(), ov_port);
                }
            }
            net::stream_datagrams::OrderedSelection result{selected, {}, route_rule};
            for (auto const& endpoint : endpoints) {
                if (endpoint.address().is_v6() && endpoint.address().to_v6().scope_id()) continue;
                net::UdpEndpoint peer{endpoint.address().is_v4() ? std::uint8_t{4} : std::uint8_t{6}, {}, endpoint.port()};
                if (peer.family == 4) { auto bytes = endpoint.address().to_v4().to_bytes(); std::ranges::copy(bytes, peer.address.begin()); }
                else { auto bytes = endpoint.address().to_v6().to_bytes(); std::ranges::copy(bytes, peer.address.begin()); }
                result.candidates.push_back(peer);
            }
            co_return result;
        };
    }
}
