// SOCKS5 UDP associate driver, QUIC sniffing, resolution, and ordered routing.
module relay;
import :session_internal;
import :session_udp_alias_tunnel;
import std;
import capy;
import corosio;
import dns.message;
import net.datagram_frame;
import net.lazy_readers;
import relay.request_backend;
import rules;
import sniff.route_tcp;
import sniff.tcp;
import sniff.udp_quic;
import socks5;
import socks5.udp_direct;
import socks5.udp_ingress;
import socks5.udp_route;

namespace relay {
#ifdef NEXUS_ENABLE_SOCKS_UDP
    namespace session_udp_detail {
        namespace {
            auto udp_control(Session& session, socks5::UdpIngress& ingress) -> capy::task<capy::results<>> {
                std::array<std::uint8_t, 256> buffer{};
                try {
                    while (!session.closed) {
                        auto [error, count] = co_await session.client.read_some(capy::mutable_buffer(buffer.data(), buffer.size()));
                        if (error || !count) break;
                    }
                    session.close();
                    ingress.wake();
                    co_return capy::results<>{};
                } catch (...) { session.close(); ingress.wake(); throw; }
            }

            auto udp_drive(Session& session, io::io_context& context, socks5::UdpIngress& ingress,
                UdpResolution& resolution, UotState& uot_state) -> capy::task<capy::results<>> {
                using namespace std::chrono_literals;
                try {
                    while (!session.closed) {
                        socks5::UdpIngressStep report;
                        bool busy = false;
                        for (unsigned batch = 0; batch < 64 && !session.closed; ++batch) {
                            auto result = ingress.step();
                            if (!result || result->output_error) { session.close(); break; }
                            report = *result;
                            if (result->forwarded || result->delivered) session.touched = Clock::now();
                            if (resolution.active && !resolution.canceled && Clock::now() >= resolution.deadline) {
                                resolution.canceled = true;
                                if (session.cancel_dns) session.cancel_dns(session.dns_operation);
                            }
#ifdef NEXUS_ENABLE_FAKEIP
                            if (uot_state.aliases) uot_state.aliases->expire(Clock::now());
#endif
                            if (uot_state.active_deadline && Clock::now() >= *uot_state.active_deadline) {
                                session.close(); uot_state.cancel(); break;
                            }
                            busy = (result->input && !result->input_backpressured && !result->domain_pending && !result->route_pending && !result->tunnel_pending) ||
                                result->forwarded || result->delivered || result->output_dropped || result->input_error.has_value();
                            if (!busy) break;
                        }
                        if (session.closed) break;
                        auto deadline = uot_state.active_deadline.value_or(Clock::time_point::max());
                        if (resolution.active && !resolution.canceled) deadline = std::min(deadline, resolution.deadline);
                        auto ready = co_await ingress.wait(context, report, deadline);
                        if (!ready) { session.close(); break; }
                    }
                    uot_state.cancel(); ingress.close();
                    co_return capy::results<>{};
                } catch (...) { uot_state.cancel(); ingress.close(); session.close(); throw; }
            }

            auto udp_resolve(Session& session, io::io_context& context, socks5::UdpIngress& ingress,
                UdpResolution& resolution, [[maybe_unused]] rules::RouteProgram const& policy) -> capy::task<capy::results<>> {
                using namespace std::chrono_literals;
                try {
                    while (!session.closed) {
                        ingress.changed().clear();
#ifdef NEXUS_ENABLE_FAKEIP
                        if (ingress.pending_route()) {
                            co_await udp_resolve_alias(session, context, ingress, resolution, policy);
                            ingress.discard_route();
                            continue;
                        }
#endif
                        auto packet = ingress.pending_domain();
                        if (!packet) {
                            auto [error] = co_await ingress.changed().wait();
                            if (error) { session.close(); break; }
                            continue;
                        }
                        auto name = std::string(reinterpret_cast<char const*>(packet->address.data()), packet->address_length);
                        auto port = packet->port;
                        auto peer = ingress.pending_domain_source();
                        if (!peer) { ingress.discard_domain(); continue; }
                        auto source = socks5::udp_endpoint(*peer);
                        resolution = {true, false, ingress.pending_domain_deadline()};
                        if (Clock::now() >= resolution.deadline) { ingress.discard_domain(); resolution.active = false; continue; }
                        auto endpoints = co_await resolve_udp_domain(session, context, std::move(name), port, resolution.deadline, &source);
                        if (session.closed) break;
                        if (endpoints && !resolution.canceled) {
                            for (auto const& endpoint : *endpoints) {
                                if (endpoint.address().is_v6() && endpoint.address().to_v6().scope_id() != 0) continue;
                                socks5::UdpPeer candidate{endpoint.address().is_v4() ? std::uint8_t{1} : std::uint8_t{4}, {}, endpoint.port()};
                                if (candidate.address_type == 1) {
                                    auto bytes = endpoint.address().to_v4().to_bytes(); std::ranges::copy(bytes, candidate.address.begin());
                                } else {
                                    auto bytes = endpoint.address().to_v6().to_bytes(); std::ranges::copy(bytes, candidate.address.begin());
                                }
                                while (!session.closed && !resolution.canceled && Clock::now() < resolution.deadline) {
                                    auto sent = ingress.send_resolved(candidate);
                                    if (sent) { session.touched = Clock::now(); break; }
                                    auto error = std::get_if<std::error_code>(&sent.error());
                                    if (!error || (*error != std::errc::resource_unavailable_try_again && *error != std::errc::interrupted)) break;
                                    auto [delay_error] = co_await io::delay(5ms);
                                    if (delay_error) { session.close(); break; }
                                }
                                if (!ingress.pending_domain() || session.closed || resolution.canceled) break;
                            }
                        }
                        ingress.discard_domain(); resolution.active = false;
                    }
                    co_return capy::results<>{};
                } catch (...) { session.close(); throw; }
            }

            auto udp_inspect_quic(Session& session, socks5::UdpIngress& ingress, UdpResolution& resolution,
                std::chrono::milliseconds timeout) -> capy::task<sniff::QuicProbeResult> {
                using namespace std::chrono_literals;
                auto metadata = ingress.route_metadata();
                if (!metadata) co_return sniff::QuicProbeResult{};
                if (metadata->quic_inspected) co_return sniff::QuicProbeResult{
                    metadata->quic_matched ? sniff::QuicProbeStatus::matched : sniff::QuicProbeStatus::unknown,
                    metadata->quic_domain};
                auto packet = ingress.pending_route(); auto source = ingress.pending_route_source();
                if (!packet || !source) co_return sniff::QuicProbeResult{};
                sniff::QuicProbeResult classification;
                std::array<std::size_t, 8> members{}; std::size_t count = 0;
                auto limit = std::min(resolution.deadline, Clock::now() + timeout);
                if (auto probe = sniff::make_quic_probe()) {
                    auto initial = probe->feed(packet->data);
                    if (initial.status == sniff::QuicProbeStatus::matched) classification = std::move(initial);
                    else if (initial.status == sniff::QuicProbeStatus::waiting) {
                        if (!ingress.begin_route_lookahead()) { session.close(); co_return sniff::QuicProbeResult{}; }
                        struct Collect { socks5::UdpIngress& ingress; ~Collect() { ingress.end_route_lookahead(); } } collect{ingress};
                        std::size_t index = 0;
                        while (!session.closed && !resolution.canceled && Clock::now() < limit) {
                            ingress.changed().clear();
                            auto next = ingress.lookahead_route(index);
                            if (!next) {
                                if (ingress.route_lookahead_full()) break;
                                auto [error] = co_await corosio::timeout(ingress.changed().wait(), limit);
                                if (error && !capy::is_timeout(error)) session.close();
                                continue;
                            }
                            auto current = index++;
                            auto const& target = next->packet;
                            if (Clock::now() >= next->deadline || next->source != *source || target.address_type != packet->address_type ||
                                target.port != packet->port || target.address_length != packet->address_length ||
                                !std::equal(target.address.begin(), target.address.begin() + target.address_length, packet->address.begin())) continue;
                            if (count >= members.size()) break;
                            auto observed = probe->feed(target.data);
                            if (observed.status == sniff::QuicProbeStatus::unrelated) continue;
                            // Unknown includes an authenticated conflicting fragment;
                            // it must not be independently re-sniffed during replay.
                            members[count++] = current; limit = std::min(limit, next->deadline);
                            if (observed.status == sniff::QuicProbeStatus::matched) { classification = std::move(observed); break; }
                            if (observed.status == sniff::QuicProbeStatus::unknown) break;
                        }
                    }
                }
                if (session.closed || resolution.canceled) co_return sniff::QuicProbeResult{};
                if (Clock::now() >= limit) classification = {};
                auto matched = classification.status == sniff::QuicProbeStatus::matched;
                if (!ingress.remember_route_sniff(classification.domain, matched)) {
                    session.close(); co_return sniff::QuicProbeResult{};
                }
                for (std::size_t i = 0; i < count; ++i) {
                    auto member = ingress.lookahead_route(members[i]);
                    if (member && Clock::now() < member->deadline &&
                        !ingress.remember_lookahead_sniff(members[i], classification.domain, matched)) {
                        session.close(); co_return sniff::QuicProbeResult{};
                    }
                }
                co_return classification;
            }

            auto udp_ordered(Session& session, io::io_context& context, socks5::UdpIngress& ingress,
                UdpResolution& resolution) -> capy::task<capy::results<>> {
                using namespace std::chrono_literals;
                try {
                    while (!session.closed) {
                        ingress.changed().clear();
                        if (!ingress.pending_route()) (void)ingress.replay_deferred();
                        auto packet = ingress.pending_route(); auto peer = ingress.pending_route_source();
                        if (!packet || !peer) { auto [error] = co_await ingress.changed().wait(); if (error) session.close(); continue; }
                        auto metadata = ingress.route_metadata();
                        if (!metadata || Clock::now() >= metadata->deadline) { ingress.discard_route(); continue; }
                        resolution = {true, false, metadata->deadline};
                        auto source = socks5::udp_endpoint(*peer);
                        rules::ProgramInput input{.port = packet->port, .network = rules::Network::udp,
                            .source_port = source.port, .source_ip_bytes = std::span(source.address).first(source.family == 4 ? 4 : 16),
                            .inbound = session.inbound, .auth_user = session.auth_user};
                        session.fill_program_input(input);
                        auto routed_packet = *packet;
#ifdef NEXUS_ENABLE_FAKEIP
                        std::shared_ptr<UdpFakeIpLease> lease;
                        if (session.fakeip) {
                            std::shared_ptr<UdpFakeIpLease> owner;
                            if (packet->address_type != 3) owner = std::make_shared<UdpFakeIpLease>();
                            auto translated = udp_fakeip_target(session, *packet);
                            if (!translated) { ingress.discard_route(); resolution.active = false; continue; }
                            if (translated->target) {
                                owner->target = std::move(translated->target);
                                routed_packet = udp_fakeip_domain(*packet, translated->request);
                                input.fakeip_domain = owner->target->mapping().domain;
                                input.domain_absent[static_cast<std::size_t>(rules::DomainSource::explicit_target)] = true;
                                lease = std::move(owner);
                            } else input.domain_absent[static_cast<std::size_t>(rules::DomainSource::fakeip)] = true;
                        }
#endif
                        std::string address, sniffed, sniffed_client;
                        bool override_with_sniff = false;
                        std::vector<io::endpoint> endpoints;
                        sniff::RouteCandidates candidates;
                        if (routed_packet.address_type == 3) {
                            if (!input.fakeip_domain) {
                                address.assign(reinterpret_cast<char const*>(routed_packet.address.data()), routed_packet.address_length);
                                input.explicit_domain = address;
                            }
                        } else {
                            io::endpoint endpoint;
                            if (packet->address_type == 1) {
                                io::ipv4_address::bytes_type bytes{}; std::copy_n(packet->address.begin(), 4, bytes.begin()); endpoint = {io::ipv4_address(bytes), packet->port};
                            } else { io::ipv6_address::bytes_type bytes{}; std::copy_n(packet->address.begin(), 16, bytes.begin()); endpoint = {io::ipv6_address(bytes), packet->port}; }
                            address = endpoint.address().to_string(); input.ip = address; endpoints.push_back(endpoint);
                            input.domain_absent[static_cast<std::size_t>(rules::DomainSource::explicit_target)] = true;
                        }
                        auto domain = input.fakeip_domain ? input.fakeip_domain : input.explicit_domain;
                        auto resolve = [&](ResolveOverride ov = {}) -> capy::task<bool> {
                            auto target_domain = (override_with_sniff && input.sniffed_domain) ? input.sniffed_domain : domain;
                            if (!target_domain) co_return true;
                            auto result = co_await resolve_destination(session, context, std::string(*target_domain), packet->port, resolution.deadline,
                                {.network = rules::Network::udp, .source_port = source.port, .source_ip_bytes = std::span(source.address).first(source.family == 4 ? 4 : 16)}, ov);
                            if (!result || resolution.canceled || session.closed || Clock::now() >= resolution.deadline) co_return false;
                            if (!input.ip && !candidates.assign(*result, input)) co_return false;
                            endpoints = std::move(*result); co_return true;
                        };
                        rules::ProgramCursor cursor; auto const& policy = *session.ordered_tcp;
                        if (policy.program.has_dns_hijack()) input.dns_query = dns::parse_query(packet->data).has_value();
                        input.route_mode = session.active_route_mode();
                        std::size_t selected = policy.fallback; bool valid = true;
                        bool udp_disable_unmapping = false;
                        std::optional<std::size_t> route_rule;
                        if (input.route_mode == rules::RouteMode::rule || policy.program.has_dns_hijack()) for (;;) {
                            auto step = cursor.poll(policy.program, input);
                            if (!step) { valid = false; break; }
                            if (step->kind == rules::ProgramPreflightKind::uncertain) {
                                if (policy.unknown_policy != sniff::UnknownRoutePolicy::skip || !cursor.skip_unknown(step->rule_index)) { valid = false; break; }
                                continue;
                            }
                            if (step->kind == rules::ProgramPreflightKind::exhausted) break;
                            auto action = *step->step;
                            if (action.action.kind == rules::ProgramActionKind::reject) { if (input.route_mode != rules::RouteMode::rule) break; valid = false; break; }
                            if (action.action.kind == rules::ProgramActionKind::hijack_dns) {
                                auto response = co_await hijack_dns_query(session, context, packet->data, source, resolution.deadline);
                                while (response && !session.closed && !resolution.canceled && Clock::now() < resolution.deadline) {
                                    auto queued = ingress.reply_route(*response);
                                    if (!queued || *queued != socks5::UdpReplyStatus::busy) break;
                                    auto [error] = co_await io::delay(5ms);
                                    if (error) { session.close(); break; }
                                }
                                valid = false; break;
                            }
                            if (auto timeout = action.action.connect_timeout_ms) {
                                resolution.deadline = ingress.limit_route(std::chrono::milliseconds(timeout));
                                if (Clock::now() >= resolution.deadline) { valid = false; break; }
                            }
                            if (action.action.kind == rules::ProgramActionKind::route || action.action.kind == rules::ProgramActionKind::bypass) {
                                if (action.action.udp_disable_domain_unmapping) udp_disable_unmapping = true;
                                selected = action.action.outbound;
                                route_rule = action.rule_index;
                                break;
                            }
                            if (action.action.kind == rules::ProgramActionKind::route_options) {
                                if (action.action.udp_disable_domain_unmapping) udp_disable_unmapping = true;
                                if (!cursor.complete(action)) { valid = false; break; }
                            } else if (action.action.kind == rules::ProgramActionKind::resolve) {
                                ResolveOverride ov{action.action.resolve_strategy, action.action.resolve_server, action.action.resolve_disable_cache, action.action.resolve_rewrite_ttl};
                                if (action.action.resolve_client_subnet) {
                                    auto const& s = *action.action.resolve_client_subnet;
                                    ov.client_subnet = dns::ClientSubnet{static_cast<std::uint16_t>(s.size == 4 ? 1 : 2), s.bits, s.address};
                                }
                                if (!co_await resolve(ov) || !cursor.complete(action)) { valid = false; break; }
                            } else if (action.action.kind == rules::ProgramActionKind::sniff) {
                                // Incomplete or unrecognized payloads retain unknown
                                // metadata for the configured policy to handle.
                                auto allowed = [&](rules::Protocol p) {
                                    return action.action.sniff_protocols == 0 || (action.action.sniff_protocols & rules::protocol_mask(p)) != 0;
                                };
                                if (action.action.sniff_override_destination) override_with_sniff = true;
                                auto query = allowed(rules::Protocol::dns) ? dns::parse_query(packet->data)
                                    : std::expected<dns::QueryMessage, dns::MessageError>(std::unexpected(dns::MessageError::truncated));
                                input.sniffed_domain.reset();
                                if (query) {
                                    input.protocol = rules::Protocol::dns;
                                    if (rules::valid_domain(query->question.name)) {
                                        sniffed = std::move(query->question.name); input.sniffed_domain = sniffed;
                                    }
                                } else if (allowed(rules::Protocol::stun) && sniff::stun_datagram(packet->data)) {
                                    input.protocol = rules::Protocol::stun;
                                    input.domain_absent[static_cast<std::size_t>(rules::DomainSource::sniffed)] = true;
                                } else if (allowed(rules::Protocol::dtls) && sniff::inspect_dtls_udp(packet->data)) {
                                    input.protocol = rules::Protocol::dtls;
                                    input.domain_absent[static_cast<std::size_t>(rules::DomainSource::sniffed)] = true;
                                } else if (allowed(rules::Protocol::ntp) && sniff::inspect_ntp_udp(packet->data)) {
                                    input.protocol = rules::Protocol::ntp;
                                    input.domain_absent[static_cast<std::size_t>(rules::DomainSource::sniffed)] = true;
                                } else if (allowed(rules::Protocol::bittorrent) && sniff::inspect_bittorrent_udp(packet->data)) {
                                    input.protocol = rules::Protocol::bittorrent;
                                    input.domain_absent[static_cast<std::size_t>(rules::DomainSource::sniffed)] = true;
                                } else if (allowed(rules::Protocol::quic)) {
                                    auto to_ms = action.action.sniff_timeout_ms ? std::chrono::milliseconds(action.action.sniff_timeout_ms) : policy.sniff_timeout;
                                    auto quic = co_await udp_inspect_quic(session, ingress, resolution, to_ms);
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
                                if (!cursor.complete(action)) { valid = false; break; }
                            } else { valid = false; break; }
                            if (session.closed || resolution.canceled || Clock::now() >= resolution.deadline) { valid = false; break; }
                        }
                        if (override_with_sniff && input.sniffed_domain) domain = input.sniffed_domain;
                        if (valid) {
                            if (auto ov = session.mode_override_outbound(domain.value_or(input.ip.value_or("")))) {
                                selected = *ov; route_rule.reset();
                            } else if (session.route_snapshot)
                                selected = session.route_snapshot->matcher.choose_outbound(selected, domain.value_or(input.ip.value_or("")));
                        }
                        if (valid && selected != 1 && domain && (override_with_sniff || !candidates.view())) valid = co_await resolve();
#ifdef NEXUS_ENABLE_FAKEIP
                        if (lease && !udp_disable_unmapping) {
                            if (valid && selected != 1 && !resolution.canceled && !session.closed)
                                co_await udp_send_alias(session, ingress, resolution, routed_packet, endpoints, lease, nullptr, *peer,
                                    route_rule, selected);
                            valid = false;
                        }
#endif
                        if (valid && selected != 1 && !resolution.canceled && !session.closed) {
                            for (auto const& endpoint : endpoints) {
                                if (endpoint.address().is_v6() && endpoint.address().to_v6().scope_id()) continue;
                                socks5::UdpPeer candidate{endpoint.address().is_v4() ? std::uint8_t{1} : std::uint8_t{4}, {}, endpoint.port()};
                                if (candidate.address_type == 1) { auto bytes = endpoint.address().to_v4().to_bytes(); std::ranges::copy(bytes, candidate.address.begin()); }
                                else { auto bytes = endpoint.address().to_v6().to_bytes(); std::ranges::copy(bytes, candidate.address.begin()); }
                                while (!session.closed && !resolution.canceled && Clock::now() < resolution.deadline) {
                                    auto sent = ingress.send_selected(candidate, selected, route_rule);
                                    if (sent) { session.touched = Clock::now(); break; }
                                    auto error = std::get_if<std::error_code>(&sent.error());
                                    if (!error || (*error != std::errc::resource_unavailable_try_again && *error != std::errc::interrupted)) break;
                                    auto [delay_error] = co_await io::delay(5ms); if (delay_error) session.close();
                                }
                                if (!ingress.pending_route() || session.closed || resolution.canceled) break;
                            }
                        }
                        ingress.discard_route(); resolution.active = false;
                    }
                    co_return capy::results<>{};
                } catch (...) { session.close(); throw; }
            }
        }
    }

    namespace session_detail {
        auto udp_associate(Session& session, io::io_context& context, rules::RouteProgram const& policy, socks5::Request const& request) -> capy::task<> {
            using namespace session_udp_detail;
            auto remote = accepted_peer(session.client); auto local = session.client.local_endpoint();
            bool ipv6 = remote.address().is_v6();
            if (!remote.port() || local.address().is_v6() != ipv6 || (request.address_type != 1 && request.address_type != 4) ||
                (ipv6 && (remote.address().to_v6().scope_id() || local.address().to_v6().scope_id()))) {
                (void)co_await reply(session.client, 8, {}, session); session.close(); session.done = true; co_return;
            }
            socks5::UdpPeer tcp{ipv6 ? std::uint8_t{4} : std::uint8_t{1}, {}, remote.port()}, hint{request.address_type, {}, request.port};
            socks5::UdpPeer bind{tcp.address_type, {}, 0};
            if (ipv6) {
                auto remote_bytes = remote.address().to_v6().to_bytes(); auto local_bytes = local.address().to_v6().to_bytes();
                std::ranges::copy(remote_bytes, tcp.address.begin()); std::ranges::copy(local_bytes, bind.address.begin());
            } else {
                auto remote_bytes = remote.address().to_v4().to_bytes(); auto local_bytes = local.address().to_v4().to_bytes();
                std::ranges::copy(remote_bytes, tcp.address.begin()); std::ranges::copy(local_bytes, bind.address.begin());
            }
            std::copy_n(request.address.begin(), request.address_length, hint.address.begin());
            auto association = socks5::UdpAssociation::create(tcp, hint);
            if (!association) { (void)co_await reply(session.client, 2, {}, session); session.close(); session.done = true; co_return; }
            session.begin_traffic(TrafficProtocol::socks_udp, 0);
            session.select_traffic_path(ConnectPath::datagrams);
            socks5::UdpIngress ingress(*association, policy, true, true, session.auth_user,
                session.direct_tcp_options ? &session.direct_tcp_options->binding : nullptr,
                session.ordered_tcp && session.ordered_tcp->udp, session.traffic_delivery(),
                {&session, [](void* owner, bool ordered, socks5::UdpSelection const& route) noexcept {
                    static_cast<Session*>(owner)->record_datagram_route(ordered,
                        {socks5::udp_endpoint(route.target), route.outbound, route.rule, route.predicate});
                }});
            if (session.principal) ingress.set_byte_budget(session.principal->bytes());
#ifdef NEXUS_ENABLE_FAKEIP
            if (session.fakeip) {
                ingress.set_destination_filter(session.fakeip, [](void const* context, socks5::UdpPeer const& target) noexcept {
                    auto const& owner = *static_cast<dns::FakeIpShared const*>(context);
                    auto address = std::span(target.address).first(target.address_type == 1 ? 4 : 16);
                    try { return bool(dns::validate_fakeip_resolution(owner, address)); }
                    catch (...) { return false; }
                });
            }
#endif
            UotState uot_state;
            UdpResolution resolution;
            auto endpoint = ingress.open(bind);
            if (!endpoint) { (void)co_await reply(session.client, 1, {}, session); session.close(); session.done = true; co_return; }
            io::endpoint bound;
            if (ipv6) bound = {io::ipv6_address(endpoint->address), endpoint->port};
            else {
                io::ipv4_address::bytes_type bytes{}; std::copy_n(endpoint->address.begin(), 4, bytes.begin());
                bound = {io::ipv4_address(bytes), endpoint->port};
            }
            if (session.udp_advertise.port()) bound = {session.udp_advertise.address(), endpoint->port};
            if (!co_await reply(session.client, 0, bound, session)) {
                ingress.close(); session.close(); session.done = true; co_return;
            }
            session.relaying = true;
            try {
                std::vector<capy::task<capy::results<>>> tasks;
                tasks.push_back(udp_control(session, ingress));
                tasks.push_back(udp_drive(session, context, ingress, resolution, uot_state));
                tasks.push_back(session.ordered_tcp && session.ordered_tcp->udp ? udp_ordered(session, context, ingress, resolution) : udp_resolve(session, context, ingress, resolution, policy));
                tasks.push_back(uot_sender(session, context, ingress, uot_state));
                if (session.tunnel_factories && !session.tunnel_factories->empty())
                    tasks.push_back(uot_state.readers.run([&session, &ingress, &uot_state](std::size_t index) {
                        return uot_reader(session, ingress, uot_state, index);
                    }));
                (void)co_await capy::when_all(std::move(tasks));
            } catch (...) { uot_state.cancel(); ingress.close(); session.close(); session.done = true; throw; }
            ingress.close(); association->close(); session.close(); session.done = true;
        }
    }
#endif
}
