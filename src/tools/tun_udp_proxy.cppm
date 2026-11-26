// TUN UDP proxy tunnel worker, ordered datagram router & self-loop/reject helpers.
export module cli.tun_udp_proxy;
import std;
import capy;
import dns.message;
import dns.reverse;
import net.datagram_frame;
import net.udp_dial;
import packet;
import packet.mux;
import platform.ip_address;
import relay;
import rules;
import sniff.route_tcp;
import sniff.udp_quic;
import udp;
import uot;

export namespace cli::tun_enabled {
    struct TunUdpProxyOps {
        using Clock = std::chrono::steady_clock;
        static constexpr std::size_t kMaxDirectUdpFlows = 4096;
        static constexpr std::size_t kMaxUdpReplies = 2048;

        template<class Impl>
        static auto udp_proxy_writer(Impl& host, std::shared_ptr<typename Impl::UdpProxyFlow> st)
            -> capy::task<capy::results<>> {
            while (!host.stop_flag.load(std::memory_order_acquire) && !st->failed) {
                if (st->tx_queue.empty()) {
                    st->work.clear();
                    auto [ec] = co_await st->work.wait();
                    if (ec) break;
                    continue;
                }
                auto pkt = std::move(st->tx_queue.front());
                st->tx_queue.pop_front();
                if (Clock::now() >= pkt.deadline) continue;
                if (!co_await st->tunnel->send(pkt.wire)) break;
                st->session.count_traffic(true, pkt.payload_size);
            }
            st->failed = true;
            co_return capy::results<>{};
        }

        template<class Impl>
        static auto udp_proxy_reader(Impl& host, bool is_v6, udp::FlowId flow, std::shared_ptr<typename Impl::UdpProxyFlow> st)
            -> capy::task<capy::results<>> {
            std::array<std::uint8_t, 65536> buf{};
            net::DatagramDecoder decoder(st->framing, st->first_target);
            while (!host.stop_flag.load(std::memory_order_acquire) && !st->failed) {
                auto n = co_await st->tunnel->read(buf);
                if (!n || *n == 0) break;
                auto span = std::span(buf).first(*n);
                while (!span.empty()) {
                    auto feed = decoder.feed(span);
                    span = span.subspan(feed.consumed);
                    if (feed.status == net::DatagramStatus::accepted) {
                        auto dg = decoder.packet();
                        if (dg && ((is_v6 && dg->destination.family == net::ProxyAddressFamily::ipv6) ||
                                   (!is_v6 && dg->destination.family == net::ProxyAddressFamily::ipv4))) {
                            typename Impl::UdpReply rep{is_v6, flow, {}, dg->destination.port, {dg->payload.begin(), dg->payload.end()}, st};
                            std::copy_n(dg->destination.bytes.begin(), is_v6 ? 16 : 4, rep.source.begin());
                            if (host.udp_replies.size() < kMaxUdpReplies) {
                                host.udp_replies.push_back(std::move(rep));
                                host.notify_tx();
                            }
                        }
                        (void)decoder.consume();
                    } else if (feed.status != net::DatagramStatus::incomplete) {
                        st->failed = true;
                        co_return capy::results<>{};
                    }
                }
            }
            st->failed = true;
            co_return capy::results<>{};
        }

        template<class Impl>
        static auto run_udp_proxy(Impl& host, bool is_v6, udp::FlowId flow, std::shared_ptr<typename Impl::UdpProxyFlow> st)
            -> capy::task<> {
            struct Guard {
                Impl& host; bool is_v6; udp::FlowId flow; std::shared_ptr<typename Impl::UdpProxyFlow> st;
                ~Guard() {
                    st->failed = true;
                    if (st->tunnel) st->tunnel->cancel();
                    st->session.close();
                    auto& flows = is_v6 ? host.udp6_proxy : host.udp4_proxy;
                    auto it = flows.find(flow);
                    if (it != flows.end()) {
                        std::erase(it->second, st);
                        if (it->second.empty()) flows.erase(it);
                    }
                }
            } guard{host, is_v6, flow, st};
            std::stop_callback cancel(st->session.stop.get_token(), [&]() noexcept {
                st->failed = true;
                st->work.set();
                st->tunnel->cancel();
            });
            if (co_await st->tunnel->connect(st->first_target, st->connect_deadline) != relay::PacketConnectResult::connected) co_return;
            if (Clock::now() >= st->connect_deadline) co_return;
            if (st->needs_uot_request) {
                auto req = uot::encode_request({false, st->first_target});
                if (!req || !co_await st->tunnel->send(*req) || Clock::now() >= st->connect_deadline) co_return;
            }
            st->session.select_traffic_path(relay::ConnectPath::tunnel);
            st->connected = true;
            (void)co_await capy::when_all(
                udp_proxy_writer(host, st),
                udp_proxy_reader(host, is_v6, flow, st));
        }

        // Numeric TUN destinations already carry the resolved address.
        static auto route_ordered_udp(std::span<std::uint8_t const> payload, rules::ProgramInput input,
            auto const& policy, Clock::time_point received, Clock::time_point& deadline,
            dns::ReverseCache* reverse_cache = nullptr, std::optional<dns::Address> target_addr = {}, std::uint64_t reverse_view = 0,
            std::uint32_t default_idle_ms = 60000, std::uint32_t* flow_idle_ms = nullptr)
            -> std::optional<rules::ProgramAction> {
            input.domain_absent[static_cast<std::size_t>(rules::DomainSource::explicit_target)] = true;
            input.domain_absent[static_cast<std::size_t>(rules::DomainSource::fakeip)] = true;
            std::optional<dns::ReverseName> reverse_name;
            if (reverse_cache && target_addr) {
                auto now_ms = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                    received.time_since_epoch()).count());
                if (auto found = reverse_cache->lookup(reverse_view, *target_addr, now_ms)) {
                    reverse_name = *found;
                    input.reverse_domain = reverse_name->view();
                } else input.domain_absent[static_cast<std::size_t>(rules::DomainSource::reverse_dns)] = true;
            } else input.domain_absent[static_cast<std::size_t>(rules::DomainSource::reverse_dns)] = true;
            std::string name, client_name;
            rules::ProgramCursor cursor;
            std::uint32_t udp_timeout_ms = 0;
            bool udp_adaptive = false;
            bool udp_disable_unmapping = false;
            std::optional<std::string> ov_addr;
            std::uint16_t ov_port = 0;
            auto apply_udp_opt = [&](rules::ProgramAction const& act) {
                if (act.udp_timeout_ms) udp_timeout_ms = act.udp_timeout_ms;
                if (act.udp_adaptive_timeout) udp_adaptive = true;
                if (act.udp_disable_domain_unmapping) udp_disable_unmapping = true;
                if (act.override_address) ov_addr = act.override_address;
                if (act.override_port) ov_port = act.override_port;
            };
            auto finish_idle = [&] {
                if (!flow_idle_ms) return;
                if (udp_timeout_ms) *flow_idle_ms = udp_timeout_ms;
                else if (udp_adaptive) *flow_idle_ms = rules::adaptive_udp_timeout_ms(input.protocol, input.port.value_or(0), default_idle_ms);
            };
            if (policy.program.has_dns_hijack()) input.dns_query = dns::parse_query(payload).has_value();
            for (;;) {
                auto next = cursor.poll(policy.program, input);
                if (!next) return {};
                if (next->kind == rules::ProgramPreflightKind::uncertain) {
                    if (policy.unknown_policy != sniff::UnknownRoutePolicy::skip || !cursor.skip_unknown(next->rule_index))
                        return {};
                    continue;
                }
                if (next->kind == rules::ProgramPreflightKind::exhausted) {
                    finish_idle();
                    auto act = rules::ProgramAction{rules::ProgramActionKind::route, policy.fallback};
                    act.override_address = ov_addr;
                    act.override_port = ov_port;
                    act.udp_disable_domain_unmapping = udp_disable_unmapping;
                    return act;
                }
                auto step = *next->step;
                if (auto timeout = step.action.connect_timeout_ms)
                    deadline = std::min(deadline, received + std::chrono::milliseconds(timeout));
                if (Clock::now() >= deadline) return {};
                switch (step.action.kind) {
                case rules::ProgramActionKind::bypass:
                case rules::ProgramActionKind::route:
                    apply_udp_opt(step.action);
                    finish_idle();
                    step.action.override_address = ov_addr;
                    step.action.override_port = ov_port;
                    step.action.udp_disable_domain_unmapping = udp_disable_unmapping;
                    return step.action;
                case rules::ProgramActionKind::hijack_dns:
                case rules::ProgramActionKind::reject:
                    return step.action;
                case rules::ProgramActionKind::sniff: {
                    auto allowed = [&](rules::Protocol p) {
                        return step.action.sniff_protocols == 0 || (step.action.sniff_protocols & rules::protocol_mask(p)) != 0;
                    };
                    auto query = allowed(rules::Protocol::dns) ? dns::parse_query(payload)
                        : std::expected<dns::QueryMessage, dns::MessageError>(std::unexpected(dns::MessageError::truncated));
                    if (query) {
                        input.protocol = rules::Protocol::dns;
                        if (rules::valid_domain(query->question.name)) name = std::move(query->question.name);
                    } else if (allowed(rules::Protocol::stun) && sniff::stun_datagram(payload)) {
                        input.protocol = rules::Protocol::stun;
                        input.domain_absent[static_cast<std::size_t>(rules::DomainSource::sniffed)] = true;
                    } else if (allowed(rules::Protocol::dtls) && sniff::inspect_dtls_udp(payload)) {
                        input.protocol = rules::Protocol::dtls;
                        input.domain_absent[static_cast<std::size_t>(rules::DomainSource::sniffed)] = true;
                    } else if (allowed(rules::Protocol::ntp) && sniff::inspect_ntp_udp(payload)) {
                        input.protocol = rules::Protocol::ntp;
                        input.domain_absent[static_cast<std::size_t>(rules::DomainSource::sniffed)] = true;
                    } else {
                        bool matched_quic = false;
                        if (allowed(rules::Protocol::quic)) {
                            if (auto quic = sniff::sniff_quic_datagram(payload); quic.status == sniff::QuicProbeStatus::matched) {
                                matched_quic = true;
                                input.protocol = rules::Protocol::quic;
                                if (quic.domain) name = std::move(*quic.domain);
                                if (quic.client) { client_name = std::move(*quic.client); input.client = client_name; }
                            }
                        }
                        if (!matched_quic && allowed(rules::Protocol::bittorrent) && sniff::inspect_bittorrent_udp(payload)) {
                            input.protocol = rules::Protocol::bittorrent;
                            input.domain_absent[static_cast<std::size_t>(rules::DomainSource::sniffed)] = true;
                        }
                    }
                    if (!name.empty()) input.sniffed_domain = name;
                    break;
                }
                case rules::ProgramActionKind::route_options:
                    apply_udp_opt(step.action);
                    break;
                case rules::ProgramActionKind::resolve:
                    break;
                }
                if (!cursor.complete(step)) return {};
            }
        }

        [[nodiscard]] static auto is_self_loop_udp(net::UdpEndpoint const& source,
            net::UdpEndpoint const& dest,
            std::optional<net::UdpEndpoint> const& local_bound) noexcept -> bool {
            auto same = [](net::UdpEndpoint const& a, net::UdpEndpoint const& b) noexcept {
                if (a.family != b.family || a.port != b.port) return false;
                auto const len = a.family == 6 ? std::size_t{16} : std::size_t{4};
                return std::ranges::equal(std::span(a.address).first(len), std::span(b.address).first(len));
            };
            if (same(source, dest)) return true;
            if (local_bound && same(*local_bound, dest)) return true;
            return false;
        }

        template<class Impl>
        static auto reject_tun_udp(Impl& host, std::span<std::uint8_t const> original, std::uint64_t now) -> void {
            if (!host.cfg.udp_reject_icmp) return;
            if (now - host.udp_icmp_window_ms >= 1000) {
                host.udp_icmp_window_ms = now;
                host.udp_icmp_replies = 0;
            }
            if (host.udp_icmp_replies >= 32) return;
            auto reply = packet::udp_administratively_prohibited(original, host.cfg.mtu);
            if (reply && host.udp_link.send(packet::Side::second, *reply)) ++host.udp_icmp_replies;
        }

        struct TunIcmpDecision {
            bool rejected = false;
            bool bypassed = false;
            std::size_t outbound = 0;
        };

        // Evaluate network=icmp routing policy on a raw IPv4/IPv6 ICMP Echo packet entering TUN.
        template<class Ordered = decltype(relay::RouteSnapshot::ordered)::value_type>
        [[nodiscard]] static auto route_tun_icmp(std::span<std::uint8_t const> raw_ip_packet,
            rules::RouteMatcher const& policy, Ordered const* ordered,
            std::string_view source_interface = {}, rules::IngressMetadata ingress = {})
            -> std::optional<TunIcmpDecision> {
            std::string dst_text;
            std::array<std::uint8_t, 16> src_bytes{};
            std::size_t addr_len = 0;
            if (auto v4 = packet::parse_icmp_echo4(raw_ip_packet)) {
                dst_text = platform::format_ipv4(v4->destination);
                std::ranges::copy(v4->source, src_bytes.begin());
                addr_len = 4;
            } else if (auto v6 = packet::parse_icmp_echo6(raw_ip_packet)) {
                dst_text = platform::format_ipv6(v6->destination);
                src_bytes = v6->source;
                addr_len = 16;
            } else {
                return std::nullopt;
            }
            auto const& mode_state = policy.runtime_mode();
            auto cur_mode = mode_state ? mode_state->mode.load(std::memory_order_acquire) : rules::RouteMode::rule;
            if (auto ov = policy.mode_override(dst_text)) {
                auto chosen = policy.choose_outbound(*ov, dst_text);
                return TunIcmpDecision{.rejected = (chosen == 1), .bypassed = false, .outbound = chosen};
            }
            auto src_span = std::span(src_bytes).first(addr_len);
            if (ordered) {
                auto prog_in = ingress.apply(rules::ProgramInput{
                    .ip = dst_text, .network = rules::Network::icmp,
                    .source_ip_bytes = src_span, .inbound = policy.inbound(),
                    .source_interface = source_interface.empty() ? std::nullopt : std::optional<std::string_view>(source_interface),
                    .route_mode = cur_mode});
                prog_in.domain_absent.fill(true);
                rules::ProgramCursor cursor;
                for (;;) {
                    auto next = cursor.poll(ordered->program, prog_in);
                    if (!next) return std::nullopt;
                    if (next->kind == rules::ProgramPreflightKind::uncertain) {
                        if (ordered->unknown_policy != sniff::UnknownRoutePolicy::skip ||
                            !cursor.skip_unknown(next->rule_index))
                            return std::nullopt;
                        continue;
                    }
                    if (next->kind == rules::ProgramPreflightKind::exhausted) {
                        auto chosen = policy.choose_outbound(ordered->fallback, dst_text);
                        return TunIcmpDecision{.rejected = (chosen == 1), .bypassed = false, .outbound = chosen};
                    }
                    auto step = *next->step;
                    if (step.action.kind == rules::ProgramActionKind::reject)
                        return TunIcmpDecision{.rejected = true, .bypassed = false, .outbound = 1};
                    if (step.action.kind == rules::ProgramActionKind::bypass ||
                        step.action.kind == rules::ProgramActionKind::route) {
                        auto chosen = policy.choose_outbound(step.action.outbound, dst_text);
                        return TunIcmpDecision{
                            .rejected = (chosen == 1),
                            .bypassed = (step.action.kind == rules::ProgramActionKind::bypass),
                            .outbound = chosen};
                    }
                    if (!cursor.complete(step)) return std::nullopt;
                }
            }
            auto minput = ingress.apply(rules::MatchInput{
                .ip = dst_text, .network = rules::Network::icmp,
                .source_ip_bytes = src_span,
                .source_interface = source_interface.empty() ? std::nullopt : std::optional<std::string_view>(source_interface)});
            auto matched = policy.match(minput);
            if (!matched) return std::nullopt;
            auto chosen = policy.choose_outbound(*matched, dst_text);
            return TunIcmpDecision{.rejected = (chosen == 1), .bypassed = false, .outbound = chosen};
        }

        // Dispatch live TUN ICMPv4/ICMPv6 Echo packets through route_tun_icmp().
        // Returns true if the packet is ICMP (handled or dropped), false if non-ICMP (e.g. IPv6 UDP).
        template<class Impl>
        static auto handle_tun_icmp(Impl& host, std::span<std::uint8_t const> raw) -> bool {
            if (raw.empty()) return false;
            auto ver = raw[0] >> 4;
            bool is_v6 = (ver == 6);
            std::optional<packet::IcmpEcho4View> v4;
            std::optional<packet::IcmpEcho6View> v6;
            if (ver == 4) {
                if (raw.size() < 28 || raw[9] != 1) return false;
                auto p = packet::parse_icmp_echo4(raw);
                if (!p) return true;
                v4 = *p;
            } else if (ver == 6) {
                auto p = packet::parse_icmp_echo6(raw);
                if (!p) return raw.size() >= 40 && raw[6] == 58;
                v6 = *p;
            } else return false;
            auto kind = is_v6 ? v6->kind : v4->kind;
            if (kind != packet::EchoKind::request) return true;
            net::UdpEndpoint source{};
            source.family = is_v6 ? 6 : 4;
            if (is_v6) source.address = v6->source;
            else std::ranges::copy(v4->source, source.address.begin());
            std::uint8_t dscp = is_v6
                ? static_cast<std::uint8_t>(((raw[0] & 0x0fu) << 2) | (raw[1] >> 6))
                : static_cast<std::uint8_t>(raw[1] >> 2);
            auto ingress = host.routing.transparent_metadata(source, dscp);
            auto snapshot = host.routing.current_route_snapshot();
            auto const& policy = snapshot ? snapshot->matcher : host.routing.routing_policy();
            auto const* ordered = snapshot ? (snapshot->ordered ? &*snapshot->ordered : nullptr) :
                host.routing.ordered_routing_policy();
            auto decision = route_tun_icmp(raw, policy, ordered, host.device_name(), ingress);
            if (!decision || decision->rejected) return true;
            auto matches_local = [&](std::optional<std::string> const& cidr, std::span<std::uint8_t const> dst) -> bool {
                if (!cidr) return false;
                auto sv = std::string_view(*cidr);
                if (auto slash = sv.find('/'); slash != std::string_view::npos) sv = sv.substr(0, slash);
                auto ip = platform::parse_ip_address(sv);
                return ip && ip->size == dst.size() && std::ranges::equal(std::span(ip->bytes).first(dst.size()), dst);
            };
            auto dst_span = is_v6 ? std::span<std::uint8_t const>(v6->destination)
                                  : std::span<std::uint8_t const>(v4->destination);
            bool local_or_fake = matches_local(is_v6 ? host.cfg.inet6_address : host.cfg.inet4_address, dst_span);
#ifdef NEXUS_ENABLE_FAKEIP
            if (!local_or_fake) local_or_fake = host.routing.protects_fakeip(dst_span);
#endif
            if (!local_or_fake) return true;
            if (is_v6) {
                if (auto rep = packet::make_icmp_echo6({v6->destination, v6->source, packet::EchoKind::reply,
                        v6->identifier, v6->sequence, v6->payload}, host.cfg.mtu))
                    (void)host.queue_udp_reply(std::move(*rep));
            } else {
                if (auto rep = packet::make_icmp_echo4({v4->destination, v4->source, packet::EchoKind::reply,
                        v4->identifier, v4->sequence, v4->payload}, host.cfg.mtu))
                    (void)host.queue_udp_reply(std::move(*rep));
            }
            return true;
        }
    };
}
