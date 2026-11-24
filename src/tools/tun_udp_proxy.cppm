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
                case rules::ProgramActionKind::bypass:
                    return {};
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
    };
}
