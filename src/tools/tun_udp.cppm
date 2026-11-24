// TUN UDP input/output bridging, DNS hijack and reply dispatch.
export module cli.tun_udp;
import std;
import capy;
import cli.tun_fakeip;
import cli.tun_owner_lookup;
import cli.tun_udp_fragments;
import cli.tun_udp_proxy;
import dns.message;
import net.datagram_frame;
import net.udp_dial;
import packet;
import packet.mux;
import platform.ip_address;
import relay;
import rules;
import udp;
import udp.route;

export namespace cli::tun_enabled {
    struct UdpOverrideMapping {
        net::UdpEndpoint dial{};
        net::UdpEndpoint client{};
    };

    inline auto same_udp_endpoint(net::UdpEndpoint const& a, net::UdpEndpoint const& b) noexcept -> bool {
        if (a.family != b.family || a.port != b.port) return false;
        auto const n = a.family == 6 ? std::size_t{16} : std::size_t{4};
        return std::ranges::equal(std::span(a.address).first(n), std::span(b.address).first(n));
    }

    struct CachedUdpRoute {
        net::UdpEndpoint target{};
        rules::IngressMetadata ingress{};
        rules::RouteMode mode = rules::RouteMode::rule;
        std::size_t global_outbound = 0, outbound = 0;
        bool valid = false;
        std::vector<UdpOverrideMapping> overrides{};
        auto matches(net::UdpEndpoint const& ep, rules::IngressMetadata const& in,
            rules::RouteMode m, std::size_t g) const noexcept -> bool {
            return valid && same_udp_endpoint(target, ep) && ingress == in && mode == m && global_outbound == g;
        }
        auto set_route(net::UdpEndpoint const& ep, rules::IngressMetadata const& in,
            rules::RouteMode m, std::size_t g, std::size_t out) noexcept -> void {
            target = ep; ingress = in; mode = m; global_outbound = g; outbound = out; valid = true;
        }
        auto record_override(net::UdpEndpoint const& dial, net::UdpEndpoint const& client) -> void {
            if (same_udp_endpoint(dial, client)) {
                if (!overrides.empty())
                    std::erase_if(overrides, [&](auto const& e) noexcept { return same_udp_endpoint(e.dial, dial); });
                return;
            }
            for (auto& e : overrides) {
                if (same_udp_endpoint(e.dial, dial)) { e.client = client; return; }
            }
            if (overrides.size() >= 64) overrides.erase(overrides.begin());
            overrides.push_back({dial, client});
        }
        [[nodiscard]] auto translate_reply_source(net::UdpEndpoint const& src) const noexcept -> net::UdpEndpoint {
            for (auto it = overrides.rbegin(); it != overrides.rend(); ++it) {
                if (same_udp_endpoint(it->dial, src)) return it->client;
            }
            return src;
        }
    };

    struct TunUdpOps {
        using Clock = std::chrono::steady_clock;

        template<class Impl>
        static auto answer_tun_dns(Impl& host, auto& bridge, auto remote, udp::FlowId flow, net::UdpEndpoint source,
            std::unique_ptr<relay::Session> session, dns::Bytes query, Clock::time_point deadline)
            -> capy::task<> {
            if (!session->closed) session->count_traffic(true, query.size());
            auto answer = co_await relay::hijack_dns_query(*session, host.routing.executor_context(), query, source, deadline);
            if (!answer || session->closed) co_return;
            auto packet = bridge.reply(flow, remote, *answer, now_ms());
            if (packet && host.queue_udp_reply(std::move(*packet)))
                session->count_traffic(false, answer->size());
        }

        template<class Impl>
        static auto process_udp_inputs(Impl& host, std::uint64_t now) -> bool {
            host.udp_fragments.expire(Clock::time_point(std::chrono::milliseconds(now)));
            bool moved = false;
            for (int k = 0; k < 16; ++k) {
                auto pkt = host.udp_link.receive(packet::Side::second);
                if (!pkt || !*pkt) break;
                moved = true;
                if ((**pkt).empty()) continue;
                auto fragmented = TunUdpFragments::fragmented(**pkt);
                if (fragmented) {
                    auto whole = host.udp_fragments.feed(**pkt, Clock::now());
                    if (!whole) continue;
                    **pkt = std::move(*whole);
                }
                auto ver = (**pkt)[0] >> 4;
                auto handle_one = [&](bool is_v6, auto& bridge, auto& direct_map, auto& proxy_map,
                                      udp::FlowId flow, std::uint64_t tok, auto const& remote,
                                      std::span<std::uint8_t const> payload, std::array<std::uint8_t, 16> const& src_ip,
                                      std::uint16_t src_port, std::uint8_t dscp) {
                    net::UdpEndpoint client_ep{};
                    client_ep.family = is_v6 ? 6 : 4; client_ep.port = remote.port;
                    if constexpr (sizeof(remote.address) == 16) client_ep.address = remote.address;
                    else std::ranges::copy(remote.address, client_ep.address.begin());
                    net::UdpEndpoint dial_ep = client_ep;
                    net::UdpEndpoint source{client_ep.family, src_ip, src_port};
                    auto ingress = host.routing.transparent_metadata(source, dscp);
                    auto received = Clock::now();
                    auto deadline = received + std::chrono::seconds(10);
                    auto direct = direct_map.find(flow);
                    auto tunnels = proxy_map.find(flow);
                    auto snapshot = direct != direct_map.end() ? direct->second->route :
                        tunnels != proxy_map.end() ? tunnels->second.front()->session.route_snapshot : host.routing.current_route_snapshot();
                    auto const* ordered = snapshot ? (snapshot->ordered ? &*snapshot->ordered : nullptr) :
                        host.routing.ordered_routing_policy();
                    if (ordered && !ordered->udp) { (void)bridge.complete(flow, tok, false, now); return; }
#ifdef NEXUS_ENABLE_FAKEIP
                    if (host.routing.protects_fakeip(std::span(client_ep.address).first(is_v6 ? 16 : 4))) {
                        auto& aliases = is_v6 ? host.udp6_aliases : host.udp4_aliases;
                        TunFakeIpOps::send_udp_alias(host, bridge, aliases, flow, tok, client_ep, source, payload, received, ingress);
                        return;
                    }
#endif
                    auto const& policy = snapshot ? snapshot->matcher : host.routing.routing_policy();
                    auto const& mode_state = policy.runtime_mode();
                    auto cur_mode = mode_state ? mode_state->mode.load(std::memory_order_acquire) : rules::RouteMode::rule;
                    auto cur_global = (mode_state && cur_mode == rules::RouteMode::global)
                        ? mode_state->global_outbound.load(std::memory_order_acquire) : std::size_t{0};
                    std::optional<std::size_t> cached_out;
                    std::shared_ptr<typename Impl::UdpProxyFlow> cached_pf;
                    if (!ordered) {
                        if (direct != direct_map.end() && direct->second->cached_route.matches(client_ep, ingress, cur_mode, cur_global)) {
                            cached_out = direct->second->cached_route.outbound;
                        } else if (tunnels != proxy_map.end()) {
                            for (auto const& owner : tunnels->second) {
                                if (!owner->failed && owner->cached_route.matches(client_ep, ingress, cur_mode, cur_global)) {
                                    cached_out = owner->cached_route.outbound;
                                    cached_pf = owner;
                                    break;
                                }
                            }
                        }
                    }
                    std::size_t out_idx = 0;
                    if (cached_out) {
                        out_idx = *cached_out;
                    } else {
                        auto dst_text = [&]() {
                            if constexpr (sizeof(remote.address) == 16) {
                                return platform::format_ipv6(remote.address);
                            } else {
                                return platform::format_ipv4(remote.address);
                            }
                        }();
                        auto source_bytes = std::span(src_ip).first(is_v6 ? 16 : 4);
                        auto owner_info = lookup_tun_owner_cached(host.udp_owner_cache, now, source_bytes, src_port,
                            std::span(client_ep.address).first(is_v6 ? 16 : 4), remote.port, policy, ordered);
                        auto apply_owner = [&](auto& target) {
                            if (!owner_info) return;
                            if (owner_info->uid) target.source_uid = owner_info->uid;
                            if (owner_info->gid) target.source_gid = owner_info->gid;
                            if (!owner_info->process_path.empty()) target.process_path = owner_info->process_path;
                            if (!owner_info->user.empty()) target.source_user = owner_info->user;
                            if (!owner_info->package_name.empty()) target.package_name = owner_info->package_name;
                        };
                        std::optional<std::size_t> selected;
                        auto ov = policy.mode_override(dst_text);
                        if (ordered && (!ov || ordered->program.has_dns_hijack())) {
                            dns::Address rev_addr{};
                            rev_addr.size = is_v6 ? 16 : 4;
                            std::copy_n(client_ep.address.begin(), rev_addr.size, rev_addr.bytes.begin());
                            auto rev_view = (snapshot && snapshot->dns && snapshot->dns->view) ? *snapshot->dns->view : std::uint64_t{0};
                            std::uint32_t flow_idle_ms = 0;
                            auto prog_in = ingress.apply(rules::ProgramInput{.ip = dst_text, .port = remote.port, .network = rules::Network::udp,
                                .source_port = src_port, .source_ip_bytes = source_bytes, .inbound = policy.inbound(), .source_interface = host.device_name(),
                                .route_mode = cur_mode});
                            apply_owner(prog_in);
                            auto action = TunUdpProxyOps::route_ordered_udp(payload, prog_in,
                                *ordered, received, deadline, host.routing.reverse_cache_ptr(), rev_addr, rev_view,
                                static_cast<std::uint32_t>(std::min<std::uint64_t>(host.cfg.udp_idle_ms, 3600000)), &flow_idle_ms);
                            if (flow_idle_ms) (void)bridge.set_flow_idle_ms(flow, flow_idle_ms);
                            if (action && action->kind == rules::ProgramActionKind::reject) {
                                if (!ov) {
                                    (void)bridge.complete(flow, tok, false, now);
                                    bool drop = relay::global_reject_storm_guard().should_drop(action->reject_method, action->reject_no_drop);
                                    if (!fragmented && !drop) TunUdpProxyOps::reject_tun_udp(host, **pkt, now);
                                    return;
                                }
                            } else if (action && action->kind == rules::ProgramActionKind::hijack_dns) {
                                auto slot = host.routing.acquire_session();
                                if (!slot) { (void)bridge.complete(flow, tok, false, now); return; }
                                try {
                                    auto session = std::make_unique<relay::Session>(host.routing.executor_context());
                                    host.routing.attach_session(*session, std::move(*slot), std::move(snapshot));
                                    session->source_interface = host.device_name();
                                    session->datagram_source = source;
                                    if (owner_info) {
                                        if (owner_info->uid) session->source_uid = owner_info->uid;
                                        if (owner_info->gid) session->source_gid = owner_info->gid;
                                        if (!owner_info->process_path.empty()) session->process_path = owner_info->process_path;
                                        if (!owner_info->user.empty()) session->source_user = owner_info->user;
                                        if (!owner_info->package_name.empty()) session->package_name = owner_info->package_name;
                                    }
                                    session->begin_traffic(relay::TrafficProtocol::tun_udp, remote.port);
                                    auto answer = answer_tun_dns(host, bridge, remote, flow, source, std::move(session),
                                        dns::Bytes(payload.begin(), payload.end()), deadline);
                                    if (bridge.complete(flow, tok, true, now))
                                        capy::run_async(host.routing.executor_context().get_executor(), [] {}, [](std::exception_ptr) noexcept {})(std::move(answer));
                                } catch (...) {
                                    (void)bridge.complete(flow, tok, false, now);
                                }
                                return;
                            }
                            if (ov) selected = ov;
                            else if (action) {
                                selected = action->outbound;
                                if (action->override_port) dial_ep.port = action->override_port;
                                if (action->override_address) {
                                    if (auto parsed_ov = platform::parse_ip_address(*action->override_address);
                                        parsed_ov && parsed_ov->size == (is_v6 ? 16 : 4)) {
                                        dial_ep.address = parsed_ov->bytes;
                                    }
                                }
                            }
                            if (!selected || Clock::now() >= deadline) { (void)bridge.complete(flow, tok, false, now); return; }
                        } else if (ov) {
                            selected = ov;
                        } else {
                            auto minput = ingress.apply(rules::MatchInput{.ip = dst_text, .port = remote.port, .network = rules::Network::udp,
                                .source_port = src_port, .source_ip_bytes = source_bytes, .source_interface = host.device_name()});
                            apply_owner(minput);
                            auto match = policy.match(minput);
                            if (match) selected = *match;
                        }
                        if (!selected) { (void)bridge.complete(flow, tok, false, now); return; }
                        out_idx = policy.choose_outbound(*selected, dst_text);
                    }
                    if (out_idx == 1) {
                        (void)bridge.complete(flow, tok, false, now);
                        if (!fragmented) TunUdpProxyOps::reject_tun_udp(host, **pkt, now);
                        return;
                    }
                    if (out_idx >= 2) {
                        if (!host.routing.has_packet_outbound(out_idx)) {
                            (void)bridge.complete(flow, tok, false, now);
                            return;
                        }
                        net::ProxyAddress pa{};
                        pa.family = is_v6 ? net::ProxyAddressFamily::ipv6 : net::ProxyAddressFamily::ipv4;
                        pa.length = is_v6 ? 16 : 4;
                        pa.port = dial_ep.port;
                        std::copy_n(dial_ep.address.begin(), pa.length, pa.bytes.begin());
                        std::shared_ptr<typename Impl::UdpProxyFlow> pf = std::move(cached_pf);
                        if (!pf && tunnels != proxy_map.end()) {
                            auto found = std::ranges::find_if(tunnels->second, [&](auto const& owner) {
                                return !owner->failed && owner->outbound == out_idx &&
                                    (!owner->tunnel->fixed_peer() || owner->first_target == pa);
                            });
                            if (found != tunnels->second.end()) pf = *found;
                            else if (tunnels->second.size() >= 32) {
                                (void)bridge.complete(flow, tok, false, now);
                                return;
                            }
                        }
                        if (!pf) {
                            auto lease_opt = host.routing.acquire_session();
                            if (!lease_opt) { (void)bridge.complete(flow, tok, false, now); return; }
                            pf = std::make_shared<typename Impl::UdpProxyFlow>(host.routing.executor_context());
                            pf->outbound = out_idx;
                            pf->connect_deadline = deadline;
                            host.routing.attach_session(pf->session, std::move(*lease_opt), std::move(snapshot));
                            pf->session.datagram_source = source;
                            pf->session.begin_traffic(relay::TrafficProtocol::tun_udp, client_ep.port);
                            pf->tunnel = host.routing.open_packet_tunnel(pf->session, out_idx);
                            if (!pf->tunnel || pf->tunnel->transport().kind != net::PacketTransportKind::framed) {
                                pf->session.close();
                                (void)bridge.complete(flow, tok, false, now); return;
                            }
                            pf->framing = pf->tunnel->transport().framing;
                            pf->needs_uot_request = pf->tunnel->transport().needs_uot_request;
                            pf->first_target = pa;
                            proxy_map[flow].push_back(pf);
                            capy::run_async(host.routing.executor_context().get_executor(), [] {}, [pf](std::exception_ptr) noexcept {
                                pf->failed = true;
                            })(TunUdpProxyOps::run_udp_proxy(host, is_v6, flow, pf));
                        }
                        if (!ordered && !cached_out) pf->cached_route.set_route(client_ep, ingress, cur_mode, cur_global, out_idx);
                        if (ordered) pf->cached_route.record_override(dial_ep, client_ep);
                        auto wire = net::encode_datagram(pf->framing, pa, payload);
                        if (wire && pf->tx_queue.size() < 64) {
                            pf->tx_queue.push_back({std::move(*wire), payload.size(), deadline});
                            pf->work.set();
                            (void)bridge.complete(flow, tok, true, now);
                        } else (void)bridge.complete(flow, tok, false, now);
                        return;
                    }
                    auto it = direct;
                    if (it == direct_map.end()) {
                        if (direct_map.size() >= TunUdpProxyOps::kMaxDirectUdpFlows ||
                            TunUdpProxyOps::is_self_loop_udp(source, dial_ep, std::nullopt)) {
                            if (TunUdpProxyOps::is_self_loop_udp(source, dial_ep, std::nullopt)) ++host.udp_self_loop_drops;
                            (void)bridge.complete(flow, tok, false, now);
                            return;
                        }
                        auto traffic = host.routing.track_traffic(relay::TrafficProtocol::tun_udp, relay::ConnectPath::direct, source, client_ep.port, true);
                        auto owner = std::make_unique<typename Impl::UdpDirectFlow>(&host.udp_binding, std::move(traffic), std::move(snapshot));
                        it = direct_map.emplace(flow, std::move(owner)).first;
                    }
                    if (!ordered && !cached_out) it->second->cached_route.set_route(client_ep, ingress, cur_mode, cur_global, 0);
                    if (ordered) it->second->cached_route.record_override(dial_ep, client_ep);
                    std::optional<net::UdpEndpoint> local_ep;
                    for (auto const& bound : it->second->socket.local_endpoints()) {
                        if (bound && TunUdpProxyOps::is_self_loop_udp(source, dial_ep, bound)) { local_ep = *bound; break; }
                    }
                    if (TunUdpProxyOps::is_self_loop_udp(source, dial_ep, local_ep)) {
                        ++host.udp_self_loop_drops;
                        (void)bridge.complete(flow, tok, false, now);
                        return;
                    }
                    bool ok = it->second->socket.send(dial_ep, payload).has_value();
                    if (ok) {
                        host.events.watch_udp(it->second->socket.native_handles(), {is_v6, false, flow});
                        it->second->traffic.count(true, payload.size());
                    }
                    (void)bridge.complete(flow, tok, ok, now);
                };

                if (ver == 4) {
                    if (auto parsed = packet::parse_udp4(**pkt)) {
                        if (auto prep = host.udp4->prepare_parsed(*parsed, now)) {
                            std::array<std::uint8_t, 16> sip{}; std::ranges::copy(parsed->source, sip.begin());
                            handle_one(false, *host.udp4, host.udp4_direct, host.udp4_proxy, prep->flow, prep->token, prep->remote, prep->payload, sip, parsed->source_port, parsed->dscp);
                        }
                    }
                } else if (ver == 6) {
                    if (auto parsed = packet::parse_udp6(**pkt)) {
                        if (auto prep = host.udp6->prepare_parsed(*parsed, now)) {
                            handle_one(true, *host.udp6, host.udp6_direct, host.udp6_proxy, prep->flow, prep->token, prep->remote, prep->payload, parsed->source, parsed->source_port, parsed->dscp);
                        }
                    }
                }
            }
            return moved;
        }

        template<class Impl>
        static auto poll_udp_outputs(Impl& host, std::uint64_t now) -> bool {
            if (now != host.last_udp_expire_ms) {
                host.last_udp_expire_ms = now;
                (void)host.udp4->expire(now);
                (void)host.udp6->expire(now);
            }
            bool const has_direct_or_alias = !host.udp4_direct.empty() || !host.udp6_direct.empty()
#ifdef NEXUS_ENABLE_FAKEIP
                || !host.udp4_aliases.empty() || !host.udp6_aliases.empty()
#endif
                ;
            if (!has_direct_or_alias && host.udp_replies.empty()) return false;
            bool moved = false;
            if (has_direct_or_alias) {
                auto buf = host.udp_rx_buffer();
                auto drain_one = [&](auto& bridge, udp::FlowId flow, auto& sock) {
                    if (sock.traffic.close_requested()) { (void)bridge->close(flow, now); return; }
                    for (int k = 0; k < 4; ++k) {
                        auto pkt = sock.socket.receive(buf);
                        if (!pkt || !*pkt) break;
                        moved = true;
                        auto reply_src = sock.cached_route.translate_reply_source((**pkt).source);
                        std::expected<packet::Bytes, udp::BridgeError> built;
                        if constexpr (std::same_as<decltype(*bridge), udp::RoutedBridge4&>) {
                            udp::Endpoint4 rep{{}, reply_src.port};
                            std::copy_n(reply_src.address.begin(), 4, rep.address.begin());
                            built = bridge->reply(flow, rep, buf.first((**pkt).size), now);
                        } else {
                            udp::Endpoint6 rep{reply_src.address, reply_src.port};
                            built = bridge->reply(flow, rep, buf.first((**pkt).size), now);
                        }
                        if (built && host.queue_udp_reply(std::move(*built)))
                            sock.traffic.count(false, (**pkt).size);
                    }
                };
                if (host.events.has_udp_epoll()) {
                    auto tp = std::chrono::steady_clock::now();
                    if (tp >= host.next_udp_sweep) {
                        host.next_udp_sweep = tp + std::chrono::milliseconds(50);
                        for (auto it = host.udp4_direct.begin(); it != host.udp4_direct.end();) { auto const& [id, s] = *it++; if (s->traffic.close_requested()) (void)host.udp4->close(id, now); }
                        for (auto it = host.udp6_direct.begin(); it != host.udp6_direct.end();) { auto const& [id, s] = *it++; if (s->traffic.close_requested()) (void)host.udp6->close(id, now); }
#ifdef NEXUS_ENABLE_FAKEIP
                        for (auto it = host.udp4_aliases.begin(); it != host.udp4_aliases.end();) { auto const& [id, s] = *it++; if (s->session.closed) (void)host.udp4->close(id, now); }
                        for (auto it = host.udp6_aliases.begin(); it != host.udp6_aliases.end();) { auto const& [id, s] = *it++; if (s->session.closed) (void)host.udp6->close(id, now); }
#endif
                    }
                    moved |= host.events.drain_ready_udp([&](auto key) {
#ifdef NEXUS_ENABLE_FAKEIP
                        if (key.is_alias) {
                            if (key.is_v6) (void)TunFakeIpOps::poll_udp_alias_id(host, host.udp6_aliases, *host.udp6, key.flow, now, buf);
                            else (void)TunFakeIpOps::poll_udp_alias_id(host, host.udp4_aliases, *host.udp4, key.flow, now, buf);
                            return;
                        }
#endif
                        if (key.is_v6) { if (auto it = host.udp6_direct.find(key.flow); it != host.udp6_direct.end()) drain_one(host.udp6, key.flow, *it->second); }
                        else { if (auto it = host.udp4_direct.find(key.flow); it != host.udp4_direct.end()) drain_one(host.udp4, key.flow, *it->second); }
                    });
                } else {
                    auto poll_direct = [&](auto& direct_map, auto& bridge) {
                        for (auto it = direct_map.begin(); it != direct_map.end();) {
                            auto const& [flow, sock] = *it++;
                            drain_one(bridge, flow, *sock);
                        }
                    };
                    poll_direct(host.udp4_direct, host.udp4);
                    poll_direct(host.udp6_direct, host.udp6);
#ifdef NEXUS_ENABLE_FAKEIP
                    moved |= TunFakeIpOps::poll_udp_aliases(host, host.udp4_aliases, *host.udp4, now);
                    moved |= TunFakeIpOps::poll_udp_aliases(host, host.udp6_aliases, *host.udp6, now);
#endif
                }
            }
            while (!host.udp_replies.empty()) {
                auto rep = std::move(host.udp_replies.front());
                host.udp_replies.pop_front();
                moved = true;
                net::UdpEndpoint reply_src{static_cast<std::uint8_t>(rep.ipv6 ? 6 : 4), rep.source, rep.source_port};
                if (rep.owner) reply_src = rep.owner->cached_route.translate_reply_source(reply_src);
                std::expected<packet::Bytes, udp::BridgeError> built;
                if (!rep.ipv6) {
                    udp::Endpoint4 src{{}, reply_src.port};
                    std::copy_n(reply_src.address.begin(), 4, src.address.begin());
                    built = host.udp4->reply(rep.flow, src, rep.payload, now);
                } else {
                    udp::Endpoint6 src{reply_src.address, reply_src.port};
                    built = host.udp6->reply(rep.flow, src, rep.payload, now);
                }
                if (built && host.queue_udp_reply(std::move(*built)))
                    rep.owner->session.count_traffic(false, rep.payload.size());
            }
            return moved;
        }
    };
}
