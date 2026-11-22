// Private UDP relay helpers included inside TunHost::Impl.
#pragma once
        static auto udp_proxy_writer(Impl& host, std::shared_ptr<UdpProxyFlow> st) -> nex::capy::task<nex::capy::results<>> {
            while (!host.stop_flag.load(std::memory_order_acquire) && !st->failed) {
                if (st->tx_queue.empty()) {
                    st->work.clear();
                    auto [ec] = co_await st->work.wait();
                    if (ec) break;
                    continue;
                }
                auto pkt = std::move(st->tx_queue.front());
                st->tx_queue.pop_front();
                if (Clock::now()>=pkt.deadline) continue;
                if (!co_await st->tunnel->send(pkt.wire)) break;
                st->session.count_traffic(true,pkt.payload_size);
            }
            st->failed = true;
            co_return nex::capy::results<>{};
        }

        static auto udp_proxy_reader(Impl& host, bool is_v6, udp::FlowId flow, std::shared_ptr<UdpProxyFlow> st)
            -> nex::capy::task<nex::capy::results<>> {
            std::array<std::uint8_t, 65536> buf{};
            net::DatagramDecoder decoder(st->framing,st->first_target);
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
                            UdpReply rep{is_v6,flow,{},dg->destination.port,{dg->payload.begin(),dg->payload.end()},st};
                            std::copy_n(dg->destination.bytes.begin(), is_v6 ? 16 : 4, rep.source.begin());
                            host.udp_replies.push_back(std::move(rep));
                        }
                        (void)decoder.consume();
                    } else if (feed.status != net::DatagramStatus::incomplete) {
                        st->failed = true;
                        co_return nex::capy::results<>{};
                    }
                }
            }
            st->failed = true;
            co_return nex::capy::results<>{};
        }

        auto run_udp_proxy(bool is_v6, udp::FlowId flow, std::shared_ptr<UdpProxyFlow> st) -> nex::capy::task<> {
            struct Guard {
                Impl& host; bool is_v6; udp::FlowId flow; std::shared_ptr<UdpProxyFlow> st;
                ~Guard() {
                    st->failed = true;
                    if (st->tunnel) st->tunnel->cancel();
                    st->session.close();
                    auto& flows=is_v6 ? host.udp6_proxy : host.udp4_proxy;
                    auto it=flows.find(flow);
                    if (it!=flows.end()) {
                        std::erase(it->second,st);
                        if (it->second.empty()) flows.erase(it);
                    }
                }
            } guard{*this,is_v6,flow,st};
            std::stop_callback cancel(st->session.stop.get_token(),[&]() noexcept {
                st->failed=true;
                st->work.set();
                st->tunnel->cancel();
            });
            if (co_await st->tunnel->connect(st->first_target,st->connect_deadline) != proxy::PacketConnectResult::connected) co_return;
            if (Clock::now()>=st->connect_deadline) co_return;
            if (st->needs_uot_request) {
                auto req = uot::encode_request({false, st->first_target});
                if (!req || !co_await st->tunnel->send(*req) || Clock::now()>=st->connect_deadline) co_return;
            }
            st->session.select_traffic_path(proxy::ConnectPath::tunnel);
            st->connected = true;
            (void)co_await nex::capy::when_all(
                udp_proxy_writer(*this, st),
                udp_proxy_reader(*this, is_v6, flow, st));
        }

        // Numeric TUN destinations already carry the resolved address.
        static auto route_ordered_udp(std::span<std::uint8_t const> payload,rules::ProgramInput input,
            auto const& policy,Clock::time_point received,Clock::time_point& deadline,
            dns::ReverseCache* reverse_cache=nullptr,std::optional<dns::Address> target_addr={},std::uint64_t reverse_view=0,
            std::uint32_t default_idle_ms=60000,std::uint32_t* flow_idle_ms=nullptr)
            -> std::optional<rules::ProgramAction> {
            input.domain_absent[static_cast<std::size_t>(rules::DomainSource::explicit_target)]=true;
            input.domain_absent[static_cast<std::size_t>(rules::DomainSource::fakeip)]=true;
            std::optional<dns::ReverseName> reverse_name;
            if (reverse_cache && target_addr) {
                auto now_ms=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                    received.time_since_epoch()).count());
                if (auto found=reverse_cache->lookup(reverse_view,*target_addr,now_ms)) {
                    reverse_name=*found;
                    input.reverse_domain=reverse_name->view();
                } else input.domain_absent[static_cast<std::size_t>(rules::DomainSource::reverse_dns)]=true;
            } else input.domain_absent[static_cast<std::size_t>(rules::DomainSource::reverse_dns)]=true;
            std::string name;
            rules::ProgramCursor cursor;
            std::uint32_t udp_timeout_ms=0;
            bool udp_adaptive=false;
            auto apply_udp_opt=[&](rules::ProgramAction const& act) {
                if (act.udp_timeout_ms) udp_timeout_ms=act.udp_timeout_ms;
                if (act.udp_adaptive_timeout) udp_adaptive=true;
            };
            auto finish_idle=[&] {
                if (!flow_idle_ms) return;
                if (udp_timeout_ms) *flow_idle_ms=udp_timeout_ms;
                else if (udp_adaptive) *flow_idle_ms=rules::adaptive_udp_timeout_ms(input.protocol,input.port.value_or(0),default_idle_ms);
            };
            if (policy.program.has_dns_hijack()) input.dns_query=dns::parse_query(payload).has_value();
            for (;;) {
                auto next=cursor.poll(policy.program,input);
                if (!next) return {};
                if (next->kind==rules::ProgramPreflightKind::uncertain) {
                    if (policy.unknown_policy!=sniff::UnknownRoutePolicy::skip || !cursor.skip_unknown(next->rule_index))
                        return {};
                    continue;
                }
                if (next->kind==rules::ProgramPreflightKind::exhausted) {
                    finish_idle();
                    return rules::ProgramAction{rules::ProgramActionKind::route,policy.fallback};
                }
                auto step=*next->step;
                if (auto timeout=step.action.connect_timeout_ms)
                    deadline=std::min(deadline,received+std::chrono::milliseconds(timeout));
                if (Clock::now()>=deadline) return {};
                switch (step.action.kind) {
                case rules::ProgramActionKind::route:
                    apply_udp_opt(step.action);
                    finish_idle();
                    return step.action;
                case rules::ProgramActionKind::hijack_dns:
                case rules::ProgramActionKind::reject:
                    return step.action;
                case rules::ProgramActionKind::bypass:
                    return {};
                case rules::ProgramActionKind::sniff: {
                    auto query=dns::parse_query(payload);
                    if (query) {
                        input.protocol=rules::Protocol::dns;
                        if (rules::valid_domain(query->question.name)) name=std::move(query->question.name);
                    } else if (sniff::stun_datagram(payload)) {
                        input.protocol=rules::Protocol::stun;
                        input.domain_absent[static_cast<std::size_t>(rules::DomainSource::sniffed)]=true;
                    } else if (auto quic=sniff::sniff_quic_datagram(payload); quic.status==sniff::QuicProbeStatus::matched) {
                        input.protocol=rules::Protocol::quic;
                        if (quic.domain) name=std::move(*quic.domain);
                    }
                    if (!name.empty()) input.sniffed_domain=name;
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

        static constexpr std::size_t kMaxDirectUdpFlows = 4096;
        std::uint64_t udp_self_loop_drops = 0;

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

        auto reject_tun_udp(std::span<std::uint8_t const> original,std::uint64_t now) -> void {
            if (!cfg.udp_reject_icmp) return;
            if (now-udp_icmp_window_ms>=1000) {
                udp_icmp_window_ms=now;
                udp_icmp_replies=0;
            }
            if (udp_icmp_replies>=32) return;
            auto reply=packet::udp_administratively_prohibited(original,cfg.mtu);
            if (reply && udp_link.send(packet::Side::second,*reply)) ++udp_icmp_replies;
        }

        auto answer_tun_dns(auto& bridge,auto remote,udp::FlowId flow,net::UdpEndpoint source,
            std::unique_ptr<proxy::Session> session,dns::Bytes query,Clock::time_point deadline)
            -> nex::capy::task<> {
            if (!session->closed) session->count_traffic(true,query.size());
            auto answer=co_await proxy::hijack_dns_query(*session,routing.executor_context(),query,source,deadline);
            if (!answer || session->closed) co_return;
            auto packet=bridge.reply(flow,remote,*answer,now_ms());
            if (packet && queue_udp_reply(std::move(*packet)))
                session->count_traffic(false,answer->size());
        }

        auto process_udp_inputs(std::uint64_t now) -> bool {
            udp_fragments.expire(Clock::time_point(std::chrono::milliseconds(now)));
            bool moved = false;
            for (int k = 0; k < 16; ++k) {
                auto pkt = udp_link.receive(packet::Side::second);
                if (!pkt || !*pkt) break;
                moved = true;
                if ((**pkt).empty()) continue;
                auto fragmented=TunUdpFragments::fragmented(**pkt);
                if (fragmented) {
                    auto whole=udp_fragments.feed(**pkt,Clock::now());
                    if (!whole) continue;
                    **pkt=std::move(*whole);
                }
                auto ver = (**pkt)[0] >> 4;
                auto handle_one = [&](bool is_v6, auto& bridge, auto& direct_map, auto& proxy_map,
                                      udp::FlowId flow, std::uint64_t tok, auto const& remote,
                                      std::span<std::uint8_t const> payload, std::array<std::uint8_t, 16> const& src_ip,
                                      std::uint16_t src_port,std::uint8_t dscp) {
                    net::UdpEndpoint ep{};
                    ep.family = is_v6 ? 6 : 4; ep.port = remote.port;
                    if constexpr (sizeof(remote.address) == 16) ep.address = remote.address;
                    else std::ranges::copy(remote.address, ep.address.begin());
                    net::UdpEndpoint source{ep.family,src_ip,src_port};
                    auto ingress=routing.transparent_metadata(source,dscp);
                    auto received=Clock::now();
                    auto deadline=received+std::chrono::seconds(10);
                    auto direct=direct_map.find(flow);
                    auto tunnels=proxy_map.find(flow);
                    auto snapshot=direct!=direct_map.end() ? direct->second->route :
                        tunnels!=proxy_map.end() ? tunnels->second.front()->session.route_snapshot : routing.current_route_snapshot();
                    auto const* ordered=snapshot ? (snapshot->ordered ? &*snapshot->ordered : nullptr) :
                        routing.ordered_routing_policy();
                    if (ordered && !ordered->udp) { (void)bridge.complete(flow,tok,false,now); return; }
#ifdef NEXUS_ENABLE_FAKEIP
                    if (routing.protects_fakeip(std::span(ep.address).first(is_v6 ? 16 : 4))) {
                        auto& aliases=is_v6 ? udp6_aliases : udp4_aliases;
                        send_udp_alias(bridge,aliases,flow,tok,ep,source,payload,received,ingress);
                        return;
                    }
#endif
                    auto dst_text = [&]() {
                        if constexpr (sizeof(remote.address) == 16) {
                            return platform::format_ipv6(remote.address);
                        } else {
                            return platform::format_ipv4(remote.address);
                        }
                    }();
                    auto const& policy=snapshot ? snapshot->matcher : routing.routing_policy();
                    auto source_bytes=std::span(src_ip).first(is_v6 ? 16 : 4);
                    std::optional<std::size_t> selected;
                    if (ordered) {
                        dns::Address rev_addr{};
                        rev_addr.size=is_v6 ? 16 : 4;
                        std::copy_n(ep.address.begin(),rev_addr.size,rev_addr.bytes.begin());
                        auto rev_view=(snapshot && snapshot->dns && snapshot->dns->view) ? *snapshot->dns->view : std::uint64_t{0};
                        std::uint32_t flow_idle_ms=0;
                        auto action=route_ordered_udp(payload,ingress.apply(rules::ProgramInput{.ip=dst_text,.port=remote.port,.network=rules::Network::udp,
                            .source_port=src_port,.source_ip_bytes=source_bytes,.inbound=policy.inbound(),.source_interface=tun->name()}),
                            *ordered,received,deadline,routing.reverse_cache_ptr(),rev_addr,rev_view,
                            static_cast<std::uint32_t>(std::min<std::uint64_t>(cfg.udp_idle_ms,3600000)),&flow_idle_ms);
                        if (flow_idle_ms) (void)bridge.set_flow_idle_ms(flow,flow_idle_ms);
                        if (action && action->kind==rules::ProgramActionKind::reject) {
                            (void)bridge.complete(flow,tok,false,now);
                            bool drop=proxy::global_reject_storm_guard().should_drop(action->reject_method,action->reject_no_drop);
                            if (!fragmented && !drop) reject_tun_udp(**pkt,now);
                            return;
                        }
                        if (action && action->kind==rules::ProgramActionKind::hijack_dns) {
                            auto slot=routing.acquire_session();
                            if (!slot) { (void)bridge.complete(flow,tok,false,now); return; }
                            try {
                                auto session=std::make_unique<proxy::Session>(routing.executor_context());
                                routing.attach_session(*session,std::move(*slot),std::move(snapshot));
                                session->source_interface=tun->name();
                                session->datagram_source=source;
                                session->begin_traffic(proxy::TrafficProtocol::tun_udp,remote.port);
                                auto answer=answer_tun_dns(bridge,remote,flow,source,std::move(session),
                                    dns::Bytes(payload.begin(),payload.end()),deadline);
                                if (bridge.complete(flow,tok,true,now))
                                    nex::capy::run_async(routing.executor_context().get_executor(),[] {},[](std::exception_ptr) noexcept {})(std::move(answer));
                            } catch (...) {
                                (void)bridge.complete(flow,tok,false,now);
                            }
                            return;
                        }
                        if (action) selected=action->outbound;
                    } else {
                        auto match=policy.match(ingress.apply(rules::MatchInput{.ip=dst_text,.port=remote.port,.network=rules::Network::udp,
                            .source_port=src_port,.source_ip_bytes=source_bytes,.source_interface=tun->name()}));
                        if (match) selected=*match;
                    }
                    if (!selected || Clock::now()>=deadline) { (void)bridge.complete(flow,tok,false,now); return; }
                    auto out_idx=policy.choose_outbound(*selected,dst_text);
                    if (out_idx == 1) {
                        (void)bridge.complete(flow,tok,false,now);
                        if (!fragmented) reject_tun_udp(**pkt,now);
                        return;
                    }
                    if (out_idx >= 2) {
                        if (!routing.has_packet_outbound(out_idx)) {
                            (void)bridge.complete(flow, tok, false, now);
                            return;
                        }
                        net::ProxyAddress pa{};
                        pa.family=is_v6 ? net::ProxyAddressFamily::ipv6 : net::ProxyAddressFamily::ipv4;
                        pa.length=is_v6 ? 16 : 4;
                        pa.port=remote.port;
                        std::copy_n(ep.address.begin(),pa.length,pa.bytes.begin());
                        std::shared_ptr<UdpProxyFlow> pf;
                        if (tunnels!=proxy_map.end()) {
                            auto found=std::ranges::find_if(tunnels->second,[&](auto const& owner) {
                                return !owner->failed && owner->outbound==out_idx &&
                                    (!owner->tunnel->fixed_peer() || owner->first_target==pa);
                            });
                            if (found!=tunnels->second.end()) pf=*found;
                            else if (tunnels->second.size()>=32) {
                                (void)bridge.complete(flow,tok,false,now);
                                return;
                            }
                        }
                        if (!pf) {
                            auto lease_opt = routing.acquire_session();
                            if (!lease_opt) { (void)bridge.complete(flow, tok, false, now); return; }
                            pf=std::make_shared<UdpProxyFlow>(routing.executor_context());
                            pf->outbound=out_idx;
                            pf->connect_deadline=deadline;
                            routing.attach_session(pf->session,std::move(*lease_opt),std::move(snapshot));
                            pf->session.datagram_source=source;
                            pf->session.begin_traffic(proxy::TrafficProtocol::tun_udp,remote.port);
                            pf->tunnel = routing.open_packet_tunnel(pf->session, out_idx);
                            if (!pf->tunnel || pf->tunnel->transport().kind != net::PacketTransportKind::framed) {
                                pf->session.close();
                                (void)bridge.complete(flow, tok, false, now); return;
                            }
                            pf->framing = pf->tunnel->transport().framing;
                            pf->needs_uot_request = pf->tunnel->transport().needs_uot_request;
                            pf->first_target=pa;
                            proxy_map[flow].push_back(pf);
                            nex::capy::run_async(routing.executor_context().get_executor(), [] {}, [pf](std::exception_ptr) noexcept {
                                pf->failed = true;
                            })(run_udp_proxy(is_v6, flow, pf));
                        }
                        auto wire=net::encode_datagram(pf->framing,pa,payload);
                        if (wire && pf->tx_queue.size()<64) {
                            pf->tx_queue.push_back({std::move(*wire),payload.size(),deadline});
                            pf->work.set();
                            (void)bridge.complete(flow, tok, true, now);
                        } else (void)bridge.complete(flow, tok, false, now);
                        return;
                    }
                    auto it=direct;
                    if (it == direct_map.end()) {
                        if (direct_map.size() >= kMaxDirectUdpFlows || is_self_loop_udp(source, ep, std::nullopt)) {
                            if (is_self_loop_udp(source, ep, std::nullopt)) ++udp_self_loop_drops;
                            (void)bridge.complete(flow, tok, false, now);
                            return;
                        }
                        auto traffic=routing.track_traffic(proxy::TrafficProtocol::tun_udp,proxy::ConnectPath::direct,source,remote.port,true);
                        auto owner=std::make_unique<UdpDirectFlow>(&udp_binding,std::move(traffic),std::move(snapshot));
                        it = direct_map.emplace(flow,std::move(owner)).first;
                    }
                    std::optional<net::UdpEndpoint> local_ep;
                    for (auto const& bound : it->second->socket.local_endpoints()) {
                        if (bound && is_self_loop_udp(source, ep, bound)) { local_ep = *bound; break; }
                    }
                    if (is_self_loop_udp(source, ep, local_ep)) {
                        ++udp_self_loop_drops;
                        (void)bridge.complete(flow, tok, false, now);
                        return;
                    }
                    bool ok = it->second->socket.send(ep,payload).has_value();
                    if (ok) it->second->traffic.count(true,payload.size());
                    (void)bridge.complete(flow, tok, ok, now);
                };

                if (ver == 4) {
                    auto parsed = packet::parse_udp4(**pkt);
                    auto prep = udp4->prepare(**pkt, now);
                    if (parsed && prep) {
                        std::array<std::uint8_t, 16> sip{}; std::ranges::copy(parsed->source, sip.begin());
                        handle_one(false, *udp4, udp4_direct, udp4_proxy, prep->flow, prep->token, prep->remote, prep->payload, sip, parsed->source_port,parsed->dscp);
                    }
                } else if (ver == 6) {
                    auto parsed = packet::parse_udp6(**pkt);
                    auto prep = udp6->prepare(**pkt, now);
                    if (parsed && prep) {
                        handle_one(true, *udp6, udp6_direct, udp6_proxy, prep->flow, prep->token, prep->remote, prep->payload, parsed->source, parsed->source_port,parsed->dscp);
                    }
                }
            }
            return moved;
        }

        auto poll_udp_outputs(std::uint64_t now) -> bool {
            bool moved = false;
            std::array<std::uint8_t, 65536> buf{};
            (void)udp4->expire(now);
            (void)udp6->expire(now);
            auto poll_direct = [&](auto& direct_map, auto& bridge) {
                for (auto it=direct_map.begin();it!=direct_map.end();) {
                    auto const& [flow,sock]=*it++;
                    if (sock->traffic.close_requested()) {
                        auto id=flow;
                        (void)bridge->close(id,now);
                        continue;
                    }
                    for (int k = 0; k < 4; ++k) {
                        auto pkt = sock->socket.receive(buf);
                        if (!pkt || !*pkt) break;
                        moved = true;
                        std::expected<packet::Bytes, udp::BridgeError> built;
                        if constexpr (std::same_as<decltype(*bridge), udp::RoutedBridge4&>) {
                            udp::Endpoint4 rep{{}, (**pkt).source.port};
                            std::copy_n((**pkt).source.address.begin(), 4, rep.address.begin());
                            built = bridge->reply(flow, rep, std::span(buf).first((**pkt).size), now);
                        } else {
                            udp::Endpoint6 rep{(**pkt).source.address, (**pkt).source.port};
                            built = bridge->reply(flow, rep, std::span(buf).first((**pkt).size), now);
                        }
                        if (built && queue_udp_reply(std::move(*built)))
                            sock->traffic.count(false,(**pkt).size);
                    }
                }
            };
            poll_direct(udp4_direct, udp4);
            poll_direct(udp6_direct, udp6);
#ifdef NEXUS_ENABLE_FAKEIP
            moved|=poll_udp_aliases(udp4_aliases,*udp4,now);
            moved|=poll_udp_aliases(udp6_aliases,*udp6,now);
#endif
            while (!udp_replies.empty()) {
                auto rep = std::move(udp_replies.front());
                udp_replies.pop_front();
                moved = true;
                std::expected<packet::Bytes,udp::BridgeError> built;
                if (!rep.ipv6) {
                    udp::Endpoint4 src{{},rep.source_port};
                    std::copy_n(rep.source.begin(),4,src.address.begin());
                    built=udp4->reply(rep.flow,src,rep.payload,now);
                } else {
                    udp::Endpoint6 src{rep.source,rep.source_port};
                    built=udp6->reply(rep.flow,src,rep.payload,now);
                }
                if (built && queue_udp_reply(std::move(*built)))
                    rep.owner->session.count_traffic(false,rep.payload.size());
            }
            return moved;
        }
