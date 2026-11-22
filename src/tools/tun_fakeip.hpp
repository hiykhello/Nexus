// Private UDP FakeIP adapter included by the TUN owner.
#pragma once
#ifdef NEXUS_ENABLE_FAKEIP
        static auto retire_udp_alias(UdpAliases& aliases,udp::FlowId id) noexcept -> void {
            auto found=aliases.find(id);
            if (found==aliases.end()) return;
            found->second->socket.close();
            found->second->session.close();
            aliases.erase(found);
        }

        static auto udp_alias_request(net::UdpEndpoint const& alias) -> socks5::Request {
            socks5::Request request;
            request.status=socks5::Status::accepted;
            request.port=alias.port;
            request.address_type=alias.family==4 ? 1 : 4;
            request.address_length=alias.family==4 ? 4 : 16;
            std::copy_n(alias.address.begin(),request.address_length,request.address.begin());
            return request;
        }

        auto find_udp_alias_target(UdpAliasFlow& flow,net::UdpEndpoint source,std::span<std::uint8_t const> payload,
            Clock::time_point received,Clock::time_point& deadline)
            -> nex::capy::task<std::optional<net::UdpEndpoint>> {
            auto& session=flow.session;
            auto const& domain=session.fakeip_target->mapping().domain;
            if (session.ordered_tcp) {
                net::ProxyAddress address{};
                address.family=net::ProxyAddressFamily::domain;
                address.port=flow.alias.port;
                address.length=static_cast<std::uint8_t>(domain.size());
                std::ranges::copy(domain,address.bytes.begin());
                auto route=proxy::ordered_datagram_router(session,routing.executor_context(),source,true);
                net::stream_datagrams::OrderedSniffer inspect=[payload](Clock::time_point)
                    -> nex::capy::task<sniff::QuicProbeResult> {
                    co_return sniff::sniff_quic_datagram(payload);
                };
                auto result=co_await route(address,payload,received,deadline,inspect);
                if (!result || result->outbound!=0) co_return std::nullopt;
                for (auto const& target:result->candidates)
                    if (!routing.protects_fakeip(std::span(target.address).first(target.family==4 ? 4 : 16)))
                        co_return target;
                co_return std::nullopt;
            }
            auto result=co_await proxy::resolve_udp_domain(session,routing.executor_context(),
                domain,flow.alias.port,deadline,&source);
            if (!result || session.closed) co_return std::nullopt;
            auto const& policy=session.route_snapshot ? session.route_snapshot->matcher : routing.routing_policy();
            for (auto const& candidate : *result) {
                auto address=candidate.address();
                net::UdpEndpoint target{address.is_v4() ? std::uint8_t{4} : std::uint8_t{6},{},candidate.port()};
                if (address.is_v4()) {
                    auto bytes=address.to_v4().to_bytes();
                    std::ranges::copy(bytes,target.address.begin());
                } else {
                    auto ipv6=address.to_v6();
                    if (ipv6.scope_id()) continue;
                    auto bytes=ipv6.to_bytes();
                    std::ranges::copy(bytes,target.address.begin());
                }
                if (!target.port || address.is_unspecified() ||
                    routing.protects_fakeip(std::span(target.address).first(target.family==4 ? 4 : 16))) continue;
                auto text=address.to_string();
                auto selected=policy.match(session.ingress.apply(rules::MatchInput{.domain=domain,.ip=text,.port=target.port,
                    .network=rules::Network::udp,.source_port=source.port,
                    .source_ip_bytes=std::span(source.address).first(source.family==4 ? 4 : 16),
                    .source_interface=tun->name()}));
                if (!selected || policy.choose_outbound(*selected,domain)!=0) continue;
                co_return target;
            }
            co_return std::nullopt;
        }

        template<class Bridge>
        auto resolve_udp_alias(Bridge& bridge,UdpAliases& aliases,udp::FlowId id,std::uint64_t token,
            std::shared_ptr<UdpAliasFlow> flow,net::UdpEndpoint source,std::vector<std::uint8_t> payload,Clock::time_point received)
            -> nex::capy::task<> {
            auto deadline=received+std::chrono::seconds(10);
            auto target=co_await find_udp_alias_target(*flow,source,payload,received,deadline);
            if (flow->session.closed || stop_flag.load(std::memory_order_acquire)) co_return;
            if (target && Clock::now()<deadline) {
                flow->target=*target;
                auto sent=flow->socket.send(*target,payload);
                if (sent && bridge.complete(id,token,true,now_ms())) {
                    flow->session.count_traffic(true,payload.size());
                    co_return;
                }
            }
            (void)bridge.complete(id,token,false,now_ms());
            retire_udp_alias(aliases,id);
        }

        template<class Bridge>
        auto send_udp_alias(Bridge& bridge,UdpAliases& aliases,udp::FlowId id,std::uint64_t token,
            net::UdpEndpoint alias,net::UdpEndpoint source,std::span<std::uint8_t const> payload,Clock::time_point received,
            rules::IngressMetadata ingress) -> void {
            if (auto existing=aliases.find(id); existing!=aliases.end()) {
                auto& flow=*existing->second;
                if (flow.session.ingress==ingress || !flow.target.port) {
                    auto sent=flow.target.port && flow.alias==alias && flow.socket.send(flow.target,payload);
                    if (bridge.complete(id,token,sent,now_ms()) && sent) flow.session.count_traffic(true,payload.size());
                    return;
                }
                retire_udp_alias(aliases,id);
            }
            auto permit=routing.acquire_session();
            if (!permit) { (void)bridge.complete(id,token,false,now_ms()); return; }
            auto flow=std::make_shared<UdpAliasFlow>(routing.executor_context(),&udp_binding,alias);
            auto& session=flow->session;
            routing.attach_session(session,std::move(*permit));
            auto translated=dns::translate_fakeip_request(*session.fakeip,udp_alias_request(alias),session.fakeip_view);
            if (!translated || !translated->target) { (void)bridge.complete(id,token,false,now_ms()); return; }
            session.fakeip_target=std::move(translated->target);
            session.datagram_source=source;
            session.ingress=ingress;
            session.source_interface=tun->name();
            session.begin_traffic(proxy::TrafficProtocol::tun_udp,alias.port);
            session.select_traffic_path(proxy::ConnectPath::direct);
            aliases.emplace(id,flow);
            nex::capy::run_async(routing.executor_context().get_executor(),[] {},
                [&bridge,&aliases,id,token,flow](std::exception_ptr) noexcept {
                    if (!flow->session.closed) {
                        (void)bridge.complete(id,token,false,now_ms());
                        retire_udp_alias(aliases,id);
                    }
                })(resolve_udp_alias(bridge,aliases,id,token,flow,source,{payload.begin(),payload.end()},received));
        }

        template<class Bridge>
        auto poll_udp_aliases(UdpAliases& aliases,Bridge& bridge,std::uint64_t now) -> bool {
            bool progress=false;
            std::array<std::uint8_t,65536> bytes;
            for (auto it=aliases.begin(); it!=aliases.end();) {
                auto const& [id,flow]=*it++;
                if (flow->session.closed) {
                    (void)bridge.close(id,now);
                    continue;
                }
                if (!flow->target.port) continue;
                auto received=flow->socket.receive(bytes);
                if (!received || !*received) continue;
                progress=true;
                if (!(**received).valid || (**received).source!=flow->target) continue;
                auto payload=std::span(bytes).first((**received).size);
                auto wire=[&] {
                    if constexpr (std::same_as<Bridge,udp::RoutedBridge4>) {
                        udp::Endpoint4 source{{},flow->alias.port};
                        std::copy_n(flow->alias.address.begin(),4,source.address.begin());
                        return bridge.reply(id,source,payload,now);
                    } else return bridge.reply(id,udp::Endpoint6{flow->alias.address,flow->alias.port},payload,now);
                }();
                if (wire && queue_udp_reply(std::move(*wire))) flow->session.count_traffic(false,payload.size());
            }
            return progress;
        }
#endif
