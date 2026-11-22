        struct UdpResolution { bool active=false, canceled=false; Clock::time_point deadline{}; };
        auto udp_drive(Session& session, io::io_context& context, socks5::UdpIngress& ingress, UdpResolution& resolution, UotState& uot_state) -> capy::task<capy::results<>> {
            using namespace std::chrono_literals;
            try {
                while (!session.closed) {
                    socks5::UdpIngressStep report;
                    bool busy=false;
                    for (unsigned batch=0; batch<64 && !session.closed; ++batch) {
                        auto result=ingress.step();
                        if (!result || result->output_error) { session.close(); break; }
                        report=*result;
                        if (result->forwarded || result->delivered) session.touched=Clock::now();
                        if (resolution.active && !resolution.canceled && Clock::now()>=resolution.deadline) {
                            resolution.canceled=true;
                            if (session.cancel_dns) session.cancel_dns(session.dns_operation);
                        }
#ifdef NEXUS_ENABLE_FAKEIP
                        if (uot_state.aliases) uot_state.aliases->expire(Clock::now());
#endif
                        if (uot_state.active_deadline && Clock::now()>=*uot_state.active_deadline) {
                            session.close(); uot_state.cancel(); break;
                        }
                        busy=(result->input && !result->input_backpressured && !result->domain_pending && !result->route_pending && !result->tunnel_pending) ||
                            result->forwarded || result->delivered || result->output_dropped || result->input_error.has_value();
                        if (!busy) break;
                    }
                    if (session.closed) break;
                    auto deadline=uot_state.active_deadline.value_or(Clock::time_point::max());
                    if (resolution.active && !resolution.canceled) deadline=std::min(deadline,resolution.deadline);
                    auto ready=co_await ingress.wait(context,report,deadline);
                    if (!ready) {session.close();break;}
                }
                uot_state.cancel(); ingress.close();
                co_return capy::results<>{};
            } catch (...) { uot_state.cancel(); ingress.close(); session.close(); throw; }
        }
#include "session_udp_fakeip.hpp"

        auto udp_resolve(Session& session, io::io_context& context, socks5::UdpIngress& ingress,
                         UdpResolution& resolution,[[maybe_unused]] rules::RouteMatcher const& policy) -> capy::task<capy::results<>> {
            using namespace std::chrono_literals;
            try {
                while (!session.closed) {
                    ingress.changed().clear();
#ifdef NEXUS_ENABLE_FAKEIP
                    if (ingress.pending_route()) {
                        co_await udp_resolve_alias(session,context,ingress,resolution,policy);
                        ingress.discard_route();
                        continue;
                    }
#endif
                    auto packet=ingress.pending_domain();
                    if (!packet) {
                        auto [error]=co_await ingress.changed().wait();
                        if (error) { session.close(); break; }
                        continue;
                    }
                    auto name=std::string(reinterpret_cast<char const*>(packet->address.data()),packet->address_length);
                    auto port=packet->port;
                    auto peer=ingress.pending_domain_source();
                    if (!peer) { ingress.discard_domain(); continue; }
                    auto source=socks5::udp_endpoint(*peer);
                    resolution={true,false,ingress.pending_domain_deadline()};
                    if (Clock::now()>=resolution.deadline) { ingress.discard_domain(); resolution.active=false; continue; }
                    auto endpoints=co_await resolve_udp_domain(session,context,std::move(name),port,resolution.deadline,&source);
                    if (session.closed) break;
                    if (endpoints && !resolution.canceled) {
                        for (auto const& endpoint:*endpoints) {
                            if (endpoint.address().is_v6() && endpoint.address().to_v6().scope_id()!=0) continue;
                            socks5::UdpPeer candidate{endpoint.address().is_v4() ? std::uint8_t{1} : std::uint8_t{4},{},endpoint.port()};
                            if (candidate.address_type==1) {
                                auto bytes=endpoint.address().to_v4().to_bytes(); std::ranges::copy(bytes,candidate.address.begin());
                            } else {
                                auto bytes=endpoint.address().to_v6().to_bytes(); std::ranges::copy(bytes,candidate.address.begin());
                            }
                            while (!session.closed && !resolution.canceled && Clock::now()<resolution.deadline) {
                                auto sent=ingress.send_resolved(candidate);
                                if (sent) { session.touched=Clock::now(); break; }
                                auto error=std::get_if<std::error_code>(&sent.error());
                                if (!error || (*error!=std::errc::resource_unavailable_try_again && *error!=std::errc::interrupted)) break;
                                auto [delay_error]=co_await io::delay(5ms);
                                if (delay_error) { session.close(); break; }
                            }
                            if (!ingress.pending_domain() || session.closed || resolution.canceled) break;
                        }
                    }
                    ingress.discard_domain(); resolution.active=false;
                }
                co_return capy::results<>{};
            } catch (...) { session.close(); throw; }
        }
        auto udp_inspect_quic(Session& session,socks5::UdpIngress& ingress,UdpResolution& resolution,
                              std::chrono::milliseconds timeout) -> capy::task<sniff::QuicProbeResult> {
            using namespace std::chrono_literals;
            auto metadata=ingress.route_metadata();
            if(!metadata)co_return sniff::QuicProbeResult{};
            if(metadata->quic_inspected)co_return sniff::QuicProbeResult{
                metadata->quic_matched ? sniff::QuicProbeStatus::matched : sniff::QuicProbeStatus::unknown,
                metadata->quic_domain};
            auto packet=ingress.pending_route();auto source=ingress.pending_route_source();
            if(!packet || !source)co_return sniff::QuicProbeResult{};
            sniff::QuicProbeResult classification;
            std::array<std::size_t,8> members{};std::size_t count=0;
            auto limit=std::min(resolution.deadline,Clock::now()+timeout);
            if(auto probe=sniff::make_quic_probe()) {
                auto initial=probe->feed(packet->data);
                if(initial.status==sniff::QuicProbeStatus::matched)classification=std::move(initial);
                else if(initial.status==sniff::QuicProbeStatus::waiting) {
                    if(!ingress.begin_route_lookahead()){session.close();co_return sniff::QuicProbeResult{};}
                    struct Collect {socks5::UdpIngress& ingress;~Collect(){ingress.end_route_lookahead();}} collect{ingress};
                    std::size_t index=0;
                    while(!session.closed && !resolution.canceled && Clock::now()<limit) {
                        ingress.changed().clear();
                        auto next=ingress.lookahead_route(index);
                        if(!next) {
                            if(ingress.route_lookahead_full())break;
                            auto [error]=co_await nex::corosio::timeout(ingress.changed().wait(),limit);
                            if (error && !nex::capy::is_timeout(error)) session.close();
                            continue;
                        }
                        auto current=index++;
                        auto const& target=next->packet;
                        if(Clock::now()>=next->deadline || next->source!=*source || target.address_type!=packet->address_type ||
                           target.port!=packet->port || target.address_length!=packet->address_length ||
                           !std::equal(target.address.begin(),target.address.begin()+target.address_length,packet->address.begin()))continue;
                        auto observed=probe->feed(target.data);
                        if(observed.status==sniff::QuicProbeStatus::unrelated)continue;
                        // Unknown includes an authenticated conflicting fragment;
                        // it must not be independently re-sniffed during replay.
                        members[count++]=current;limit=std::min(limit,next->deadline);
                        if(observed.status==sniff::QuicProbeStatus::matched){classification=std::move(observed);break;}
                        if(observed.status==sniff::QuicProbeStatus::unknown)break;
                    }
                }
            }
            if(session.closed || resolution.canceled)co_return sniff::QuicProbeResult{};
            if(Clock::now()>=limit)classification={};
            auto matched=classification.status==sniff::QuicProbeStatus::matched;
            if(!ingress.remember_route_sniff(classification.domain,matched)){
                session.close();co_return sniff::QuicProbeResult{};
            }
            for(std::size_t i=0;i<count;++i) {
                auto member=ingress.lookahead_route(members[i]);
                if(member && Clock::now()<member->deadline &&
                   !ingress.remember_lookahead_sniff(members[i],classification.domain,matched)) {
                    session.close();co_return sniff::QuicProbeResult{};
                }
            }
            co_return classification;
        }
        auto udp_ordered(Session& session,io::io_context& context,socks5::UdpIngress& ingress,
            UdpResolution& resolution) -> capy::task<capy::results<>> {
            using namespace std::chrono_literals;
            try {
                while(!session.closed) {
                    ingress.changed().clear();
                    if(!ingress.pending_route())(void)ingress.replay_deferred();
                    auto packet=ingress.pending_route();auto peer=ingress.pending_route_source();
                    if(!packet || !peer) {auto [error]=co_await ingress.changed().wait();if(error)session.close();continue;}
                    auto metadata=ingress.route_metadata();
                    if(!metadata || Clock::now()>=metadata->deadline){ingress.discard_route();continue;}
                    resolution={true,false,metadata->deadline};
                    auto source=socks5::udp_endpoint(*peer);
                    rules::ProgramInput input{.port=packet->port,.network=rules::Network::udp,
                        .source_port=source.port,.source_ip_bytes=std::span(source.address).first(source.family==4 ? 4 : 16),
                        .inbound=session.inbound,.auth_user=session.auth_user};
                    auto routed_packet=*packet;
#ifdef NEXUS_ENABLE_FAKEIP
                    std::shared_ptr<UdpFakeIpLease> lease;
                    if (session.fakeip) {
                        std::shared_ptr<UdpFakeIpLease> owner;
                        if (packet->address_type!=3) owner=std::make_shared<UdpFakeIpLease>();
                        auto translated=udp_fakeip_target(session,*packet);
                        if (!translated) {ingress.discard_route();resolution.active=false;continue;}
                        if (translated->target) {
                            owner->target=std::move(translated->target);
                            routed_packet=udp_fakeip_domain(*packet,translated->request);
                            input.fakeip_domain=owner->target->mapping().domain;
                            input.domain_absent[static_cast<std::size_t>(rules::DomainSource::explicit_target)]=true;
                            lease=std::move(owner);
                        } else input.domain_absent[static_cast<std::size_t>(rules::DomainSource::fakeip)]=true;
                    }
#endif
                    std::string address,sniffed;
                    std::vector<io::endpoint> endpoints;
                    sniff::RouteCandidates candidates;
                    if(routed_packet.address_type==3) {
                        if (!input.fakeip_domain) {
                            address.assign(reinterpret_cast<char const*>(routed_packet.address.data()),routed_packet.address_length);
                            input.explicit_domain=address;
                        }
                    } else {
                        io::endpoint endpoint;
                        if(packet->address_type==1) {
                            io::ipv4_address::bytes_type bytes{};std::copy_n(packet->address.begin(),4,bytes.begin());endpoint={io::ipv4_address(bytes),packet->port};
                        } else {io::ipv6_address::bytes_type bytes{};std::copy_n(packet->address.begin(),16,bytes.begin());endpoint={io::ipv6_address(bytes),packet->port};}
                        address=endpoint.address().to_string();input.ip=address;endpoints.push_back(endpoint);
                        input.domain_absent[static_cast<std::size_t>(rules::DomainSource::explicit_target)]=true;
                    }
                    auto domain=input.fakeip_domain ? input.fakeip_domain : input.explicit_domain;
                    auto resolve=[&]() -> capy::task<bool> {
                        if(!domain)co_return true;
                        auto result=co_await resolve_destination(session,context,std::string(*domain),packet->port,resolution.deadline,
                            {.network=rules::Network::udp,.source_port=source.port,.source_ip_bytes=std::span(source.address).first(source.family==4 ? 4 : 16)});
                        if(!result || resolution.canceled || session.closed || Clock::now()>=resolution.deadline || !candidates.assign(*result,input))co_return false;
                        endpoints=std::move(*result);co_return true;
                    };
                    rules::ProgramCursor cursor;auto const& policy=*session.ordered_tcp;
                    if (policy.program.has_dns_hijack()) input.dns_query=dns::parse_query(packet->data).has_value();
                    std::size_t selected=policy.fallback;bool valid=true;
                    std::optional<std::size_t> route_rule;
                    for(;;) {
                        auto step=cursor.poll(policy.program,input);
                        if(!step){valid=false;break;}
                        if(step->kind==rules::ProgramPreflightKind::uncertain) {
                            if(policy.unknown_policy!=sniff::UnknownRoutePolicy::skip || !cursor.skip_unknown(step->rule_index)){valid=false;break;}
                            continue;
                        }
                        if(step->kind==rules::ProgramPreflightKind::exhausted)break;
                        auto action=*step->step;
                        if(action.action.kind==rules::ProgramActionKind::reject){valid=false;break;}
                        if(action.action.kind==rules::ProgramActionKind::hijack_dns) {
                            auto response=co_await hijack_dns_query(session,context,packet->data,source,resolution.deadline);
                            while(response && !session.closed && !resolution.canceled && Clock::now()<resolution.deadline) {
                                auto queued=ingress.reply_route(*response);
                                if(!queued || *queued!=socks5::UdpReplyStatus::busy)break;
                                auto [error]=co_await io::delay(5ms);
                                if(error){session.close();break;}
                            }
                            valid=false;break;
                        }
                        if(auto timeout=action.action.connect_timeout_ms) {
                            resolution.deadline=ingress.limit_route(std::chrono::milliseconds(timeout));
                            if (Clock::now()>=resolution.deadline) {valid=false;break;}
                        }
                        if (action.action.kind==rules::ProgramActionKind::route) {
                            selected=action.action.outbound;
                            route_rule=action.rule_index;
                            break;
                        }
                        if(action.action.kind==rules::ProgramActionKind::route_options) {
                            if(!cursor.complete(action)){valid=false;break;}
                        } else if(action.action.kind==rules::ProgramActionKind::resolve) {
                            if(!co_await resolve() || !cursor.complete(action)){valid=false;break;}
                        } else if(action.action.kind==rules::ProgramActionKind::sniff) {
                            // Incomplete or unrecognized payloads retain unknown
                            // metadata for the configured policy to handle.
                            auto query=dns::parse_query(packet->data);
                            input.sniffed_domain.reset();
                            if(query) {
                                input.protocol=rules::Protocol::dns;
                                if(rules::valid_domain(query->question.name)) {
                                    sniffed=std::move(query->question.name);input.sniffed_domain=sniffed;
                                }
                            } else if(sniff::stun_datagram(packet->data)) {
                                input.protocol=rules::Protocol::stun;
                                input.domain_absent[static_cast<std::size_t>(rules::DomainSource::sniffed)]=true;
                            } else {
                                auto quic=co_await udp_inspect_quic(session,ingress,resolution,policy.sniff_timeout);
                                if (quic.status==sniff::QuicProbeStatus::matched) {
                                    input.protocol=rules::Protocol::quic;
                                    if (quic.domain) {
                                        sniffed=std::move(*quic.domain);input.sniffed_domain=sniffed;
                                    }
                                }
                            }
                            if(!cursor.complete(action)){valid=false;break;}
                        } else {valid=false;break;}
                        if(session.closed || resolution.canceled || Clock::now()>=resolution.deadline){valid=false;break;}
                    }
                    if (session.route_snapshot)
                        selected=session.route_snapshot->matcher.choose_outbound(selected,domain.value_or(input.ip.value_or("")));
                    if(valid && selected!=1 && domain && !candidates.view())valid=co_await resolve();
#ifdef NEXUS_ENABLE_FAKEIP
                    if (lease) {
                        if (valid && selected!=1 && !resolution.canceled && !session.closed)
                            co_await udp_send_alias(session,ingress,resolution,routed_packet,endpoints,lease,nullptr,*peer,
                                route_rule,selected);
                        valid=false;
                    }
#endif
                    if(valid && selected!=1 && !resolution.canceled && !session.closed) {
                        for(auto const& endpoint:endpoints) {
                            if(endpoint.address().is_v6() && endpoint.address().to_v6().scope_id())continue;
                            socks5::UdpPeer candidate{endpoint.address().is_v4() ? std::uint8_t{1} : std::uint8_t{4},{},endpoint.port()};
                            if(candidate.address_type==1) {auto bytes=endpoint.address().to_v4().to_bytes();std::ranges::copy(bytes,candidate.address.begin());}
                            else {auto bytes=endpoint.address().to_v6().to_bytes();std::ranges::copy(bytes,candidate.address.begin());}
                            while(!session.closed && !resolution.canceled && Clock::now()<resolution.deadline) {
                                auto sent=ingress.send_selected(candidate,selected,route_rule);
                                if(sent){session.touched=Clock::now();break;}
                                auto error=std::get_if<std::error_code>(&sent.error());
                                if(!error || (*error!=std::errc::resource_unavailable_try_again && *error!=std::errc::interrupted))break;
                                auto [delay_error]=co_await io::delay(5ms);if(delay_error)session.close();
                            }
                            if(!ingress.pending_route() || session.closed || resolution.canceled)break;
                        }
                    }
                    ingress.discard_route();resolution.active=false;
                }
                co_return capy::results<>{};
            } catch(...) {session.close();throw;}
        }
