// Included in BasicUdpListener; all calls run on its serialized executor.
        auto advance_ordered(OrderedUdpDecision& decision,std::uint64_t token,Clock::time_point& deadline)
            -> std::expected<UdpResolvedAction,UdpResolveError> {
            auto fail=[&](UdpResolveError error) -> std::expected<UdpResolvedAction,UdpResolveError> {
                (void)sniff_owner_->complete(token);return std::unexpected(error);
            };
            auto now=Clock::now();
            if(stopped_ || now>=deadline)return fail(UdpResolveError::canceled);
            auto packet=state_.dispatcher_.pending_packet(token);
            if(!packet)return fail(UdpResolveError::state);
            auto step=decision.next(packet->packet.payload,true);
            deadline=std::min(deadline,decision.limit());
            if(Clock::now()>=deadline)return fail(UdpResolveError::canceled);
            if(step.stop==OrderedUdpStop::sniff_wait) {
                if(!sniff_owner_->wait(token,now))return fail(UdpResolveError::state);
                return UdpResolvedAction::complete;
            }
            if(step.stop==OrderedUdpStop::resolve)return UdpResolvedAction::resolve_again;
            if(step.stop!=OrderedUdpStop::route || !ordered_->allows(step.outbound))return fail(UdpResolveError::dispatch);
            if(decision.needs_resolution()) {
                if(!decision.resolve_selected())return fail(UdpResolveError::state);
                return UdpResolvedAction::resolve_again;
            }
            UdpTunnelReplySink sink=[this](UdpSessionHandle const& session,UdpPeer source,std::span<std::uint8_t const> payload) {
                return queue_tunnel_reply(session,source,payload);
            };
            auto sent=ordered_->send(context_,state_.dispatcher_,token,step.outbound,decision.candidates(),decision.inbound(),deadline,std::move(sink));
            (void)sniff_owner_->complete(token);
            if(!sent)return std::unexpected(sent.error());
            return UdpResolvedAction::complete;
        }
        auto send_legacy(std::uint64_t token,std::span<UdpPeer const> candidates,std::optional<std::string_view> inbound,
            Clock::time_point deadline) -> std::expected<UdpResolvedAction,UdpResolveError> {
            auto selected=state_.dispatcher_.select_route(token,candidates,Clock::now());
            if (!selected) return std::unexpected(UdpResolveError::dispatch);
            std::array target{selected->target};
            UdpTunnelReplySink sink=[this](UdpSessionHandle const& session,UdpPeer source,std::span<std::uint8_t const> payload) {
                return queue_tunnel_reply(session,source,payload);
            };
            auto sent=ordered_->send(context_,state_.dispatcher_,token,selected->outbound,target,inbound,deadline,std::move(sink));
            if (!sent) return std::unexpected(sent.error());
            return UdpResolvedAction::complete;
        }
        auto start_resolution(UdpPending pending,UdpPeer source,std::optional<std::string_view> inbound,
                              Clock::time_point deadline,std::shared_ptr<OrderedUdpDecision> decision={}) -> bool {
            auto const& a=pending.address;
            if(a.size()<5 || a[0]!=3 || a.size()!=static_cast<std::size_t>(a[1])+4)return false;
            UdpResolvePlan plan{upstream_,1,dns_options_.tcp_only,{}};
            std::optional<UdpResolvePlan> alternate;
            std::optional<dns::detail::FamilyCachePolicy> cache_policy;
#ifdef NEXUS_DNS_RESPONSE
            UdpResponseRouting const* response_routing=nullptr;
            UdpResponseContext response_context{};
#endif
            if(dns_routing_) {
                auto name=std::string_view(reinterpret_cast<char const*>(a.data()+2),a[1]);
                auto types=dns::detail::address_types(dns_options_.strategy);
                auto* packet=state_.dispatcher_.pending_packet(pending.token);
                auto auth_user=packet ? packet->auth_user : std::nullopt;
                policy::DnsContext input{.network=rules::Network::udp,.source_port=source.port,
                    .source_ip_bytes=std::span(source.address).first(source.family==4 ? 4 : 16),.inbound=inbound,.auth_user=auth_user};
#ifdef NEXUS_DNS_RESPONSE
                if(has_response_program_) {
                    for(unsigned i=0;i<dns::detail::address_type_count(dns_options_.strategy);++i)
                        if(policy::dns_preflight_reject(dns_routing_->rules,name,types[i],input))return false;
                    response_routing=&*dns_routing_;response_context.source=source.address;
                    response_context.size=source.family==4 ? 4 : 16;response_context.port=source.port;
                    response_context.inbound=inbound;
                    response_context.auth_user=auth_user;
                } else {
#endif
                auto selected=policy::select_question_dns_action(dns_routing_->rules,name,types[0],dns_routing_->fallback,dns_options_.disable_cache,input);
                auto second=dns::detail::address_type_count(dns_options_.strategy)==2 ?
                    policy::select_question_dns_action(dns_routing_->rules,name,types[1],dns_routing_->fallback,dns_options_.disable_cache,input) : selected;
                if(selected.action==policy::DnsAction::reject || second.action==policy::DnsAction::reject)return false;
                cache_policy.emplace();
                (*cache_policy)[types[0]==1 ? 0 : 1]=selected.disable_cache;
                if(dns::detail::address_type_count(dns_options_.strategy)==2)
                    (*cache_policy)[types[1]==1 ? 0 : 1]=second.disable_cache;
                plan=dns_plan(selected.server);
                if(dns::detail::address_type_count(dns_options_.strategy)==2 && second.server!=selected.server)
                    alternate=dns_plan(second.server);
#ifdef NEXUS_DNS_RESPONSE
                }
#endif
            }
            UdpResolvedHandler handler;
            if(decision)handler=[this,decision](std::uint64_t token,std::span<UdpPeer const> candidates,
                                                Clock::time_point& deadline)
                -> std::expected<UdpResolvedAction,UdpResolveError> {
                if(!decision->supply(candidates)) {
                    (void)sniff_owner_->complete(token);return std::unexpected(UdpResolveError::state);
                }
                return advance_ordered(*decision,token,deadline);
            };
            else if (ordered_) handler=[this,inbound](std::uint64_t token,std::span<UdpPeer const> candidates,
                                                       Clock::time_point& until) {
                return send_legacy(token,candidates,inbound,until);
            };
            auto started=resolver_.start(std::move(pending),plan.upstream,plan.view,Clock::now(),deadline,dns_options_.strategy,
                plan.tcp,dns_options_.disable_cache,dns_options_.edns,std::move(plan.hops),std::move(alternate),cache_policy
#ifdef NEXUS_DNS_RESPONSE
                ,response_routing,response_context
#endif
                ,std::move(handler));
            return started.has_value();
        }
        auto drain_ordered() -> void {
            auto busy=[this](std::uint64_t token){return resolver_.busy(token);};
            while(!stopped_) {
                auto ready=sniff_owner_->pop(Clock::now(),busy);if(!ready)break;
                struct Guard {
                    BasicUdpListener& owner;std::uint64_t token;bool transferred=false;
                    ~Guard() {
                        if(!transferred) {
                            (void)owner.sniff_owner_->complete(token);
                            (void)owner.state_.dispatcher_.cancel(token);
                        }
                    }
                } guard{*this,ready->token};
                auto result=advance_ordered(*ready->decision,ready->token,ready->deadline);
                if(!result)continue;
                if(*result==UdpResolvedAction::complete){guard.transferred=true;continue;}
                auto packet=state_.dispatcher_.pending_packet(ready->token);if(!packet)continue;
                guard.transferred=start_resolution({ready->token,packet->packet.address},packet->source,
                    ready->decision->inbound(),ready->deadline,ready->decision);
            }
        }
