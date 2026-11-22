// Private to the proxy DNS implementation.
        struct AddressPolicyRegistration {
            void*& operation;
            void (*&cancel)(void*) noexcept;
            ~AddressPolicyRegistration() {cancel=nullptr;operation=nullptr;}
        };
        auto resolve_response_program(Session& session,nex::corosio::io_context& context,std::string const& name,
            std::uint16_t port,dns::detail::AddressStrategy family,Clock::time_point deadline,policy::DnsContext input,
            void*& registered,void (*&cancel)(void*) noexcept,bool const* canceled=nullptr,
            std::optional<std::size_t> view_final={},std::span<dns::ResponseRaceMode const> modes={})
            -> nex::capy::task<DnsResult> {
            using Error=dns::detail::ResolveError;
            auto const& routing=session.dns->routing;
            // A later response-dependent option can change the effective TTL
            // after an evaluate, so its earlier cache lookup must also bypass.
            auto rewrite_possible=std::ranges::any_of(session.dns_rules(),[](auto const& rule){return rule.rewrite_ttl.has_value();});
            std::shared_ptr<dns::LocalSnapshot const> snapshot;
            if (session.local_dns) snapshot=session.local_dns->source.acquire();
            std::size_t rotation=(snapshot && snapshot->config.rotate && session.local_dns) ? session.local_dns->rotation++ : 0;
            auto types=dns::detail::address_types(family);auto count=dns::detail::address_type_count(family);
            std::vector<std::string> candidates;
            if (snapshot && count==2 && std::ranges::any_of(routing.servers,[](auto const& server){return !server.port;})) {
                auto host=dns::detail::local_hosts_response(*snapshot,name,types[0]);
                if (!host) co_return std::unexpected(host.error());
                if (host->response) candidates.push_back(host->question); else {
                    auto generated=dns::detail::local_response_candidates(snapshot->config,name,host->question);
                    if (!generated) co_return std::unexpected(generated.error());
                    candidates=std::move(*generated);
                }
            } else candidates.emplace_back();
            for (auto const& candidate:candidates) {
            dns::detail::AddressAnswers<false> answers;
            bool local_used=false;
            std::optional<std::pair<std::size_t,std::string>> local_candidate;
            bool next_candidate=false;
            for (unsigned i=0;i<count;++i) {
                if(!modes.empty() || policy::dns_has_concurrent_rules(session.dns_rules())) {
                    using Program=dns::AddressRaceProgram<AddressRaceOperation>;
                    if(cancel || (!modes.empty() && modes.size()!=session.dns_rules().size()))co_return std::unexpected(Error::state);
                    Program program(context,session.dns_rules(),modes,view_final.value_or(routing.final),routing.disable_cache);
                    AddressPolicyRegistration registration{registered,cancel};
                    registered=&program;cancel=[](void* value) noexcept {static_cast<Program*>(value)->cancel();};
                    AddressRaceFactory factory{session,context,name,types[i],port,snapshot,rewrite_possible,rotation,candidate,local_candidate};
                    auto decision=co_await program.run(factory,name,types[i],input,deadline);
                    cancel=nullptr;registered=nullptr;
                    if(session.closed || (canceled && *canceled))co_return std::unexpected(Error::canceled);
                    if(!decision)co_return std::unexpected(decision.error());
                    auto const& step=decision->step;
                    if(step.action==policy::DnsAction::reject)co_return std::unexpected(Error::policy_rejected);
                    if(step.action==policy::DnsAction::predefined) {
                        if(step.rule>=session.dns_rules().size() || !session.dns_rules()[step.rule].predefined)co_return std::unexpected(Error::state);
                        auto added=answers.add(dns::predefined_addresses(*session.dns_rules()[step.rule].predefined,{name,types[i]}));
                        if(!added)co_return std::unexpected(added.error());
                    } else if(step.action==policy::DnsAction::route) {
                        if(step.server>=routing.servers.size())co_return std::unexpected(Error::state);
                        auto local=!routing.servers[step.server].port;local_used|=local;
                        std::expected<dns::AddressAnswer,Error> answer=std::unexpected(Error::state);
                        if(decision->route) {
                            if(!*decision->route)answer=std::unexpected(decision->route->error());
                            else if(auto* selected=std::get_if<dns::AddressAnswer>(&**decision->route))answer=std::move(*selected);
                        } else {
                            auto one=types[i]==1 ? dns::detail::AddressStrategy::ipv4_only : dns::detail::AddressStrategy::ipv6_only;
                            dns::detail::FamilyCachePolicy cache{};cache[types[i]==1 ? 0 : 1]=step.disable_cache || rewrite_possible;
                            auto route_name=local && !candidate.empty() ? candidate+"." : name;
                            auto until=step.timeout_ms ? std::min(deadline,Clock::now()+std::chrono::milliseconds(*step.timeout_ms)) : deadline;
                            answer=co_await resolve_dns_value<true>(session,context,step.server,route_name,port,one,until,
                                registered,cancel,canceled,snapshot ? &snapshot : nullptr,cache,step.subnet.value_or(std::nullopt));
                        }
                        auto added=answers.add(std::move(answer));
                        if(!added) {if(local && added.error()==Error::name_not_found){next_candidate=true;break;}co_return std::unexpected(added.error());}
                    } else if(step.action==policy::DnsAction::respond) {
                        if(!decision->response || !decision->metadata)co_return std::unexpected(Error::state);
                        auto& selected=*decision->metadata;local_used|=selected.local;
                        if(selected.local && !selected.upstream.port() && selected.empty) {
                            auto added=answers.add(std::unexpected(Error::no_data));if(!added)co_return std::unexpected(added.error());
                        } else {
                            dns::detail::AddressResolver resolver(context,selected.tcp,routing.edns,selected.subnet,selected.protection.get());
                            AddressPolicyRegistration active{registered,cancel};
                            registered=&resolver;cancel=[](void* value) noexcept {static_cast<dns::detail::AddressResolver*>(value)->cancel();};
                            auto generator=[] {return dns::detail::random_id();};
                            auto answer=co_await resolver.resolve(selected.upstream,{selected.question,types[i]},selected.deadline,generator,&decision->response);
                            if(session.closed || (canceled && *canceled))co_return std::unexpected(Error::canceled);
                            auto added=answers.add(std::move(answer));
                            if(!added) {if(selected.local && added.error()==Error::name_not_found){next_candidate=true;break;}co_return std::unexpected(added.error());}
                        }
                    } else co_return std::unexpected(Error::state);
                    continue;
                }
                dns::ResponseWalk walk(session.dns_rules(),view_final.value_or(routing.final),routing.disable_cache);
                std::optional<dns::detail::EvaluatedResponseMeta> evaluation;
                std::vector<std::pair<std::string_view,dns::detail::EvaluatedResponseMeta>> named_evaluations;
                for (;;) {
                    if (session.closed || (canceled && *canceled)) co_return std::unexpected(Error::canceled);
                    if (Clock::now()>=deadline) co_return std::unexpected(Error::timeout);
                    auto step=walk.next(name,types[i],input);
                    if (!step) co_return std::unexpected(step.error()==dns::ResponseProgramError::resource_limit ? Error::limit : Error::state);
                    auto action_deadline=step->timeout_ms ? std::min(deadline,Clock::now()+std::chrono::milliseconds(*step->timeout_ms)) : deadline;
                    if (step->action==policy::DnsAction::reject) co_return std::unexpected(Error::policy_rejected);
                    if (step->action==policy::DnsAction::predefined) {
                        auto const& definition=*session.dns_rules()[step->rule].predefined;
                        auto answer=dns::predefined_addresses(definition,{name,types[i]});
                        auto added=answers.add(std::move(answer));
                        if (!added) co_return std::unexpected(added.error());
                        break;
                    }
                    auto one=types[i]==1 ? dns::detail::AddressStrategy::ipv4_only : dns::detail::AddressStrategy::ipv6_only;
                    if (step->action==policy::DnsAction::route) {
                        dns::detail::FamilyCachePolicy cache{};cache[types[i]==1 ? 0 : 1]=step->disable_cache || rewrite_possible;
                        auto local=!routing.servers[step->server].port;
                        local_used|=local;
                        auto route_name=local && !candidate.empty() ? candidate+"." : name;
                        auto answer=co_await resolve_dns_value<true>(session,context,step->server,route_name,port,one,action_deadline,
                            registered,cancel,canceled,snapshot ? &snapshot : nullptr,cache,step->subnet.value_or(std::nullopt));
                        auto added=answers.add(std::move(answer));
                        if (!added) {
                            if (local && added.error()==Error::name_not_found) { next_candidate=true;break; } co_return std::unexpected(added.error());
                        }
                        break;
                    }
                    if (step->action==policy::DnsAction::evaluate) {
                        auto fixed=!candidate.empty() ? std::optional<std::string_view>{candidate} :
                            local_candidate && local_candidate->first==step->server ? std::optional<std::string_view>{local_candidate->second} : std::nullopt;
                        auto evaluation_subnet=step->subnet.value_or(std::nullopt);
                        if(cancel)co_return std::unexpected(Error::state);
                        ResponseOperation operation(session,context,step->server,name,types[i],action_deadline,snapshot ? &snapshot : nullptr,
                            step->disable_cache || rewrite_possible,&rotation,fixed,evaluation_subnet);
                        AddressPolicyRegistration registration{registered,cancel};
                        registered=&operation;
                        cancel=[](void* value) noexcept {static_cast<ResponseOperation*>(value)->cancel();};
                        auto result=co_await operation.run();
                        if (!result) {
                            if(result.error()==Error::canceled || session.closed)co_return std::unexpected(Error::canceled);
                            if(result.error()==Error::budget_exhausted)co_return std::unexpected(Error::limit);
                            if(!walk.failed())co_return std::unexpected(Error::state);
                            continue;
                        }
                        auto selected=std::move(*result);
                        if (selected.local && !local_candidate) local_candidate.emplace(step->server,selected.question);
                        if(step->rewrite_ttl) {
                            auto const& raw=selected.response.wire;
                            if(raw.size()<2)co_return std::unexpected(Error::protocol);
                            auto id=static_cast<std::uint16_t>((std::uint16_t(raw[0])<<8)|raw[1]);
                            if(!dns::rewrite_response(selected.response,id,step->rewrite_ttl))co_return std::unexpected(Error::protocol);
                        }
                        dns::detail::EvaluatedResponseMeta meta{selected.upstream,selected.tcp,std::move(selected.question),selected.local,
                            selected.response.records.empty(),action_deadline,evaluation_subnet,selected.protection};
                        auto saved=walk.evaluated(std::move(selected.response));
                        if (!saved) co_return std::unexpected(saved.error()==dns::ResponseProgramError::resource_limit ? Error::limit : Error::state);
                        if(step->response_tag)named_evaluations.emplace_back(*step->response_tag,std::move(meta));
                        else evaluation=std::move(meta);
                        continue;
                    }
                    if (step->action==policy::DnsAction::respond) {
                        auto* selected=evaluation ? &*evaluation : nullptr;
                        if(step->response_tag) {
                            auto found=std::ranges::find(named_evaluations,*step->response_tag,&std::pair<std::string_view,dns::detail::EvaluatedResponseMeta>::first);
                            selected=found==named_evaluations.end() ? nullptr : &found->second;
                        }
                        if (!selected || cancel) co_return std::unexpected(Error::state);
                        local_used|=selected->local;
                        if (selected->local && !selected->upstream.port() && selected->empty) {
                            auto added=answers.add(std::unexpected(Error::no_data)); if (!added) co_return std::unexpected(added.error()); break;
                        }
                        auto first=walk.take_response();if (!first) co_return std::unexpected(Error::state);
                        dns::detail::AddressResolver resolver(context,selected->tcp,routing.edns,selected->subnet,selected->protection.get());
                        AddressPolicyRegistration registration{registered,cancel};
                        registered=&resolver;cancel=[](void* value) noexcept { static_cast<dns::detail::AddressResolver*>(value)->cancel(); };
                        auto generator=[] { return dns::detail::random_id(); };
                        auto answer=co_await resolver.resolve(selected->upstream,{selected->question,types[i]},selected->deadline,generator,&first);
                        if (session.closed || (canceled && *canceled)) co_return std::unexpected(Error::canceled);
                        auto added=answers.add(std::move(answer));
                        if (!added) {
                            if (selected->local && added.error()==Error::name_not_found) { next_candidate=true;break; } co_return std::unexpected(added.error());
                        }
                        break;
                    }
                    co_return std::unexpected(Error::state);
                }
                if (next_candidate) break;
            }
            if (next_candidate) continue;
            auto result=answers.finish();
            if (!result) {
                if (local_used && result.error()==Error::no_data) continue;
                co_return std::unexpected(result.error());
            }
            co_return endpoints(*result,port);
            }
            co_return std::unexpected(Error::no_data);
        }
