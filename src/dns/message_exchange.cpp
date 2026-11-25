module dns.message_exchange;
import std;
import dns.message;
import dns.message_fakeip;
import dns.input_budget;
import dns.response_program;
import dns.message_cache;
import dns.message_synthetic;
import dns.policy;
import dns.response_query;
import rules;
import dns.local_config;
import dns.corosio_resolver;
import capy;
import corosio;

namespace dns {
    auto MessageExchange::refresh(corosio::io_context& context,std::shared_ptr<MessageCache> cache,MessageCache::Ticket ticket,
        corosio::endpoint endpoint,QueryMessage query,Clock::time_point until,bool tcp,
        std::shared_ptr<detail::ProtectedQuery const> protection,InputBudget::Lease reservation)
        -> capy::task<> {
        (void)reservation;
        struct Registration {
            MessageCache& cache;
            MessageCache::Ticket ticket;
            ~Registration() {cache.cancel(ticket);}
        } registration{*cache,ticket};
        try {
            auto stop=cache->refresh_token();
            if (stop.stop_requested()) co_return;
            detail::MessageQuery transport(context,tcp,protection.get());
            std::stop_callback cancellation(stop,[&transport] noexcept {transport.cancel();});
            auto wire=co_await transport.run_borrowed(endpoint,query,until);
            if (!wire || stop.stop_requested()) co_return;
            auto response=parse_owned_response(std::move(*wire),query.id,query.question);
            if (response && (response->rcode==0 || response->rcode==3))
                cache->publish(ticket,query,std::move(*response),Clock::now());
        } catch (...) {}
    }

    auto MessageExchange::start_refresh(std::shared_ptr<MessageCache> cache,MessageCache::Ticket ticket,corosio::endpoint endpoint,
        QueryMessage const& query,Clock::time_point until,std::size_t server,bool tcp) -> void {
        auto cost=listener_query_cost(query);
        if (cost) {
            auto lease=default_message_override_budget().acquire(*cost);
            if (lease) {
                try {
                    capy::run_async(context_.get_executor(),[] {},
                        [cache,ticket](std::exception_ptr) noexcept {cache->cancel(ticket);})
                        (refresh(context_,cache,ticket,endpoint,query,until,tcp,upstreams_[server].protection,std::move(*lease)));
                    return;
                } catch (...) {
                    cache->cancel(ticket);
                    throw;
                }
            }
        }
        cache->cancel(ticket);
    }

    auto MessageExchange::run_flight(corosio::io_context& context,std::shared_ptr<MessageCache::QueryFlight> flight,
        corosio::endpoint endpoint,QueryMessage query,bool tcp,
        std::shared_ptr<detail::ProtectedQuery const> protection,InputBudget::Lease reservation)
        -> capy::task<MessageCache::QueryFlight::Result> {
        (void)reservation;
        try {
            auto stop=flight->stop.get_token();
            if (stop.stop_requested()) co_return std::unexpected(detail::ResolveError::canceled);
            detail::MessageQuery transport(context,tcp,protection.get());
            std::stop_callback cancellation(stop,[&transport] noexcept {transport.cancel();});
            co_return co_await transport.run_borrowed(endpoint,query,flight->deadline);
        } catch (...) {}
        co_return std::unexpected(detail::ResolveError::state);
    }

    auto MessageExchange::coalesced(MessageCache::JoinedQuery joined,corosio::endpoint endpoint,QueryMessage const& query,
        Clock::time_point until,std::size_t server,bool tcp) -> capy::task<MessageCache::QueryFlight::Result> {
        using Error=detail::ResolveError;
        auto& flight=*joined.flight;
        ++flight.waiters;
        flight_=&flight;
        struct Registration {
            MessageExchange& owner;
            MessageCache::QueryFlight& flight;
            ~Registration() {
                owner.flight_=nullptr;
                if (--flight.waiters) return;
                if (!flight.result) flight.stop.request_stop();
                owner.cache_->cancel(flight.ticket);
            }
        } registration{*this,flight};
        if (joined.launch) {
            auto cost=listener_query_cost(query);
            auto lease=cost ? default_message_override_budget().acquire(*cost) : std::nullopt;
            if (!lease) co_return std::unexpected(Error::budget_exhausted);
            auto fail_flight = [](std::shared_ptr<MessageCache::QueryFlight> const& owner) noexcept {
                try { owner->complete(std::unexpected(Error::state)); }
                catch (...) { owner->result.emplace(std::unexpected(Error::state)); owner->changed.set(); }
            };
            try {
                capy::run_async(context_.get_executor(),
                    [owner=joined.flight, fail_flight](auto result) noexcept {
                        try { owner->complete(std::move(result)); }
                        catch (...) { fail_flight(owner); }
                    },
                    [owner=joined.flight, fail_flight](std::exception_ptr) noexcept { fail_flight(owner); })
                    (run_flight(context_,joined.flight,endpoint,query,tcp,upstreams_[server].protection,std::move(*lease)));
            } catch (...) {
                fail_flight(joined.flight);
                co_return std::unexpected(Error::state);
            }
        }
        while (!flight.result && !canceled_) {
            flight.changed.clear();
            auto [error]=co_await corosio::timeout(flight.changed.wait(),until);
            if (error) co_return std::unexpected(canceled_ ? Error::canceled :
                capy::is_timeout(error) ? Error::timeout : Error::canceled);
        }
        if (canceled_) co_return std::unexpected(Error::canceled);
        if (Clock::now()>=until) co_return std::unexpected(Error::timeout);
        if (!*flight.result) co_return std::unexpected(flight.result->error());
        auto wire=**flight.result;
        wire[0]=static_cast<std::uint8_t>(query.id>>8);
        wire[1]=static_cast<std::uint8_t>(query.id);
        if (!std::exchange(flight.published,true)) {
            auto response=parse_response(wire,query.id,query.question);
            if (response) cache_->publish(flight.ticket,query,std::move(*response),Clock::now());
        }
        co_return wire;
    }

    auto MessageExchange::exchange(corosio::endpoint endpoint,QueryMessage const& query,Clock::time_point until,
        std::size_t server,bool tcp,bool disabled,std::shared_ptr<LocalSnapshot const> snapshot)
        -> capy::task<std::expected<Bytes,detail::ResolveError>> {
        using Error=detail::ResolveError;
        stale_cache_=false;
        if(canceled_)co_return std::unexpected(Error::canceled);
        if(Clock::now()>=until)co_return std::unexpected(Error::timeout);
        if(cache_ && !disabled) {
            auto cache_scope=independent_cache_ ? static_cast<std::uint32_t>(step_.rule+1) : 0u;
            MessageCache::View view(server,endpoint,tcp,snapshot,policy_view_,cache_scope);
            auto now=Clock::now();
            if (auto cached=cache_->lookup(view,query,now)) co_return std::move(*cached);
            if (cache_->optimistic()) {
                auto owner=cache_->weak_from_this().lock();
                if (owner) if (auto stale=owner->lookup_stale(view,query,now)) {
                    if (stale->refresh)
                        start_refresh(std::move(owner),*stale->refresh,endpoint,query,until,server,tcp);
                    stale_cache_=true;
                    co_return std::move(stale->wire);
                }
            }
            auto joined=cache_->join(view,query,until);
            if (!joined) co_return std::unexpected(joined.error());
            if (*joined) {
                bool may_retry=!(*joined)->launch && (*joined)->flight->deadline<until;
                auto response=co_await coalesced(std::move(**joined),endpoint,query,until,server,tcp);
                if (response || !may_retry || response.error()!=Error::timeout || Clock::now()>=until)
                    co_return response;
                auto retry=cache_->join(view,query,until);
                if (!retry) co_return std::unexpected(retry.error());
                if (*retry) co_return co_await coalesced(std::move(**retry),endpoint,query,until,server,tcp);
            }
        }
        active_.emplace(context_,tcp,upstreams_[server].protection.get());
        auto wire=co_await active_->run_borrowed(endpoint,query,until);active_.reset();
        if(canceled_)co_return std::unexpected(Error::canceled);
        co_return wire;
    }

    auto MessageExchange::run() -> capy::task<std::expected<Bytes,detail::ResolveError>> {
        using Error=detail::ResolveError;
        if(std::exchange(started_,true) || step_.server>=upstreams_.size())co_return std::unexpected(Error::state);
        if(canceled_)co_return std::unexpected(Error::canceled);
        if(step_.action==policy::DnsAction::route && query_.question.klass==1 &&
            ((step_.strategy==rules::DnsRuleStrategy::ipv4_only && query_.question.type==28) ||
             (step_.strategy==rules::DnsRuleStrategy::ipv6_only && query_.question.type==1))) {
            policy::PredefinedResponse empty{.rcode=0};
            auto reply=synthetic_message(query_,empty);
            if(!reply)co_return std::unexpected(Error::protocol);
            local_synthetic_=true;
            co_return std::move(*reply);
        }
        if(step_.subnet) {
            // Conservatively reserve the original capacity plus room for
            // both old and expanded option vectors during reallocation,
            // plus the replacement ECS.
            auto cost=listener_query_cost(query_);
            constexpr auto extra=256*sizeof(QueryOption)+32;
            if(!cost || *cost>std::numeric_limits<std::size_t>::max()-extra)co_return std::unexpected(Error::limit);
            auto lease=override_budget_.acquire(*cost+extra);if(!lease)co_return std::unexpected(Error::budget_exhausted);
            override_lease_.emplace(std::move(*lease));
            upstream_query_.emplace(query_);
            if(!set_query_client_subnet(*upstream_query_,*step_.subnet))co_return std::unexpected(Error::protocol);
        }
        auto const& query=query_;auto const& upstream_query=this->upstream_query();
        auto const& upstream=upstreams_[step_.server];auto until=until_;auto& local_synthetic=local_synthetic_;
        std::expected<Bytes,Error> wire=std::unexpected(Error::state);
        if(upstream.local) {
            auto snapshot=upstream.local->snapshots.acquire();
            if(!snapshot)co_return std::unexpected(Error::state);
            auto const& local=*snapshot;
            if(query.question.klass==1 && (query.question.type==1 || query.question.type==28)) {
                auto hosts=detail::local_hosts_response(local,query.question.name,query.question.type);
                if(!hosts)co_return std::unexpected(hosts.error());
                if(hosts->response) {
                    auto encoded=encode_response(*hosts->response,query.id,{});
                    if(!encoded)co_return std::unexpected(Error::protocol);
                    (*encoded)[2]=static_cast<std::uint8_t>(((*encoded)[2]&~0x01u)|((query.flags>>8)&0x01u));
                    (*encoded)[3]=static_cast<std::uint8_t>(((*encoded)[3]&~0x10u)|(query.flags&0x10u));
                    if(query.edns) {
                        auto payload=std::clamp<std::uint16_t>(query.edns->udp_payload_size,512,4096);
                        (*encoded)[10]=0;(*encoded)[11]=1;
                        encoded->insert(encoded->end(),{0,0,41,static_cast<std::uint8_t>(payload>>8),static_cast<std::uint8_t>(payload),0,0,static_cast<std::uint8_t>(query.edns->dnssec_ok ? 0x80 : 0),0,0,0});
                    }
                    auto parsed=parse_response(*encoded,query.id,query.question);if(!parsed)co_return std::unexpected(Error::protocol);
                    encoded=complete_response_ecs(query,*parsed);if(!encoded)co_return std::unexpected(Error::protocol);
                    wire=std::move(*encoded);
                    local_synthetic=true;
                }
            }
            if(!wire) {
                auto const& cfg=local.config;
                if(cfg.servers.empty() || cfg.servers.size()>3 || !cfg.attempts || cfg.attempts>5 || !cfg.timeout_seconds || cfg.timeout_seconds>30)co_return std::unexpected(Error::state);
                auto last=Error::transport;
                std::optional<Bytes> last_failure_response;
                auto rotation=cfg.rotate ? upstream.local->rotation.fetch_add(1,std::memory_order_relaxed)%cfg.servers.size() : 0;
                for(std::uint32_t attempt=0;attempt<cfg.attempts && !wire;++attempt) {
                    for(std::size_t index=0;index<cfg.servers.size();++index) {
                        auto const& server=cfg.servers[(rotation+index)%cfg.servers.size()];
                        if(canceled_)co_return std::unexpected(Error::canceled);
                        auto now=Clock::now();if(now>=until)co_return std::unexpected(Error::timeout);
                        corosio::endpoint endpoint;
                        if(server.ipv6)endpoint={corosio::ipv6_address(server.address),server.port};
                        else {corosio::ipv4_address::bytes_type bytes{};std::copy_n(server.address.begin(),4,bytes.begin());endpoint={corosio::ipv4_address(bytes),server.port};}
                        wire=co_await exchange(endpoint,upstream_query,std::min(until,now+std::chrono::seconds(cfg.timeout_seconds)),step_.server,cfg.use_tcp,step_.disable_cache,snapshot);
                        if(wire) {
                            auto response=parse_response(*wire,query.id,query.question);
                            if(!response)co_return std::unexpected(Error::protocol);
                            if(response->rcode!=2 && response->rcode!=5)break;
                            last_failure_response=std::move(*wire);
                            wire=std::unexpected(response->rcode==2 ? Error::server_failure : Error::refused);
                            continue;
                        }
                        last=wire.error();if(last!=Error::transport && last!=Error::timeout)co_return std::unexpected(last);
                    }
                }
                if(!wire && last_failure_response)wire=std::move(*last_failure_response);
                if(!wire)co_return std::unexpected(last);
            }
        } else {
            std::vector<std::size_t> chain;auto current=step_.server;
            while(upstreams_[current].resolver) {
                if(chain.size()>=upstreams_.size())co_return std::unexpected(Error::state);
                chain.push_back(current);current=*upstreams_[current].resolver;
                if(current>=upstreams_.size())co_return std::unexpected(Error::state);
            }
            std::vector<corosio::endpoint> endpoints;
            std::shared_ptr<LocalSnapshot const> bootstrap_local;
            std::shared_ptr<LocalSnapshot const> cache_snapshot;
            if(upstreams_[current].endpoint.port()) endpoints.push_back(upstreams_[current].endpoint);
            else if(upstreams_[current].local) {
                bootstrap_local=upstreams_[current].local->snapshots.acquire();if(!bootstrap_local)co_return std::unexpected(Error::state);
                cache_snapshot=bootstrap_local;
                auto const& cfg=bootstrap_local->config;
                if(cfg.servers.size()>3 || !cfg.attempts || cfg.attempts>5 || !cfg.timeout_seconds || cfg.timeout_seconds>30)co_return std::unexpected(Error::state);
                auto rotation=cfg.rotate && !cfg.servers.empty() ? upstreams_[current].local->rotation.fetch_add(1,std::memory_order_relaxed)%cfg.servers.size() : 0;
                for(std::size_t index=0;index<cfg.servers.size();++index) {
                    auto const& server=cfg.servers[(rotation+index)%cfg.servers.size()];
                    if(server.ipv6)endpoints.emplace_back(corosio::ipv6_address(server.address),server.port);
                    else {corosio::ipv4_address::bytes_type bytes{};std::copy_n(server.address.begin(),4,bytes.begin());endpoints.emplace_back(corosio::ipv4_address(bytes),server.port);}
                }
            }
            for(auto it=chain.rbegin();it!=chain.rend();++it) {
                auto const& next=upstreams_[*it];if(next.host.empty() || !next.port)co_return std::unexpected(Error::state);
                std::vector<corosio::endpoint> resolved;
                bool hosts_known=false;
                if(bootstrap_local) {
                    auto name=normalize_local_name(next.host);if(!name)co_return std::unexpected(Error::protocol);
                    for(auto const& host:bootstrap_local->hosts) if(host.name==*name) {
                        hosts_known=true;
                        if(host.address.ipv6)resolved.emplace_back(corosio::ipv6_address(host.address.address),next.port);
                        else {corosio::ipv4_address::bytes_type bytes{};std::copy_n(host.address.address.begin(),4,bytes.begin());resolved.emplace_back(corosio::ipv4_address(bytes),next.port);}
                        if(resolved.size()>64)co_return std::unexpected(Error::limit);
                    }
                }
                auto attempts=bootstrap_local ? bootstrap_local->config.attempts : 1u;
                auto last=Error::transport;
                std::vector<std::string> candidates{next.host};
                if(bootstrap_local && !hosts_known) {
                    auto normalized=normalize_local_name(next.host);if(!normalized)co_return std::unexpected(Error::protocol);
                    auto search=detail::local_response_candidates(bootstrap_local->config,next.host,*normalized);
                    if(!search)co_return std::unexpected(search.error());
                    candidates=std::move(*search);
                }
                for(auto const& name:candidates) {
                    if(hosts_known || !resolved.empty())break;
                    for(std::uint32_t attempt=0;attempt<attempts && resolved.empty();++attempt) {
                        for(auto const& endpoint:endpoints) {
                            std::optional<std::string> canonical;std::vector<corosio::endpoint> candidate;bool no_data=false;
                            for(auto type:{std::uint16_t{1},std::uint16_t{28}}) {
                                if(canceled_)co_return std::unexpected(Error::canceled);
                                auto now=Clock::now();if(now>=until)co_return std::unexpected(Error::timeout);
                                auto attempt_deadline=bootstrap_local ? std::min(until,now+std::chrono::seconds(bootstrap_local->config.timeout_seconds)) : until;
                                bootstrap_.emplace(context_,bootstrap_local ? bootstrap_local->config.use_tcp : upstreams_[current].tcp,false,
                                    std::nullopt,upstreams_[current].protection.get());
                                auto answer=co_await bootstrap_->resolve_random(endpoint,{name,type},attempt_deadline);bootstrap_.reset();
                                if(!answer) {
                                    last=answer.error();if(last==Error::canceled)co_return std::unexpected(last);
                                    if(last==Error::timeout && Clock::now()>=until)co_return std::unexpected(last);
                                    if(last==Error::no_data){no_data=true;continue;}
                                    if(last==Error::name_not_found && (!candidate.empty() || no_data))co_return std::unexpected(Error::protocol);
                                    if(last==Error::name_not_found || last==Error::transport || last==Error::timeout || last==Error::server_failure || last==Error::refused) {candidate.clear();break;}
                                    co_return std::unexpected(last);
                                }
                                if(canonical && *canonical!=answer->canonical_name)co_return std::unexpected(Error::protocol);
                                canonical=answer->canonical_name;
                                for(auto const& address:answer->addresses) {
                                    if(candidate.size()>=64)co_return std::unexpected(Error::limit);
                                    if(address.size==4){corosio::ipv4_address::bytes_type bytes{};std::copy_n(address.bytes.begin(),4,bytes.begin());candidate.emplace_back(corosio::ipv4_address(bytes),next.port);}
                                    else if(address.size==16)candidate.emplace_back(corosio::ipv6_address(address.bytes),next.port);
                                }
                            }
                            if(!candidate.empty()){resolved=std::move(candidate);break;}
                            if(last==Error::name_not_found || last==Error::no_data)break;
                        }
                        if(last==Error::name_not_found || last==Error::no_data)break;
                    }
                    if(resolved.empty() && last!=Error::name_not_found && last!=Error::no_data)break;
                }
                if(resolved.empty())co_return std::unexpected(last);
                endpoints=std::move(resolved);current=*it;bootstrap_local.reset();
            }
            if(endpoints.empty())co_return std::unexpected(Error::state);
            for(auto const& endpoint:endpoints) {
                if(canceled_)co_return std::unexpected(Error::canceled);
                wire=co_await exchange(endpoint,upstream_query,until,step_.server,upstream.tcp,step_.disable_cache,cache_snapshot);
                if(wire || wire.error()!=Error::transport)break;
            }
        }
        co_return wire;
    }

    auto EvaluatedMessageExchange::run() -> capy::task<std::expected<EvaluatedMessage,detail::ResolveError>> {
        auto wire=co_await exchange_.run();
        if(!wire)co_return std::unexpected(wire.error());
        auto view=response_ecs_view(exchange_.upstream_query());
        if(!view)co_return std::unexpected(detail::ResolveError::protocol);
        auto lease=default_message_race_result_budget().acquire(wire->capacity());
        if(!lease)co_return std::unexpected(detail::ResolveError::budget_exhausted);
        co_return EvaluatedMessage{std::move(*wire),*view,exchange_.local_synthetic(),std::move(lease),exchange_.stale_cache()};
    }
}
