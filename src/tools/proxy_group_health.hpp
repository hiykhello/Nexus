// Private CLI runtime. Probe results cross the worker boundary through the ticket.
#pragma once
namespace cli::run_detail {
    class OutboundGroupHealth {
        using Clock=std::chrono::steady_clock;
        struct Member {
            std::optional<std::size_t> outbound;
            std::uint32_t measurement=0;
            std::uint16_t status_code=0;
            Clock::time_point sampled{};
            std::optional<std::uint64_t> network_generation;
            std::uint32_t ewma_ms=0;
            bool has_ewma=false;
            std::uint8_t consecutive_failures=0;
            Clock::time_point breaker_until{};
        };
        struct Job {
            std::size_t group;
            socks5::Request target;
            std::string request;
            bool use_tls=false;
            std::string tls_server_name;
            std::vector<Member> members;
            std::optional<std::string> manual_override;
            Clock::time_point next=Clock::time_point::min();
        };
        std::vector<Job> jobs_;
        std::size_t cursor_=0,member_=0;
        std::shared_ptr<proxy::OutboundProbe> pending_;
        std::optional<std::size_t> pending_outbound_;
        std::optional<std::uint64_t> network_generation_,round_network_generation_,pending_network_generation_;

        struct ParsedProbeTarget {
            socks5::Request target;
            std::string request;
            bool use_tls=false;
            std::string host;
        };

        static auto target(std::string_view url,config::OutboundProbeMode mode)
            -> std::expected<ParsedProbeTarget,std::string> {
            bool use_tls=url.starts_with("https://");
            if ((!use_tls && !url.starts_with("http://")) ||
                (use_tls && mode!=config::OutboundProbeMode::h2_ping) ||
                std::ranges::any_of(url,[](unsigned char c) {
                    return c<=0x20 || c>=0x7f || c=='#' || c=='\\';
                })) return std::unexpected("invalid outbound probe URL");
            url.remove_prefix(use_tls ? 8 : 7);
            auto separator=url.find_first_of("/?");
            auto authority=url.substr(0,separator);
            if (authority.empty() || authority.contains('@')) return std::unexpected("invalid outbound probe authority");
            auto dial=std::string(authority);
            if (!authority.contains(':') || authority.ends_with(']')) dial+=use_tls ? ":443" : ":80";
            auto parsed=http::parse_destination_authority(dial);
            if (parsed.status!=http::ConnectStatus::accepted) return std::unexpected("invalid outbound probe address");

            socks5::Request request;
            request.status=socks5::Status::accepted;
            request.port=parsed.port;
            std::string host_name;
            if (parsed.kind==http::HostKind::domain) {
                request.address_type=3;
                request.address_length=static_cast<std::uint8_t>(parsed.host.size());
                std::ranges::copy(parsed.host,request.address.begin());
                host_name=std::string(parsed.host);
            } else {
                request.address_type=parsed.kind==http::HostKind::ipv4 ? 1 : 4;
                request.address_length=parsed.kind==http::HostKind::ipv4 ? 4 : 16;
                std::ranges::copy(parsed.address,request.address.begin());
                auto end=authority.starts_with('[') ? authority.find(']') : authority.rfind(':');
                host_name=authority.starts_with('[') && end!=authority.npos ?
                    std::string(authority.substr(1,end-1)) :
                    std::string(end!=authority.npos ? authority.substr(0,end) : authority);
            }
            auto path=separator==url.npos ? std::string_view("/") : url.substr(separator);
            auto wire="HEAD "+std::string(path.starts_with('/') ? "" : "/")+std::string(path)+
                " HTTP/1.1\r\nHost: "+std::string(authority)+"\r\nConnection: close\r\n\r\n";
            return ParsedProbeTarget{request,std::move(wire),use_tls,std::move(host_name)};
        }

        auto find_job(std::size_t group) noexcept -> Job* {
            auto it=std::ranges::find(jobs_,group,&Job::group);
            return it==jobs_.end() ? nullptr : &*it;
        }
        auto find_job(std::size_t group) const noexcept -> Job const* {
            auto it=std::ranges::find(jobs_,group,&Job::group);
            return it==jobs_.end() ? nullptr : &*it;
        }
    public:
        struct Selection { std::size_t group; std::string_view member; };
        struct Observation {
            std::optional<std::size_t> outbound;
            std::string_view state;
            std::optional<std::uint32_t> latency_ms;
            std::optional<std::uint32_t> ewma_ms;
            std::optional<std::uint16_t> last_status;
            std::optional<std::chrono::milliseconds> age;
            std::uint8_t consecutive_failures=0;
            bool breaker_open=false;
            bool probing=false;
        };

        [[nodiscard]] auto override_member(std::size_t group) const noexcept -> std::optional<std::string_view> {
            auto const* job=find_job(group);
            if (!job || !job->manual_override) return {};
            return *job->manual_override;
        }
        auto set_override(std::size_t group,std::string_view member) -> bool {
            auto* job=find_job(group);
            if (!job) return false;
            job->manual_override=std::string(member);
            return true;
        }
        auto clear_override(std::size_t group) -> bool {
            auto* job=find_job(group);
            if (!job) return false;
            job->manual_override.reset();
            job->next=Clock::now();
            return true;
        }
        auto invalidate_network() noexcept -> void {
            auto now=Clock::now();
            for (auto& job : jobs_) {
                job.next=now;
                for (auto& m : job.members) {
                    m.consecutive_failures=0;
                    m.breaker_until={};
                    m.has_ewma=false;
                }
            }
        }
        auto trigger_probe(std::size_t group) noexcept -> bool {
            auto* job=find_job(group);
            if (!job) return false;
            job->next=Clock::now();
            for (auto& m : job->members) {
                m.consecutive_failures=0;
                m.breaker_until={};
            }
            return true;
        }
        [[nodiscard]] auto best_up_member(config::Config const& config,std::size_t index,
            std::optional<std::uint64_t> network_generation) const noexcept -> std::optional<std::string_view> {
            auto const* job=find_job(index);
            if (!job) return {};
            auto const& group=config.selectors[index];
            auto now=Clock::now();
            auto score=[&](std::size_t k) -> std::uint32_t {
                auto const& m=job->members[k];
                return m.has_ewma ? m.ewma_ms : (m.measurement>1 ? m.measurement-2 : 0xffffffffu);
            };
            std::optional<std::size_t> best;
            for (std::size_t k=0;k<job->members.size() && k<group.members.size();++k) {
                auto const& sample=job->members[k];
                if (sample.measurement<=1 || sample.network_generation!=network_generation ||
                    sample.outbound!=config::configured_outbound_index(config,group.members[k]) ||
                    now<sample.breaker_until) continue;
                if (!best || score(k)<score(*best)) best=k;
                if (group.mode==config::OutboundGroupMode::fallback) break;
            }
            if (!best) return {};
            return group.members[*best];
        }

        [[nodiscard]] auto observe(config::Config const& config,std::size_t index,std::size_t member,
            std::optional<std::uint64_t> network_generation) const noexcept -> Observation {
            auto const& name=config.selectors[index].members[member];
            auto outbound=config::configured_outbound_index(config,name);
            auto const* job=find_job(index);
            Observation result{.outbound=outbound,.state="not-probed"};
            if (!job) return result;
            result.probing=pending_ && job==&jobs_[cursor_] &&
                member==member_ && pending_outbound_==outbound && pending_network_generation_==network_generation;
            auto const& sample=job->members[member];
            if (sample.measurement==0) result.state="unknown";
            else if (sample.outbound!=outbound || sample.network_generation!=network_generation) result.state="stale";
            else {
                auto now=Clock::now();
                result.state=sample.measurement>1 ? "up" : "down";
                if (sample.measurement>1) result.latency_ms=sample.measurement-2;
                if (sample.has_ewma) result.ewma_ms=sample.ewma_ms;
                if (sample.status_code) result.last_status=sample.status_code;
                result.consecutive_failures=sample.consecutive_failures;
                result.breaker_open=now<sample.breaker_until;
                result.age=std::chrono::duration_cast<std::chrono::milliseconds>(now-sample.sampled);
            }
            return result;
        }
        [[nodiscard]] static auto create(config::Config const& config) -> std::expected<OutboundGroupHealth,std::string> {
            OutboundGroupHealth health;
            for (std::size_t i=0;i<config.selectors.size();++i) {
                auto const& group=config.selectors[i];
                if (group.mode!=config::OutboundGroupMode::fallback && group.mode!=config::OutboundGroupMode::url_test) continue;
                auto parsed=target(group.probe.url,group.probe.mode);
                if (!parsed) return std::unexpected(group.name+": "+parsed.error());
                auto sni=group.probe.server_name.empty() ? std::move(parsed->host) : group.probe.server_name;
                health.jobs_.push_back({i,parsed->target,std::move(parsed->request),parsed->use_tls,
                    std::move(sni),std::vector<Member>(group.members.size())});
            }
            return health;
        }

        // A round measures the effective physical leaf of each named member.
        // A concurrent config change invalidates a sample only for the changed leaf.
        [[nodiscard]] auto poll(nexus::function_ref<bool(std::shared_ptr<proxy::OutboundProbe>)> enqueue,
            config::Config const& config,std::optional<std::uint64_t> network_generation) -> std::optional<Selection> {
            if (jobs_.empty()) return {};
            auto now=Clock::now();
            if (network_generation_!=network_generation) {
                network_generation_=network_generation;
                for (auto& entry : jobs_) entry.next=now;
            }
            auto& job=jobs_[cursor_];
            auto const& group=config.selectors[job.group];
            if (pending_) {
                auto measurement=pending_->result.load(std::memory_order_acquire);
                if (!measurement) return {};
                auto status=pending_->status_code.load(std::memory_order_relaxed);
                auto& prev=job.members[member_];
                bool same_leaf=(prev.outbound==pending_outbound_ && prev.network_generation==pending_network_generation_);
                Member next_member{pending_outbound_,measurement,status,now,pending_network_generation_};
                if (measurement>1) {
                    auto raw_ms=measurement-2;
                    next_member.ewma_ms=(same_leaf && prev.has_ewma) ? ((3u*raw_ms+7u*prev.ewma_ms+5u)/10u) : raw_ms;
                    next_member.has_ewma=true;
                    next_member.consecutive_failures=0;
                    next_member.breaker_until={};
                } else {
                    auto fails=static_cast<std::uint8_t>(std::min<unsigned>(255u,(same_leaf ? prev.consecutive_failures : 0u)+1u));
                    next_member.consecutive_failures=fails;
                    next_member.ewma_ms=same_leaf ? prev.ewma_ms : 0u;
                    next_member.has_ewma=same_leaf && prev.has_ewma;
                    if (fails>=3) {
                        auto cooldown=std::max<std::uint64_t>(static_cast<std::uint64_t>(group.probe.interval_ms)*3u,5000u);
                        next_member.breaker_until=now+std::chrono::milliseconds(cooldown);
                    }
                }
                prev=next_member;
                ++member_;
                pending_.reset();
                pending_outbound_.reset();
            }
            if (member_==0 && now<job.next) {
                cursor_=(cursor_+1)%jobs_.size();
                return {};
            }
            if (!member_) round_network_generation_=network_generation;
            while (member_<group.members.size()) {
                auto outbound=config::configured_outbound_index(config,group.members[member_]);
                if (!outbound || *outbound==1) {
                    job.members[member_++]={outbound,1,0,now,network_generation};
                    continue;
                }
                auto matcher=rules::RouteMatcher::compile({},*outbound,2+config.tunnel_count());
                if (!matcher) {
                    job.members[member_++]={outbound,1,0,now,network_generation};
                    continue;
                }
                auto probe=std::make_shared<proxy::OutboundProbe>();
                probe->route=std::move(*matcher);
                probe->target=job.target;
                probe->request=job.request;
                probe->mode=group.probe.mode==config::OutboundProbeMode::h2_ping ?
                    proxy::OutboundProbeMode::h2_ping : proxy::OutboundProbeMode::http;
                for (auto const& r : group.probe.expected_status)
                    probe->expected_status.push_back({r.low,r.high});
                probe->use_tls=job.use_tls;
                probe->tls_server_name=job.tls_server_name;
                probe->tls_ca_file=group.probe.ca_file;
                probe->deadline=now+std::chrono::milliseconds(group.probe.timeout_ms);
                if (enqueue(probe)) {
                    pending_=std::move(probe);
                    pending_outbound_=outbound;
                    pending_network_generation_=network_generation;
                }
                return {};
            }
            auto current=std::ranges::find(group.members,group.selected)-group.members.begin();
            auto valid=[&](std::size_t k) {
                auto const& sample=job.members[k];
                return sample.measurement>1 && sample.network_generation==network_generation &&
                    sample.outbound==config::configured_outbound_index(config,group.members[k]) &&
                    now>=sample.breaker_until;
            };
            auto score=[&](std::size_t k) -> std::uint32_t {
                auto const& sample=job.members[k];
                return sample.has_ewma ? sample.ewma_ms : (sample.measurement>1 ? sample.measurement-2 : 0xffffffffu);
            };
            std::optional<std::size_t> best;
            for (std::size_t k=0;k<job.members.size();++k) {
                if (!valid(k)) continue;
                if (!best || score(k)<score(*best)) best=k;
                if (group.mode==config::OutboundGroupMode::fallback) break;
            }
            member_=0;
            cursor_=(cursor_+1)%jobs_.size();
            job.next=round_network_generation_==network_generation ?
                now+std::chrono::milliseconds(group.probe.interval_ms) : now;
            if (round_network_generation_!=network_generation) return {};
            if (job.manual_override) return {};
            if (!best || *best==static_cast<std::size_t>(current)) return {};
            if (group.mode==config::OutboundGroupMode::url_test && valid(static_cast<std::size_t>(current)) &&
                score(*best)+group.probe.tolerance_ms>=score(static_cast<std::size_t>(current))) return {};
            return Selection{job.group,group.members[*best]};
        }
    };
    auto durable_fakeip_view(config::Config const& config) -> std::uint64_t {
        auto const& routing=*config.dns;
        auto material=routing.message_cache_policy+routing.cache_rule_fingerprints;
        for (auto const& group:config.selectors) {
            material.push_back('\0');
            material+=group.selected;
            material.push_back('\0');
            material+=group.selected_leaf;
        }
        auto digest=::state::fingerprint(std::as_bytes(std::span(material)));
        std::uint64_t view=0;
        for (auto byte:std::span(digest).first<8>()) view=(view<<8)|std::to_integer<unsigned>(byte);
        return view;
    }

    auto publish_group_routes(auto const& listeners,proxy::RouteSnapshots& snapshots,
        config::Config const& config,RouteFiles const& files,bool replace_dns_policy=false,
        std::optional<nexus::function_ref<std::expected<void,std::string>()>> before_publish={})
        -> std::expected<void,std::string> {
        auto routes=project_routes(config,files);
        auto next=std::make_shared<std::vector<proxy::RouteSnapshot>>();
        next->reserve(listeners.size());
        auto active=snapshots.load(std::memory_order_acquire);
        auto generation=active && !active->empty() ? active->front().generation+1 : 1;
        auto dns=config.dns && active && !active->empty() ? active->front().dns : nullptr;
        auto previous=active && !active->empty() ? active->front().dns_transports : nullptr;
        auto transports=prepare_dns_transport_snapshot(config,generation,previous,replace_dns_policy);
        if (!transports) return std::unexpected(std::move(transports.error()));
        if (config.dns && (!dns || replace_dns_policy || *transports!=previous)) {
            auto view=config.dns->fakeip && config.dns->fakeip->unified ? durable_fakeip_view(config) : generation;
            dns=std::make_shared<proxy::DnsRuleSnapshot>(config.dns->rules,view);
        }
        for(std::size_t index=0;index<listeners.size();++index) {
            auto candidate=listeners[index].server->compile_route_snapshot(routes.indexed,routes.default_outbound,
                config.inbounds[index].name,routes.program(config),routes.distribution);
            if(!candidate)return std::unexpected(std::move(candidate.error()));
            candidate->dns=dns;
            candidate->dns_transports=*transports;
            candidate->generation=generation;
            next->push_back(std::move(*candidate));
        }
        if (before_publish) {
            auto ready=(*before_publish)();
            if (!ready) return ready;
        }
        snapshots.store(std::move(next),std::memory_order_release);
        return {};
    }

}
