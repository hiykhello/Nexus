// Private CLI runtime outbound group health probe, failover & route publication helpers.
export module cli.proxy_group_health;
import std;
import cli.dns_transports;
export import cli.proxy_selector_state;
import cli.route_files;
import config;
import functional;
import relay;
import rules;
import socks5;

export namespace cli::run_detail {
    class OutboundGroupHealth {
        using Clock = std::chrono::steady_clock;
        struct Member {
            std::optional<std::size_t> outbound;
            std::uint32_t measurement = 0;
            std::uint16_t status_code = 0;
            Clock::time_point sampled{};
            std::optional<std::uint64_t> network_generation;
            std::uint32_t ewma_ms = 0;
            bool has_ewma = false;
            std::uint8_t consecutive_failures = 0;
            Clock::time_point breaker_until{};
        };
        struct InFlight {
            std::size_t member = 0;
            std::shared_ptr<relay::OutboundProbe> probe;
            std::optional<std::size_t> outbound;
            std::optional<std::uint64_t> network_generation;
        };
        struct Job {
            std::size_t group;
            std::string group_name;
            std::vector<std::string> member_names;
            socks5::Request target;
            std::string request;
            bool use_tls = false;
            std::string tls_server_name;
            std::vector<Member> members;
            std::optional<std::string> manual_override;
            std::vector<bool> last_healthy;
            Clock::time_point next = Clock::time_point::min();
            Clock::time_point last_activity = Clock::now();
            bool idle_paused = false;
        };
        std::vector<Job> jobs_;
        std::size_t cursor_ = 0, next_member_ = 0;
        std::vector<InFlight> inflight_;
        std::optional<std::uint64_t> network_generation_, round_network_generation_;

        auto find_job(std::size_t group) noexcept -> Job* {
            auto it = std::ranges::find(jobs_, group, &Job::group);
            return it == jobs_.end() ? nullptr : &*it;
        }
        auto find_job(std::size_t group) const noexcept -> Job const* {
            auto it = std::ranges::find(jobs_, group, &Job::group);
            return it == jobs_.end() ? nullptr : &*it;
        }
        auto find_job_by_name(std::string_view name) noexcept -> Job* {
            auto it = std::ranges::find(jobs_, name, &Job::group_name);
            return it == jobs_.end() ? nullptr : &*it;
        }
        auto reset_cursor(std::size_t next_cursor) noexcept -> void {
            inflight_.clear(); next_member_ = 0;
            cursor_ = jobs_.empty() ? 0 : (next_cursor % jobs_.size());
        }
        static auto diff_demoted(std::vector<bool> const& prev, std::vector<bool> const& next) -> std::vector<std::size_t> {
            std::vector<std::size_t> out;
            for (std::size_t k = 0; k < next.size(); ++k)
                if ((k >= prev.size() || prev[k]) && !next[k]) out.push_back(k);
            return out;
        }
        static auto apply_sample(Job& job, std::size_t m, std::optional<std::size_t> outbound,
            std::uint32_t measurement, std::uint16_t status, std::optional<std::uint64_t> net_gen,
            config::OutboundSelector const& group, Clock::time_point now) noexcept -> void {
            auto& prev = job.members[m];
            bool same_leaf = (prev.outbound == outbound && prev.network_generation == net_gen);
            Member next{outbound, measurement, status, now, net_gen};
            if (measurement > 1) {
                auto raw_ms = measurement - 2;
                next.ewma_ms = (same_leaf && prev.has_ewma) ? ((3u * raw_ms + 7u * prev.ewma_ms + 5u) / 10u) : raw_ms;
                next.has_ewma = true;
            } else {
                auto fails = static_cast<std::uint8_t>(std::min<unsigned>(255u, (same_leaf ? prev.consecutive_failures : 0u) + 1u));
                next.consecutive_failures = fails;
                next.ewma_ms = same_leaf ? prev.ewma_ms : 0u;
                next.has_ewma = same_leaf && prev.has_ewma;
                if (fails >= 3) {
                    auto cooldown = std::max<std::uint64_t>(static_cast<std::uint64_t>(group.probe.interval_ms) * 3u, 5000u);
                    next.breaker_until = now + std::chrono::milliseconds(cooldown);
                }
            }
            prev = next;
        }
    public:
        struct Selection {
            std::size_t group;
            std::string_view member;
            bool balance_changed = false;
            std::vector<std::size_t> demoted_members{};
        };
        struct Observation {
            std::optional<std::size_t> outbound;
            std::string_view state;
            std::optional<std::uint32_t> latency_ms, ewma_ms;
            std::optional<std::uint16_t> last_status;
            std::optional<std::chrono::milliseconds> age;
            std::uint8_t consecutive_failures = 0;
            bool breaker_open = false, probing = false;
        };

        [[nodiscard]] auto override_member(std::size_t group) const noexcept -> std::optional<std::string_view> {
            auto const* job = find_job(group);
            return (job && job->manual_override) ? std::optional<std::string_view>(*job->manual_override) : std::nullopt;
        }
        auto set_override(std::size_t group, std::string_view member) -> bool {
            auto* job = find_job(group);
            if (!job) return false;
            job->manual_override = std::string(member);
            return true;
        }
        auto clear_override(std::size_t group) -> bool {
            auto* job = find_job(group);
            if (!job) return false;
            job->manual_override.reset();
            job->next = Clock::now();
            return true;
        }
        [[nodiscard]] auto is_idle_paused(std::size_t group) const noexcept -> bool {
            auto const* job = find_job(group);
            return job && job->idle_paused;
        }
        auto note_group_activity(std::size_t group, Clock::time_point now = Clock::now()) noexcept -> void {
            if (auto* job = find_job(group)) {
                if (now > job->last_activity) job->last_activity = now;
                if (job->idle_paused) { job->idle_paused = false; job->next = std::min(job->next, now); }
            }
        }
        auto note_group_activity(std::string_view group_name, Clock::time_point now = Clock::now()) noexcept -> void {
            if (auto* job = find_job_by_name(group_name)) note_group_activity(job->group, now);
        }
        auto sync_activity(relay::GroupRuntimeHooks const& hooks) noexcept -> void {
            for (auto const& job : jobs_)
                if (auto ms = hooks.last_active_ms(job.group); ms > 0)
                    note_group_activity(job.group, Clock::time_point(std::chrono::milliseconds(ms)));
        }
        auto invalidate_network() noexcept -> void {
            auto now = Clock::now();
            inflight_.clear(); next_member_ = 0;
            for (auto& job : jobs_) {
                job.next = now; job.last_activity = now; job.idle_paused = false; job.last_healthy.clear();
                for (auto& m : job.members) { m.consecutive_failures = 0; m.breaker_until = {}; m.has_ewma = false; }
            }
        }
        auto trigger_probe(std::size_t group, Clock::time_point now = Clock::now()) noexcept -> bool {
            auto* job = find_job(group);
            if (!job) return false;
            job->next = now; job->last_activity = now; job->idle_paused = false;
            for (auto& m : job->members) { m.consecutive_failures = 0; m.breaker_until = {}; }
            return true;
        }
        [[nodiscard]] auto best_up_member(config::Config const& config, std::size_t index,
            std::optional<std::uint64_t> network_generation, Clock::time_point now = Clock::now()) const noexcept
            -> std::optional<std::string_view> {
            auto const* job = find_job(index);
            if (!job || index >= config.selectors.size()) return {};
            auto const& group = config.selectors[index];
            auto score = [&](std::size_t k) -> std::uint32_t {
                auto const& m = job->members[k];
                return m.has_ewma ? m.ewma_ms : (m.measurement > 1 ? m.measurement - 2 : 0xffffffffu);
            };
            std::optional<std::size_t> best;
            for (std::size_t k = 0; k < job->members.size() && k < group.members.size(); ++k) {
                auto const& s = job->members[k];
                if (s.measurement <= 1 || s.network_generation != network_generation ||
                    s.outbound != config::configured_outbound_index(config, group.members[k]) ||
                    now < s.breaker_until) continue;
                if (!best || score(k) < score(*best)) best = k;
                if (group.mode == config::OutboundGroupMode::fallback) break;
            }
            return best ? std::optional<std::string_view>(group.members[*best]) : std::nullopt;
        }

        // Instant dial-failure demotion & failover without waiting for the next probe interval.
        [[nodiscard]] auto record_dial_failure(config::Config const& config, std::string_view group_tag,
            std::string_view outbound_tag, std::optional<std::uint64_t> network_generation = {},
            Clock::time_point now = Clock::now()) -> std::optional<Selection> {
            auto* job = find_job_by_name(group_tag);
            if (!job || job->group >= config.selectors.size()) return {};
            auto const& group = config.selectors[job->group];
            if (group.mode == config::OutboundGroupMode::select || job->members.size() != group.members.size()) return {};
            std::optional<std::size_t> failed_idx;
            for (std::size_t k = 0; k < group.members.size(); ++k) {
                if (group.members[k] == outbound_tag || config::selected_outbound(config, group.members[k]) == outbound_tag) {
                    failed_idx = k; break;
                }
            }
            if (!failed_idx) return {};
            auto const m = *failed_idx;
            auto& entry = job->members[m];
            entry.outbound = config::configured_outbound_index(config, group.members[m]);
            entry.measurement = 1; entry.sampled = now; entry.network_generation = network_generation;
            entry.consecutive_failures = static_cast<std::uint8_t>(std::max<unsigned>(3u, entry.consecutive_failures + 1u));
            entry.breaker_until = now + std::chrono::milliseconds(std::max<std::uint64_t>(group.probe.interval_ms, 5000u));
            job->last_activity = now; job->idle_paused = false;
            job->next = std::min(job->next, now + std::chrono::milliseconds(std::min<std::uint32_t>(group.probe.interval_ms, 5000u)));

            if (group.mode == config::OutboundGroupMode::load_balance) {
                std::vector<bool> mask = job->last_healthy.size() == group.members.size()
                    ? job->last_healthy : std::vector<bool>(group.members.size(), true);
                mask[m] = false;
                if (std::ranges::none_of(mask, std::identity{}))
                    for (std::size_t k = 0; k < mask.size(); ++k) mask[k] = (mask.size() == 1 || k != m);
                if (mask == job->last_healthy) return {};
                auto demoted = diff_demoted(job->last_healthy, mask);
                job->last_healthy = std::move(mask);
                return Selection{job->group, group.selected, true, std::move(demoted)};
            }
            if ((job->manual_override && *job->manual_override != group.members[m]) || group.selected != group.members[m])
                return {};
            if (auto best = best_up_member(config, job->group, network_generation, now); best && *best != group.members[m])
                return Selection{job->group, *best, false};
            for (std::size_t k = 0; k < group.members.size(); ++k) {
                if (k == m) continue;
                auto cand_ob = config::configured_outbound_index(config, group.members[k]);
                auto const& s = job->members[k];
                if (!cand_ob || *cand_ob == 1 || now < s.breaker_until ||
                    (s.measurement == 1 && s.network_generation == network_generation)) continue;
                return Selection{job->group, group.members[k], false};
            }
            return {};
        }

        [[nodiscard]] auto record_dial_failure_by_index(config::Config const& config, std::string_view group_tag,
            std::size_t outbound_index, std::optional<std::uint64_t> network_generation = {},
            Clock::time_point now = Clock::now()) -> std::optional<Selection> {
            auto try_job = [&](Job const& job) -> std::optional<Selection> {
                if (job.group >= config.selectors.size()) return {};
                auto const& group = config.selectors[job.group];
                for (auto const& member : group.members)
                    if (config::configured_outbound_index(config, member) == outbound_index)
                        return record_dial_failure(config, group.name, member, network_generation, now);
                return {};
            };
            if (!group_tag.empty()) {
                auto const* job = find_job_by_name(group_tag);
                return job ? try_job(*job) : std::nullopt;
            }
            for (auto const& job : jobs_) if (auto sel = try_job(job)) return sel;
            return {};
        }

        [[nodiscard]] auto observe(config::Config const& config, std::size_t index, std::size_t member,
            std::optional<std::uint64_t> network_generation) const noexcept -> Observation {
            if (index >= config.selectors.size() || member >= config.selectors[index].members.size())
                return {.state = "not-probed"};
            auto const& name = config.selectors[index].members[member];
            auto outbound = config::configured_outbound_index(config, name);
            auto const* job = find_job(index);
            Observation result{.outbound = outbound, .state = "not-probed"};
            if (!job || member >= job->members.size()) return result;
            result.probing = cursor_ < jobs_.size() && job == &jobs_[cursor_] &&
                std::ranges::any_of(inflight_, [&](InFlight const& f) {
                    return f.member == member && f.outbound == outbound && f.network_generation == network_generation;
                });
            auto const& s = job->members[member];
            if (s.measurement == 0) result.state = "unknown";
            else if (s.outbound != outbound || s.network_generation != network_generation) result.state = "stale";
            else {
                auto now = Clock::now();
                result.state = s.measurement > 1 ? "up" : "down";
                if (s.measurement > 1) result.latency_ms = s.measurement - 2;
                if (s.has_ewma) result.ewma_ms = s.ewma_ms;
                if (s.status_code) result.last_status = s.status_code;
                result.consecutive_failures = s.consecutive_failures;
                result.breaker_open = now < s.breaker_until;
                result.age = std::chrono::duration_cast<std::chrono::milliseconds>(now - s.sampled);
            }
            return result;
        }
        [[nodiscard]] static auto create(config::Config const& config, Clock::time_point now = Clock::now())
            -> std::expected<OutboundGroupHealth, std::string> {
            OutboundGroupHealth health;
            for (std::size_t i = 0; i < config.selectors.size(); ++i) {
                auto const& group = config.selectors[i];
                if (group.mode != config::OutboundGroupMode::fallback && group.mode != config::OutboundGroupMode::url_test &&
                    (group.mode != config::OutboundGroupMode::load_balance || group.probe.url.empty())) continue;
                auto parsed = parse_probe_target(group.probe.url, group.probe.mode);
                if (!parsed) return std::unexpected(group.name + ": " + parsed.error());
                auto sni = group.probe.server_name.empty() ? std::move(parsed->host) : group.probe.server_name;
                health.jobs_.push_back({i, group.name, group.members, parsed->target, std::move(parsed->request),
                    parsed->use_tls, std::move(sni), std::vector<Member>(group.members.size()), {}, {},
                    Clock::time_point::min(), now, false});
            }
            return health;
        }

        [[nodiscard]] auto reconciled(config::Config const& next_config) const
            -> std::expected<OutboundGroupHealth, std::string> {
            auto next = create(next_config);
            if (!next) return next;
            next->network_generation_ = network_generation_;
            for (auto& dst : next->jobs_) {
                auto old = std::ranges::find(jobs_, dst.group_name, &Job::group_name);
                if (old == jobs_.end()) continue;
                dst.last_activity = old->last_activity; dst.idle_paused = old->idle_paused;
                if (old->manual_override && std::ranges::contains(dst.member_names, *old->manual_override))
                    dst.manual_override = old->manual_override;
                for (std::size_t k = 0; k < dst.member_names.size() && k < dst.members.size(); ++k) {
                    auto it = std::ranges::find(old->member_names, dst.member_names[k]);
                    if (it == old->member_names.end()) continue;
                    auto old_k = static_cast<std::size_t>(it - old->member_names.begin());
                    if (old_k < old->members.size() &&
                        old->members[old_k].outbound == config::configured_outbound_index(next_config, dst.member_names[k]))
                        dst.members[k] = old->members[old_k];
                }
            }
            return next;
        }

        // Concurrent per-group probing with idle-timeout pausing & EWMA/circuit-breaker scoring.
        [[nodiscard]] auto poll(functional::function_ref<bool(std::shared_ptr<relay::OutboundProbe>)> enqueue,
            config::Config const& config, std::optional<std::uint64_t> network_generation,
            Clock::time_point now = Clock::now()) -> std::optional<Selection> {
            if (jobs_.empty()) return {};
            if (network_generation_ != network_generation) {
                network_generation_ = network_generation;
                for (auto& entry : jobs_) { entry.next = now; entry.idle_paused = false; }
            }
            if (cursor_ >= jobs_.size()) reset_cursor(0);
            auto& job = jobs_[cursor_];
            if (job.group >= config.selectors.size() || job.members.size() != config.selectors[job.group].members.size()) {
                reset_cursor(cursor_ + 1);
                return {};
            }
            auto const& group = config.selectors[job.group];
            for (auto it = inflight_.begin(); it != inflight_.end();) {
                if (it->member >= job.members.size()) { it = inflight_.erase(it); continue; }
                auto measurement = it->probe->result.load(std::memory_order_acquire);
                if (!measurement) { ++it; continue; }
                apply_sample(job, it->member, it->outbound, measurement,
                    it->probe->status_code.load(std::memory_order_relaxed), it->network_generation, group, now);
                it = inflight_.erase(it);
            }
            if (next_member_ == 0 && inflight_.empty()) {
                if (group.probe.idle_timeout_ms > 0 &&
                    now >= job.last_activity + std::chrono::milliseconds(group.probe.idle_timeout_ms)) {
                    job.idle_paused = true; cursor_ = (cursor_ + 1) % jobs_.size(); return {};
                }
                if (now < job.next) { cursor_ = (cursor_ + 1) % jobs_.size(); return {}; }
                job.idle_paused = false;
                round_network_generation_ = network_generation;
            }
            std::size_t const max_conc = std::clamp<std::size_t>(group.probe.probe_concurrency, 1u, 1024u);
            while (inflight_.size() < max_conc && next_member_ < group.members.size()) {
                auto outbound = config::configured_outbound_index(config, group.members[next_member_]);
                if (!outbound || *outbound == 1) { job.members[next_member_++] = {outbound, 1, 0, now, network_generation}; continue; }
                auto matcher = rules::RouteMatcher::compile({}, *outbound, 2 + config.tunnel_count());
                if (!matcher) { job.members[next_member_++] = {outbound, 1, 0, now, network_generation}; continue; }
                auto probe = std::make_shared<relay::OutboundProbe>();
                probe->route = std::move(*matcher); probe->target = job.target; probe->request = job.request;
                probe->mode = group.probe.mode == config::OutboundProbeMode::h2_ping ?
                    relay::OutboundProbeMode::h2_ping : relay::OutboundProbeMode::http;
                for (auto const& r : group.probe.expected_status) probe->expected_status.push_back({r.low, r.high});
                probe->use_tls = job.use_tls; probe->tls_server_name = job.tls_server_name;
                probe->tls_ca_file = group.probe.ca_file;
                probe->deadline = now + std::chrono::milliseconds(group.probe.timeout_ms);
                if (!enqueue(probe)) break;
                inflight_.push_back({next_member_++, std::move(probe), outbound, network_generation});
            }
            if (!inflight_.empty() || next_member_ < group.members.size()) return {};

            auto current = static_cast<std::size_t>(std::ranges::find(group.members, group.selected) - group.members.begin());
            auto valid = [&](std::size_t k) {
                auto const& s = job.members[k];
                return s.measurement > 1 && s.network_generation == network_generation &&
                    s.outbound == config::configured_outbound_index(config, group.members[k]) && now >= s.breaker_until;
            };
            auto score = [&](std::size_t k) -> std::uint32_t {
                auto const& s = job.members[k];
                return s.has_ewma ? s.ewma_ms : (s.measurement > 1 ? s.measurement - 2 : 0xffffffffu);
            };
            std::optional<std::size_t> best;
            std::vector<bool> mask(job.members.size(), true);
            bool any_up = false;
            for (std::size_t k = 0; k < job.members.size(); ++k) {
                bool up = valid(k); mask[k] = up; any_up |= up;
                if (!up) continue;
                if (!best || score(k) < score(*best)) best = k;
                if (group.mode == config::OutboundGroupMode::fallback) break;
            }
            next_member_ = 0; cursor_ = (cursor_ + 1) % jobs_.size();
            job.next = round_network_generation_ == network_generation ? now + std::chrono::milliseconds(group.probe.interval_ms) : now;
            if (group.mode == config::OutboundGroupMode::load_balance) {
                if (!any_up) std::fill(mask.begin(), mask.end(), true);
                bool changed = (mask != job.last_healthy);
                auto demoted = changed ? diff_demoted(job.last_healthy, mask) : std::vector<std::size_t>{};
                job.last_healthy = std::move(mask);
                if (round_network_generation_ == network_generation && changed)
                    return Selection{job.group, group.selected, true, std::move(demoted)};
                return {};
            }
            if (round_network_generation_ != network_generation || job.manual_override || !best || *best == current) return {};
            if (group.mode == config::OutboundGroupMode::url_test && current < job.members.size() &&
                valid(current) && score(*best) + group.probe.tolerance_ms >= score(current)) return {};
            return Selection{job.group, group.members[*best]};
        }

        template<class Dist>
        [[nodiscard]] auto filter_distribution(config::Config const& config, Dist distribution) const -> Dist {
            if constexpr (!requires { distribution->groups; distribution->physical_count; }) { (void)config; return distribution; }
            else {
                if (!distribution || jobs_.empty()) return distribution;
                std::shared_ptr<std::remove_const_t<typename Dist::element_type>> copy;
                for (auto const& job : jobs_) {
                    if (job.group >= config.selectors.size() || job.last_healthy.empty()) continue;
                    auto const& sel = config.selectors[job.group];
                    if (sel.mode != config::OutboundGroupMode::load_balance || job.group >= distribution->groups.size()) continue;
                    auto const& orig = distribution->groups[job.group];
                    if (orig.size() != job.last_healthy.size()) continue;
                    std::vector<std::size_t> filtered;
                    filtered.reserve(orig.size());
                    for (std::size_t k = 0; k < orig.size(); ++k) if (job.last_healthy[k]) filtered.push_back(orig[k]);
                    if (filtered.empty()) filtered = orig;
                    if (filtered != orig) {
                        if (!copy) copy = std::make_shared<std::remove_const_t<typename Dist::element_type>>(*distribution);
                        copy->groups[job.group] = std::move(filtered);
                    }
                }
                return copy ? Dist(std::move(copy)) : distribution;
            }
        }
    };

    inline auto publish_group_routes(auto const& listeners, relay::RouteSnapshots& snapshots,
        config::Config const& config, RouteFiles const& files, bool replace_dns_policy = false,
        std::optional<functional::function_ref<std::expected<void, std::string>()>> before_publish = {},
        OutboundGroupHealth const* health = nullptr)
        -> std::expected<void, std::string> {
        auto routes = project_routes(config, files);
        if (health) routes.distribution = health->filter_distribution(config, std::move(routes.distribution));
        auto next = std::make_shared<std::vector<relay::RouteSnapshot>>();
        next->reserve(listeners.size());
        auto active = snapshots.load(std::memory_order_acquire);
        auto generation = active && !active->empty() ? active->front().generation + 1 : 1;
        auto dns = config.dns && active && !active->empty() ? active->front().dns : nullptr;
        auto dns_runtime = active && !active->empty() ? active->front().dns_runtime : nullptr;
        bool dns_disabled = active && !active->empty() && active->front().dns_disabled;
        auto previous = active && !active->empty() ? active->front().dns_transports : nullptr;
        auto transports = prepare_dns_transport_snapshot(config, generation, previous, replace_dns_policy);
        if (!transports) return std::unexpected(std::move(transports.error()));
        if (config.dns && (!dns || replace_dns_policy || *transports != previous)) {
            auto view = config.dns->fakeip && config.dns->fakeip->unified ? durable_fakeip_view(config) : generation;
            dns = std::make_shared<relay::DnsRuleSnapshot>(config.dns->rules, view);
        }
        auto group_tags = build_group_tag_map(config);
        for (std::size_t index = 0; index < listeners.size(); ++index) {
            auto candidate = listeners[index].server->compile_route_snapshot(routes.indexed, routes.default_outbound,
                config.inbounds[index].name, routes.program(config), routes.distribution);
            if (!candidate) return std::unexpected(std::move(candidate.error()));
            candidate->dns = dns; candidate->dns_transports = *transports; candidate->dns_runtime = dns_runtime;
            candidate->dns_disabled = dns_disabled; candidate->group_tags = group_tags; candidate->generation = generation;
            next->push_back(std::move(*candidate));
        }
        if (before_publish) if (auto ready = (*before_publish)(); !ready) return ready;
        snapshots.store(std::move(next), std::memory_order_release);
        return {};
    }

    inline auto apply_group_health_selection(auto const& listeners, relay::RouteSnapshots& snapshots,
        config::Config& running, RouteFiles const& files, OutboundGroupHealth const& health,
        OutboundGroupHealth::Selection const& picked) -> std::expected<void, std::string> {
        if (picked.balance_changed) {
            auto ok = publish_group_routes(listeners, snapshots, running, files, false, {}, &health);
            if (ok) (void)interrupt_balance_demoted(listeners, running, picked.group, picked.demoted_members);
            return ok;
        }
        auto prev = running;
        auto requested = running;
        requested.selectors[picked.group].selected = picked.member;
        auto next = config::reselect_outbounds(running, requested);
        if (!next) return std::unexpected(std::move(next.error()));
        auto ok = publish_group_routes(listeners, snapshots, *next, files, false, {}, &health);
        if (ok) { running = std::move(*next); (void)interrupt_group_sessions(listeners, prev, running, picked.group); }
        return ok;
    }
}
