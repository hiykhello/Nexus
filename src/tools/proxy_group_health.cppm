// Private CLI runtime outbound group health probe & route publication helpers.
export module cli.proxy_group_health;
import std;
import cli.dns_transports;
import cli.route_files;
import config;
import functional;
import http.connect;
import relay;
import rules;
import socks5;
import state.core;

export namespace cli::run_detail {
    struct ParsedProbeTarget {
        socks5::Request target;
        std::string request;
        bool use_tls = false;
        std::string host;
    };

    inline auto parse_probe_target(std::string_view url, config::OutboundProbeMode = config::OutboundProbeMode::http)
        -> std::expected<ParsedProbeTarget, std::string> {
        bool use_tls = url.starts_with("https://");
        if (url.size() > 2048 || (!use_tls && !url.starts_with("http://")) ||
            std::ranges::any_of(url, [](unsigned char c) {
                return c <= 0x20 || c >= 0x7f || c == '#' || c == '\\';
            })) return std::unexpected("invalid outbound probe URL");
        url.remove_prefix(use_tls ? 8 : 7);
        auto separator = url.find_first_of("/?");
        auto authority = url.substr(0, separator);
        if (authority.empty() || authority.contains('@')) return std::unexpected("invalid outbound probe authority");
        auto dial = std::string(authority);
        if (!authority.contains(':') || authority.ends_with(']')) dial += use_tls ? ":443" : ":80";
        auto parsed = http::parse_destination_authority(dial);
        if (parsed.status != http::ConnectStatus::accepted) return std::unexpected("invalid outbound probe address");

        socks5::Request request;
        request.status = socks5::Status::accepted;
        request.port = parsed.port;
        std::string host_name;
        if (parsed.kind == http::HostKind::domain) {
            request.address_type = 3;
            request.address_length = static_cast<std::uint8_t>(parsed.host.size());
            std::ranges::copy(parsed.host, request.address.begin());
            host_name = std::string(parsed.host);
        } else {
            request.address_type = parsed.kind == http::HostKind::ipv4 ? 1 : 4;
            request.address_length = parsed.kind == http::HostKind::ipv4 ? 4 : 16;
            std::ranges::copy(parsed.address, request.address.begin());
            auto end = authority.starts_with('[') ? authority.find(']') : authority.rfind(':');
            host_name = authority.starts_with('[') && end != authority.npos ?
                std::string(authority.substr(1, end - 1)) :
                std::string(end != authority.npos ? authority.substr(0, end) : authority);
        }
        auto path = separator == url.npos ? std::string_view("/") : url.substr(separator);
        auto wire = "HEAD " + std::string(path.starts_with('/') ? "" : "/") + std::string(path) +
            " HTTP/1.1\r\nHost: " + std::string(authority) + "\r\nConnection: close\r\n\r\n";
        return ParsedProbeTarget{request, std::move(wire), use_tls, std::move(host_name)};
    }

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
        };
        std::vector<Job> jobs_;
        std::size_t cursor_ = 0, member_ = 0;
        std::shared_ptr<relay::OutboundProbe> pending_;
        std::optional<std::size_t> pending_outbound_;
        std::optional<std::uint64_t> network_generation_, round_network_generation_, pending_network_generation_;

        static auto target(std::string_view url, config::OutboundProbeMode mode)
            -> std::expected<ParsedProbeTarget, std::string> {
            return parse_probe_target(url, mode);
        }

        auto find_job(std::size_t group) noexcept -> Job* {
            auto it = std::ranges::find(jobs_, group, &Job::group);
            return it == jobs_.end() ? nullptr : &*it;
        }
        auto find_job(std::size_t group) const noexcept -> Job const* {
            auto it = std::ranges::find(jobs_, group, &Job::group);
            return it == jobs_.end() ? nullptr : &*it;
        }
    public:
        struct Selection { std::size_t group; std::string_view member; bool balance_changed = false; };
        struct Observation {
            std::optional<std::size_t> outbound;
            std::string_view state;
            std::optional<std::uint32_t> latency_ms;
            std::optional<std::uint32_t> ewma_ms;
            std::optional<std::uint16_t> last_status;
            std::optional<std::chrono::milliseconds> age;
            std::uint8_t consecutive_failures = 0;
            bool breaker_open = false;
            bool probing = false;
        };

        [[nodiscard]] auto override_member(std::size_t group) const noexcept -> std::optional<std::string_view> {
            auto const* job = find_job(group);
            if (!job || !job->manual_override) return {};
            return *job->manual_override;
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
        auto invalidate_network() noexcept -> void {
            auto now = Clock::now();
            for (auto& job : jobs_) {
                job.next = now;
                job.last_healthy.clear();
                for (auto& m : job.members) {
                    m.consecutive_failures = 0;
                    m.breaker_until = {};
                    m.has_ewma = false;
                }
            }
        }
        auto trigger_probe(std::size_t group) noexcept -> bool {
            auto* job = find_job(group);
            if (!job) return false;
            job->next = Clock::now();
            for (auto& m : job->members) {
                m.consecutive_failures = 0;
                m.breaker_until = {};
            }
            return true;
        }
        [[nodiscard]] auto best_up_member(config::Config const& config, std::size_t index,
            std::optional<std::uint64_t> network_generation) const noexcept -> std::optional<std::string_view> {
            auto const* job = find_job(index);
            if (!job || index >= config.selectors.size()) return {};
            auto const& group = config.selectors[index];
            auto now = Clock::now();
            auto score = [&](std::size_t k) -> std::uint32_t {
                auto const& m = job->members[k];
                return m.has_ewma ? m.ewma_ms : (m.measurement > 1 ? m.measurement - 2 : 0xffffffffu);
            };
            std::optional<std::size_t> best;
            for (std::size_t k = 0; k < job->members.size() && k < group.members.size(); ++k) {
                auto const& sample = job->members[k];
                if (sample.measurement <= 1 || sample.network_generation != network_generation ||
                    sample.outbound != config::configured_outbound_index(config, group.members[k]) ||
                    now < sample.breaker_until) continue;
                if (!best || score(k) < score(*best)) best = k;
                if (group.mode == config::OutboundGroupMode::fallback) break;
            }
            if (!best) return {};
            return group.members[*best];
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
            result.probing = pending_ && cursor_ < jobs_.size() && job == &jobs_[cursor_] &&
                member == member_ && pending_outbound_ == outbound && pending_network_generation_ == network_generation;
            auto const& sample = job->members[member];
            if (sample.measurement == 0) result.state = "unknown";
            else if (sample.outbound != outbound || sample.network_generation != network_generation) result.state = "stale";
            else {
                auto now = Clock::now();
                result.state = sample.measurement > 1 ? "up" : "down";
                if (sample.measurement > 1) result.latency_ms = sample.measurement - 2;
                if (sample.has_ewma) result.ewma_ms = sample.ewma_ms;
                if (sample.status_code) result.last_status = sample.status_code;
                result.consecutive_failures = sample.consecutive_failures;
                result.breaker_open = now < sample.breaker_until;
                result.age = std::chrono::duration_cast<std::chrono::milliseconds>(now - sample.sampled);
            }
            return result;
        }
        [[nodiscard]] static auto create(config::Config const& config) -> std::expected<OutboundGroupHealth, std::string> {
            OutboundGroupHealth health;
            for (std::size_t i = 0; i < config.selectors.size(); ++i) {
                auto const& group = config.selectors[i];
                if (group.mode != config::OutboundGroupMode::fallback && group.mode != config::OutboundGroupMode::url_test &&
                    (group.mode != config::OutboundGroupMode::load_balance || group.probe.url.empty())) continue;
                auto parsed = target(group.probe.url, group.probe.mode);
                if (!parsed) return std::unexpected(group.name + ": " + parsed.error());
                auto sni = group.probe.server_name.empty() ? std::move(parsed->host) : group.probe.server_name;
                health.jobs_.push_back({i, group.name, group.members, parsed->target, std::move(parsed->request),
                    parsed->use_tls, std::move(sni), std::vector<Member>(group.members.size())});
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
                if (old->manual_override && std::ranges::contains(dst.member_names, *old->manual_override))
                    dst.manual_override = old->manual_override;
                for (std::size_t k = 0; k < dst.member_names.size() && k < dst.members.size(); ++k) {
                    auto it = std::ranges::find(old->member_names, dst.member_names[k]);
                    if (it == old->member_names.end()) continue;
                    auto old_k = static_cast<std::size_t>(it - old->member_names.begin());
                    if (old_k >= old->members.size()) continue;
                    auto next_ob = config::configured_outbound_index(next_config, dst.member_names[k]);
                    if (old->members[old_k].outbound == next_ob) dst.members[k] = old->members[old_k];
                }
            }
            return next;
        }

        // A round measures the effective physical leaf of each named member.
        // A concurrent config change invalidates a sample only for the changed leaf.
        [[nodiscard]] auto poll(functional::function_ref<bool(std::shared_ptr<relay::OutboundProbe>)> enqueue,
            config::Config const& config, std::optional<std::uint64_t> network_generation) -> std::optional<Selection> {
            if (jobs_.empty()) return {};
            auto now = Clock::now();
            if (network_generation_ != network_generation) {
                network_generation_ = network_generation;
                for (auto& entry : jobs_) entry.next = now;
            }
            if (cursor_ >= jobs_.size()) { cursor_ = 0; member_ = 0; pending_.reset(); pending_outbound_.reset(); }
            auto& job = jobs_[cursor_];
            if (job.group >= config.selectors.size() || job.members.size() != config.selectors[job.group].members.size()) {
                pending_.reset();
                pending_outbound_.reset();
                member_ = 0;
                cursor_ = (cursor_ + 1) % jobs_.size();
                return {};
            }
            auto const& group = config.selectors[job.group];
            if (pending_) {
                if (member_ >= job.members.size()) {
                    pending_.reset();
                    pending_outbound_.reset();
                    member_ = 0;
                    return {};
                }
                auto measurement = pending_->result.load(std::memory_order_acquire);
                if (!measurement) return {};
                auto status = pending_->status_code.load(std::memory_order_relaxed);
                auto& prev = job.members[member_];
                bool same_leaf = (prev.outbound == pending_outbound_ && prev.network_generation == pending_network_generation_);
                Member next_member{pending_outbound_, measurement, status, now, pending_network_generation_};
                if (measurement > 1) {
                    auto raw_ms = measurement - 2;
                    next_member.ewma_ms = (same_leaf && prev.has_ewma) ? ((3u * raw_ms + 7u * prev.ewma_ms + 5u) / 10u) : raw_ms;
                    next_member.has_ewma = true;
                    next_member.consecutive_failures = 0;
                    next_member.breaker_until = {};
                } else {
                    auto fails = static_cast<std::uint8_t>(std::min<unsigned>(255u, (same_leaf ? prev.consecutive_failures : 0u) + 1u));
                    next_member.consecutive_failures = fails;
                    next_member.ewma_ms = same_leaf ? prev.ewma_ms : 0u;
                    next_member.has_ewma = same_leaf && prev.has_ewma;
                    if (fails >= 3) {
                        auto cooldown = std::max<std::uint64_t>(static_cast<std::uint64_t>(group.probe.interval_ms) * 3u, 5000u);
                        next_member.breaker_until = now + std::chrono::milliseconds(cooldown);
                    }
                }
                prev = next_member;
                ++member_;
                pending_.reset();
                pending_outbound_.reset();
            }
            if (member_ == 0 && now < job.next) {
                cursor_ = (cursor_ + 1) % jobs_.size();
                return {};
            }
            if (!member_) round_network_generation_ = network_generation;
            while (member_ < group.members.size()) {
                auto outbound = config::configured_outbound_index(config, group.members[member_]);
                if (!outbound || *outbound == 1) {
                    job.members[member_++] = {outbound, 1, 0, now, network_generation};
                    continue;
                }
                auto matcher = rules::RouteMatcher::compile({}, *outbound, 2 + config.tunnel_count());
                if (!matcher) {
                    job.members[member_++] = {outbound, 1, 0, now, network_generation};
                    continue;
                }
                auto probe = std::make_shared<relay::OutboundProbe>();
                probe->route = std::move(*matcher);
                probe->target = job.target;
                probe->request = job.request;
                probe->mode = group.probe.mode == config::OutboundProbeMode::h2_ping ?
                    relay::OutboundProbeMode::h2_ping : relay::OutboundProbeMode::http;
                for (auto const& r : group.probe.expected_status)
                    probe->expected_status.push_back({r.low, r.high});
                probe->use_tls = job.use_tls;
                probe->tls_server_name = job.tls_server_name;
                probe->tls_ca_file = group.probe.ca_file;
                probe->deadline = now + std::chrono::milliseconds(group.probe.timeout_ms);
                if (enqueue(probe)) {
                    pending_ = std::move(probe);
                    pending_outbound_ = outbound;
                    pending_network_generation_ = network_generation;
                }
                return {};
            }
            auto current = std::ranges::find(group.members, group.selected) - group.members.begin();
            auto valid = [&](std::size_t k) {
                auto const& sample = job.members[k];
                return sample.measurement > 1 && sample.network_generation == network_generation &&
                    sample.outbound == config::configured_outbound_index(config, group.members[k]) &&
                    now >= sample.breaker_until;
            };
            auto score = [&](std::size_t k) -> std::uint32_t {
                auto const& sample = job.members[k];
                return sample.has_ewma ? sample.ewma_ms : (sample.measurement > 1 ? sample.measurement - 2 : 0xffffffffu);
            };
            std::optional<std::size_t> best;
            std::vector<bool> mask(job.members.size(), true);
            bool any_up = false;
            for (std::size_t k = 0; k < job.members.size(); ++k) {
                bool up = valid(k);
                mask[k] = up;
                any_up |= up;
                if (!up) continue;
                if (!best || score(k) < score(*best)) best = k;
                if (group.mode == config::OutboundGroupMode::fallback) break;
            }
            if (group.mode == config::OutboundGroupMode::load_balance) {
                if (!any_up) std::fill(mask.begin(), mask.end(), true);
                bool changed = (mask != job.last_healthy);
                job.last_healthy = std::move(mask);
                member_ = 0;
                cursor_ = (cursor_ + 1) % jobs_.size();
                job.next = round_network_generation_ == network_generation ?
                    now + std::chrono::milliseconds(group.probe.interval_ms) : now;
                if (round_network_generation_ == network_generation && changed)
                    return Selection{job.group, group.selected, true};
                return {};
            }
            member_ = 0;
            cursor_ = (cursor_ + 1) % jobs_.size();
            job.next = round_network_generation_ == network_generation ?
                now + std::chrono::milliseconds(group.probe.interval_ms) : now;
            if (round_network_generation_ != network_generation) return {};
            if (job.manual_override) return {};
            if (!best || *best == static_cast<std::size_t>(current)) return {};
            if (group.mode == config::OutboundGroupMode::url_test && static_cast<std::size_t>(current) < job.members.size() &&
                valid(static_cast<std::size_t>(current)) &&
                score(*best) + group.probe.tolerance_ms >= score(static_cast<std::size_t>(current))) return {};
            return Selection{job.group, group.members[*best]};
        }

        template<class Dist>
        [[nodiscard]] auto filter_distribution(config::Config const& config, Dist distribution) const -> Dist {
            if constexpr (!requires { distribution->groups; distribution->physical_count; }) {
                (void)config;
                return distribution;
            } else {
                if (!distribution || jobs_.empty()) return distribution;
                std::shared_ptr<std::remove_const_t<typename Dist::element_type>> copy;
                for (auto const& job : jobs_) {
                    if (job.group >= config.selectors.size() || job.last_healthy.empty()) continue;
                    auto const& selector = config.selectors[job.group];
                    if (selector.mode != config::OutboundGroupMode::load_balance ||
                        job.group >= distribution->groups.size()) continue;
                    auto const& orig = distribution->groups[job.group];
                    if (orig.size() != job.last_healthy.size()) continue;
                    std::vector<std::size_t> filtered;
                    filtered.reserve(orig.size());
                    for (std::size_t k = 0; k < orig.size(); ++k)
                        if (job.last_healthy[k]) filtered.push_back(orig[k]);
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

    inline auto durable_fakeip_view(config::Config const& config) -> std::uint64_t {
        auto const& routing = *config.dns;
        auto material = routing.message_cache_policy + routing.cache_rule_fingerprints;
        for (auto const& group : config.selectors) {
            material.push_back('\0');
            material += group.selected;
            material.push_back('\0');
            material += group.selected_leaf;
        }
        auto digest = ::state::fingerprint(std::as_bytes(std::span(material)));
        std::uint64_t view = 0;
        for (auto byte : std::span(digest).first<8>()) view = (view << 8) | std::to_integer<unsigned>(byte);
        return view;
    }

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
        for (std::size_t index = 0; index < listeners.size(); ++index) {
            auto candidate = listeners[index].server->compile_route_snapshot(routes.indexed, routes.default_outbound,
                config.inbounds[index].name, routes.program(config), routes.distribution);
            if (!candidate) return std::unexpected(std::move(candidate.error()));
            candidate->dns = dns;
            candidate->dns_transports = *transports;
            candidate->dns_runtime = dns_runtime;
            candidate->dns_disabled = dns_disabled;
            candidate->generation = generation;
            next->push_back(std::move(*candidate));
        }
        if (before_publish) {
            auto ready = (*before_publish)();
            if (!ready) return ready;
        }
        snapshots.store(std::move(next), std::memory_order_release);
        return {};
    }
}
