import cli.proxy_run;
import cli.hy2_enabled;
import cli.hy2_disabled;
import cli.masque_enabled;
import cli.masque_disabled;
import cli.tuic_enabled;
import cli.tuic_disabled;
import cli.tun_enabled;
import cli.tun_disabled;
namespace cli {
#ifdef NEXUS_ENABLE_MASQUE
using SelectedMasqueRuntime=masque_enabled::Runtime;
#else
using SelectedMasqueRuntime=masque_disabled::Runtime;
#endif
#ifdef NEXUS_ENABLE_HY2
using SelectedHy2Runtime=hy2_enabled::Runtime;
#else
using SelectedHy2Runtime=hy2_disabled::Runtime;
#endif
#ifdef NEXUS_ENABLE_TUIC
using SelectedTuicRuntime=tuic_enabled::Runtime;
#else
using SelectedTuicRuntime=tuic_disabled::Runtime;
#endif
#ifdef NEXUS_ENABLE_TUN
using SelectedTunRuntime=tun_enabled::Runtime;
#else
using SelectedTunRuntime=tun_disabled::Runtime;
#endif
}
import std;
import config;
import cli.dns_transports;
import rules;
import rules.rule_input;
import crypto;
import proxy;
import proxy.principal_limits;
import shadowsocks.key;
import shadowsocks.identity;
import ss_udp.shared_coordinator;
import ss_udp.ordered_sender;

namespace cli {
    class ShadowsocksUdpRuntime {
        std::shared_ptr<shadowsocks::detail::UdpListenerIngress> ingress_;
        std::uint64_t generation_=0;
        std::optional<proxy::DnsRouting> dns_;
        struct SecretKey {
            std::array<std::uint8_t,32> bytes{};
            ~SecretKey() { crypto::cleanse(bytes); }
        };
        struct ListenerKeys {
            SecretKey primary;
            struct User {std::string name; SecretKey secret;};
            std::vector<User> users;
        };
        std::vector<std::unique_ptr<ListenerKeys>> keys_;
        std::unique_ptr<proxy::Server> routing_;
        std::optional<proxy::udp_runtime::CoordinatorUdpInbounds> inbounds_;
        bool routing_active_=false;
    public:
        ~ShadowsocksUdpRuntime() {stop();}
        auto stage_admission(ShadowsocksUdpRuntime const* previous,std::uint64_t generation) -> void {
            ingress_=previous && previous->ingress_ ? previous->ingress_ :
                std::make_shared<shadowsocks::detail::UdpListenerIngress>();
            generation_=generation;
        }
        auto publish_admission() noexcept -> void {
            if (ingress_) ingress_->publish(generation_);
        }
        [[nodiscard]] auto has_listeners() const noexcept -> bool {return inbounds_.has_value();}
        [[nodiscard]] auto idle() const noexcept -> bool {return !inbounds_ || inbounds_->idle();}
        auto resize(std::size_t count,bool has_shadowsocks) -> void;
        auto remember(std::size_t index,std::span<std::uint8_t const> bytes,std::span<proxy::ShadowsocksUserKey const> users) -> void;
        [[nodiscard]] auto configure(config::Config const&,std::span<std::string const>,std::span<std::size_t const>,
            std::span<rules::ProgramRule const>,proxy::Server*,std::span<proxy::Server* const>,std::span<DnsProtection const>) -> std::expected<void,std::string>;
        [[nodiscard]] auto bind_shared_dns(proxy::SharedDnsGeneration&,std::size_t,std::size_t) -> bool;
        [[nodiscard]] auto start() -> std::expected<void,std::string>;
        [[nodiscard]] auto healthy() const noexcept -> bool;
        [[nodiscard]] auto failed() const noexcept -> bool;
        [[nodiscard]] auto wait(std::chrono::milliseconds) const noexcept -> std::chrono::milliseconds;
        auto poll() -> void;
        auto stop() noexcept -> void;
    };
    auto ShadowsocksUdpRuntime::resize(std::size_t count,bool has_shadowsocks) -> void {
        if (has_shadowsocks) keys_.resize(count);
    }
    auto ShadowsocksUdpRuntime::remember(std::size_t index,std::span<std::uint8_t const> bytes,
        std::span<proxy::ShadowsocksUserKey const> users) -> void {
        auto keys=std::make_unique<ListenerKeys>();
        std::ranges::copy(bytes,keys->primary.bytes.begin());
        keys->users.reserve(users.size());
        for (auto const& user:users) {
            auto& entry=keys->users.emplace_back();
            entry.name=user.name;
            std::ranges::copy(user.key,entry.secret.bytes.begin());
        }
        keys_[index]=std::move(keys);
    }
    auto ShadowsocksUdpRuntime::configure(config::Config const& config,std::span<std::string const> rules_data,
                               std::span<std::size_t const> rule_data_index,std::span<rules::ProgramRule const> ordered_rules,
                               proxy::Server* parent,std::span<proxy::Server* const> traffic,std::span<DnsProtection const> protection) -> std::expected<void,std::string> {
        if(config.ordered_tcp && !config.ordered_tcp->udp) {decltype(keys_){}.swap(keys_);return {};}
        if (!std::ranges::any_of(config.inbounds,[](auto const& item) { return item.shadowsocks.has_value(); })) {
            return {};
        }
        if (!ingress_ && std::ranges::any_of(keys_,[](auto const& keys) {return keys && !keys->users.empty();}))
            stage_admission(nullptr,1);
        std::vector<rules::RouteRule> routes;
        for (std::size_t i=0;i<config.routes.size();++i) {
            auto const& route=config.routes[i];
            auto const& bytes=rules_data[rule_data_index[i]];
            auto format=route.file.format==config::RuleFormat::kdl ? rules::InputFormat::kdl : route.file.format==config::RuleFormat::beve ? rules::InputFormat::beve : rules::InputFormat::srs;
            auto parsed=rules::parse_rule_input(bytes,format,route.file.ip_cidr_match_source);
            if (!parsed) { return std::unexpected("UDP routing: "+parsed.error().message); }
            routes.push_back({std::move(*parsed),route.outbound});
        }
        auto native_outbound=std::ranges::any_of(config.shadowsocks_outbounds,[](auto const& entry) {return entry.config.udp_native;});
        if (config.ordered_tcp || native_outbound || uses_proxy_dns(config.dns)) {
            if (!parent) return std::unexpected("UDP routing parent is unavailable");
            routing_=std::make_unique<proxy::Server>(proxy::RoutingOnly{});
            routing_->inherit_routing(*parent,0,1);
            inbounds_.emplace(routing_->executor_context());
        } else inbounds_.emplace();
        if (config.ordered_tcp || native_outbound) {
            std::shared_ptr<rules::RouteProgram const> policy;
            if (config.ordered_tcp) {
                auto program=rules::RouteProgram::compile(ordered_rules,2+config.tunnel_count());
                if (!program) {return std::unexpected("UDP routing: "+program.error().message);}
                policy=std::make_shared<rules::RouteProgram const>(std::move(*program));
            }
            auto* ordered=config.ordered_tcp ? &*config.ordered_tcp : nullptr;
            if (!inbounds_->set_ordered(proxy::udp_runtime::make_ordered_udp_sender(*routing_,std::move(policy),
                config.default_outbound,ordered && ordered->skip_unknown,
                std::chrono::milliseconds(ordered ? ordered->sniff_timeout_ms : 200))))
                return std::unexpected("cannot configure ordered UDP routing");
        }
        if (ingress_) inbounds_->set_ingress(*ingress_,generation_);
        if (!inbounds_->set_socket_binding(config.direct_tcp_options.binding))
            return std::unexpected("cannot configure UDP socket binding");
        dns_=proxy::udp_runtime::udp_dns_config(config);
        for (std::size_t index=0;index<protection.size();++index)
            dns_->servers[index].protection=protection[index];
        for (std::size_t i=0;i<config.inbounds.size();++i) {
            auto const& entry=config.inbounds[i];
            if (!entry.shadowsocks) continue;
            auto policy=rules::RouteMatcher::compile(routes,config.default_outbound,
                2+config.tunnel_count(),
                rules::SourceMetadata::provided,entry.name,rules::AuthMetadata::provided);
            if (!policy) { return std::unexpected("UDP routing: "+policy.error().message); }
            auto size=entry.shadowsocks->method=="2022-blake3-aes-128-gcm" ? 16U : 32U;
            auto method=entry.shadowsocks->method=="2022-blake3-chacha20-poly1305" ?
                shadowsocks::CipherMethod::chacha20 : shadowsocks::CipherMethod::aes;
            auto const& keys=*keys_[i];
            auto primary=std::span(keys.primary.bytes).first(size);
            auto* traffic_listener=traffic.empty() ? nullptr : traffic[i];
            if (keys.users.empty()) {
                auto added=inbounds_->add(primary,entry.port,*policy,traffic_listener,method);
                if (!added) { return std::unexpected("shadowsocks UDP: "+added.error()); }
                continue;
            }
            auto identity=std::make_shared<shadowsocks::detail::UdpIdentitySecret const>(primary);
            auto* principals=traffic_listener ? traffic_listener->principal_policy() : nullptr;
            for (auto const& user:keys.users) {
                auto key=std::span(user.secret.bytes).first(size);
                auto added=inbounds_->add(key,entry.port,*policy,traffic_listener,method,
                    shadowsocks::detail::UdpIdentityRoute{identity,shadowsocks::identity_hash(key),user.name,
                        principals ? principals->find(user.name) : nullptr});
                if (!added) { return std::unexpected("shadowsocks UDP: "+added.error()); }
            }
        }
        decltype(keys_){}.swap(keys_);
        return {};
    }
    auto ShadowsocksUdpRuntime::bind_shared_dns(proxy::SharedDnsGeneration& generation,std::size_t group,std::size_t reader) -> bool {
        if (!inbounds_) return true;
        if (routing_ && !routing_->bind_shared_dns(generation,group,reader+1)) return false;
        auto& setup=inbounds_->setup();
#ifdef NEXUS_DNS_RESPONSE
        if (::policy::dns_has_response_program(dns_->rules)) {
            auto* cache=generation.ensure_response_cache();
            if (!cache || !setup.bind_response_cache(*cache)) return false;
        }
#endif
        return setup.bind(generation.cache(),group,reader) &&
            setup.bind_coordinator(generation.coordinator(),generation.registry(),*dns_,dns_->optimistic_cache_seconds!=0,std::chrono::seconds(30)) &&
            setup.bind_local(generation.local_registry());
    }
    auto ShadowsocksUdpRuntime::start() -> std::expected<void,std::string> {
        if(routing_) {
            auto prepared=routing_->prepare_routing(1);
            if(!prepared){routing_->stop(); return std::unexpected("UDP routing setup: "+prepared.error().message());}
            auto activated=routing_->activate_context();
            if(!activated){routing_->stop(); return std::unexpected("UDP routing setup: "+activated.error().message());}
            routing_active_=true;
        }
        if (inbounds_) if (auto error=inbounds_->start(*dns_)) {
            stop(); return std::unexpected("cannot listen for SS-2022 UDP: "+error.message());
        }
        return {};
    }
    auto ShadowsocksUdpRuntime::healthy() const noexcept -> bool { return !inbounds_ || inbounds_->healthy(); }
    auto ShadowsocksUdpRuntime::failed() const noexcept -> bool { return !healthy(); }
    auto ShadowsocksUdpRuntime::wait(std::chrono::milliseconds value) const noexcept -> std::chrono::milliseconds {
        return inbounds_ ? std::min(value,std::chrono::milliseconds(5)) : value;
    }
    auto ShadowsocksUdpRuntime::poll() -> void { if (inbounds_) inbounds_->poll(std::chrono::milliseconds(1)); }
    auto ShadowsocksUdpRuntime::stop() noexcept -> void {
        if (inbounds_) inbounds_->stop();
        if (routing_active_) {routing_->stop();routing_active_=false;}
    }
}

auto nexus_run(int argc, char** argv) -> int {
    return nexus_run_proxy<cli::ShadowsocksUdpRuntime,cli::SelectedHy2Runtime,cli::SelectedMasqueRuntime,cli::SelectedTuicRuntime,cli::SelectedTunRuntime>(argc,argv);
}
