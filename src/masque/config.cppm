export module masque.config;
import std;
import masque.bearer;
import masque.target;
import http.header;
import net.udp_socket;
import platform.ip_address;
import dns.address_sequence;
import ngtcp2;

export namespace masque {
    struct DestinationRule {
        net::UdpEndpoint network{};
        std::uint8_t prefix=0;
        std::uint16_t first_port=0,last_port=0;
        auto valid() const noexcept -> bool {
            auto size=network.family==4 ? 4u : network.family==6 ? 16u : 0u;
            if(!size || prefix>size*8 || !first_port || first_port>last_port || network.port ||
               (size==4 && std::ranges::any_of(std::span(network.address).subspan(4),[](auto b){return b!=0;})))return false;
            for(unsigned bit=prefix;bit<size*8;++bit)if(network.address[bit/8]&(0x80u>>(bit%8)))return false;
            // IPv4-mapped prefixes have ambiguous family semantics and are
            // rejected separately by UdpOwner before policy evaluation.
            return true;
        }
        auto matches(net::UdpEndpoint candidate) const noexcept -> bool {
            if(candidate.family!=network.family || candidate.port<first_port || candidate.port>last_port)return false;
            auto whole=prefix/8,remaining=prefix%8;
            if(!std::ranges::equal(std::span(network.address).first(whole),std::span(candidate.address).first(whole)))return false;
            return !remaining || ((network.address[whole]^candidate.address[whole]) & (0xffu<<(8-remaining)))==0;
        }
    };
    enum class HostConfigError { authority,credential,rules,timeout,memory };
    // Immutable owner configuration. Secrets are loaded by the caller using
    // the existing private-file boundary; an empty allowlist fails closed.
    struct HostConfig {
        std::string authority;
        BearerCredential credential;
        std::vector<DestinationRule> destinations;
        dns::detail::AddressStrategy family=dns::detail::AddressStrategy::prefer_ipv4;
        std::chrono::milliseconds dns_timeout{5000};
        std::size_t native_bytes=8*1024*1024;
        HostConfig(std::string name,BearerCredential secret,std::vector<DestinationRule> rules)
            :authority(std::move(name)),credential(std::move(secret)),destinations(std::move(rules)) {}
        auto valid(bool ip = false) const noexcept -> bool {
            if(authority.empty() || authority.size()>255 || (!ip && destinations.empty()) || destinations.size()>256 ||
               dns_timeout.count()<=0 || dns_timeout>std::chrono::minutes(1) || native_bytes<65536 || native_bytes>1024ull*1024*1024)return false;
            if(!std::ranges::all_of(authority,[](unsigned char c){return c>0x20 && c<0x7f && c!='/' && c!='?' && c!='#' && c!='@' && c!='\\';}))return false;
            return std::ranges::all_of(destinations,[](auto const& rule){return rule.valid();});
        }
    };
    class ConfigPolicy {
        HostConfig const& config_;
        void* wake_context_;
        void (*wake_)(void*) noexcept;
        void* cid_context_=nullptr;
        bool (*cid_add_)(void*,std::span<std::uint8_t const>) noexcept=nullptr;
        void (*cid_remove_)(void*,std::span<std::uint8_t const>) noexcept=nullptr;
    public:
        using Identity=std::size_t;
        ConfigPolicy(HostConfig const& config,void* context,void (*wake)(void*) noexcept) noexcept:config_(config),wake_context_(context),wake_(wake) {}
        auto authenticate(std::span<http::HeaderField const> fields) const noexcept -> std::optional<Identity> {
            return config_.credential.authenticate(fields) ? std::optional<Identity>{0} : std::nullopt;
        }
        auto allow(Identity,UdpTarget const&,net::UdpEndpoint endpoint) const noexcept -> bool {
            return std::ranges::any_of(config_.destinations,[&](auto const& rule){return rule.matches(endpoint);});
        }
        auto changed() noexcept -> void {wake_(wake_context_);}
        auto cid_callbacks(void* context,bool (*add)(void*,std::span<std::uint8_t const>) noexcept,
            void (*remove)(void*,std::span<std::uint8_t const>) noexcept) noexcept -> void {cid_context_=context;cid_add_=add;cid_remove_=remove;}
        auto add_connection_id(ngtcp2::ngtcp2_cid const& cid,ngtcp2::ngtcp2_stateless_reset_token const&) noexcept -> int {
            return cid_add_ && cid_add_(cid_context_,{cid.data,cid.datalen}) ? 0 : ngtcp2::err_callback_failure;
        }
        auto remove_connection_id(ngtcp2::ngtcp2_cid const& cid) noexcept -> int {
            if(cid_remove_)cid_remove_(cid_context_,{cid.data,cid.datalen});return 0;
        }
    };
}
