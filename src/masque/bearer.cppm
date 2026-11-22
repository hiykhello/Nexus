export module masque.bearer;
import std;
import crypto;
import http.header;
import masque.target;
import net.udp_socket;

export namespace masque {
    // Immutable bearer credential. The caller loads it through an existing
    // private-file mechanism. This type never logs or copies request values.
    class BearerCredential {
        crypto::Bytes bytes_;
        explicit BearerCredential(crypto::Bytes&& bytes):bytes_(std::move(bytes)) {}
        static auto token_char(unsigned char c) noexcept -> bool {
            return (c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') || c=='-' || c=='.' || c=='_' || c=='~' || c=='+' || c=='/';
        }
        static auto valid_token(std::span<std::uint8_t const> token) noexcept -> bool {
            bool padding=false,base=false;
            for(auto c:token) {
                if(c=='=')padding=true;
                else {if(padding || !token_char(c))return false;base=true;}
            }
            return base;
        }
    public:
        BearerCredential(BearerCredential const&)=delete;
        auto operator=(BearerCredential const&) -> BearerCredential& = delete;
        BearerCredential(BearerCredential&& other) noexcept:bytes_(std::move(other.bytes_)) {}
        auto operator=(BearerCredential&& other) noexcept -> BearerCredential& {
            if(this!=&other){crypto::cleanse(bytes_);bytes_=std::move(other.bytes_);}return *this;
        }
        ~BearerCredential(){crypto::cleanse(bytes_);}
        static auto create(std::span<std::uint8_t const> value) -> std::optional<BearerCredential> {
            if(value.empty() || value.size()>4096 || !valid_token(value))return {};
            return BearerCredential(crypto::Bytes(value.begin(),value.end()));
        }
        auto authenticate(std::span<http::HeaderField const> headers) const noexcept -> bool {
            std::string_view value;bool seen=false;
            for(auto const& field:headers)if(field.name=="proxy-authorization") {if(seen)return false;seen=true;value=field.value;}
            if(!seen || value.size()<8)return false;
            constexpr std::string_view scheme="bearer";
            for(std::size_t i=0;i<scheme.size();++i) {
                auto c=static_cast<unsigned char>(value[i]);if(c>='A' && c<='Z')c+=('a'-'A');if(c!=scheme[i])return false;
            }
            auto position=scheme.size();if(value[position]!=' ')return false;
            while(position<value.size() && value[position]==' ')++position;
            auto token=value.substr(position);
            auto wire=std::span(reinterpret_cast<std::uint8_t const*>(token.data()),token.size());
            if(!valid_token(wire))return false;
            return crypto::constant_time_equal(bytes_,wire);
        }
    };
    // The destination policy must independently authorize each resolved IP;
    // a credential alone never grants access to arbitrary destinations.
    template<class TargetPolicy> class BearerPolicy {
        BearerCredential credential_;TargetPolicy& target_;
    public:
        using Identity=std::size_t;
        BearerPolicy(BearerCredential credential,TargetPolicy& target):credential_(std::move(credential)),target_(target) {}
        auto authenticate(std::span<http::HeaderField const> headers) const noexcept -> std::optional<Identity> {
            return credential_.authenticate(headers) ? std::optional<Identity>{0} : std::nullopt;
        }
        auto allow(Identity,UdpTarget const& target,net::UdpEndpoint endpoint) -> bool {return target_.allow(target,endpoint);}
        auto changed() noexcept -> void {static_assert(noexcept(target_.changed()));target_.changed();}
    };
}
