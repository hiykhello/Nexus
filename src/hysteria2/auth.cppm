export module hysteria2.auth;
import std;
import http.header;

export namespace hysteria2 {
    inline constexpr std::size_t max_auth_fields=64,max_auth_bytes=16384,max_credential_bytes=4096;
    enum class AuthError { malformed,too_large,duplicate,not_auth,credentials,rate,udp,status,rejected };
    struct ClientAuthView { std::string_view credential; std::uint64_t receive_bps=0; }; // 0 means unknown.
    struct ServerAuth { bool udp=false,automatic=false; std::uint64_t receive_bps=0; }; // Non-auto 0 means unlimited.
    struct CongestionPolicy {
        std::uint64_t send_bps=0,receive_bps=0;
        bool ignore_client_bandwidth=false,disable_compensation=false;
    };
    // A zero result selects standard congestion control. The empty optional
    // represents the fixed server policy which refuses an unknown client rate.
    inline auto server_congestion(CongestionPolicy const& policy,std::uint64_t client_receive) noexcept -> std::optional<std::uint64_t> {
        if(policy.ignore_client_bandwidth && policy.receive_bps && !client_receive)return {};
        if((policy.ignore_client_bandwidth && !policy.receive_bps) || !client_receive)return 0;
        return policy.send_bps ? std::min(policy.send_bps,client_receive) : client_receive;
    }
    inline auto client_congestion(CongestionPolicy const& policy,ServerAuth const& server) noexcept -> std::uint64_t {
        if(server.automatic || !policy.send_bps)return 0;
        return server.receive_bps ? std::min(policy.send_bps,server.receive_bps) : policy.send_bps;
    }
    namespace auth_detail {
        enum class Role { request,response };
        struct Fields {
            std::optional<std::string_view> method,scheme,authority,path,status,host,credential,rate,udp,padding;
        };
        inline auto value_valid(std::string_view value) noexcept -> bool {
            return http::valid_header_field_value(value) && (value.empty() ||
                (value.front()!=' ' && value.front()!='\t' && value.back()!=' ' && value.back()!='\t'));
        }
        inline auto decimal(std::string_view value) noexcept -> std::optional<std::uint64_t> {
            if (value.empty() || !std::ranges::all_of(value,[](char c) { return c>='0' && c<='9'; })) return {};
            std::uint64_t result=0;
            auto [end,error]=std::from_chars(value.data(),value.data()+value.size(),result);
            if (error!=std::errc{} || end!=value.data()+value.size()) return {};
            return result;
        }
        inline auto inspect(std::span<http::HeaderField const> fields,Role role) noexcept -> std::expected<Fields,AuthError> {
            if (fields.size()>max_auth_fields) return std::unexpected(AuthError::too_large);
            Fields result;
            std::size_t bytes=0;
            bool ordinary=false;
            for (auto const& field:fields) {
                auto name=field.name,value=field.value;
                if (name.size()>max_auth_bytes-bytes || value.size()>max_auth_bytes-bytes-name.size()) return std::unexpected(AuthError::too_large);
                bytes+=name.size()+value.size();
                if (name.empty() || !value_valid(value)) return std::unexpected(AuthError::malformed);
                auto token=name.front()==':' ? name.substr(1) : name;
                if (token.empty() || !std::ranges::all_of(token,[](char c) { return http::header_token(c) && !(c>='A' && c<='Z'); }))
                    return std::unexpected(AuthError::malformed);
                std::optional<std::string_view>* destination=nullptr;
                if (name.front()==':') {
                    if (ordinary) return std::unexpected(AuthError::malformed);
                    if (role==Role::request) {
                        if (name==":method") destination=&result.method;
                        else if (name==":scheme") destination=&result.scheme;
                        else if (name==":authority") destination=&result.authority;
                        else if (name==":path") destination=&result.path;
                    } else if (name==":status") destination=&result.status;
                    if (!destination) return std::unexpected(AuthError::malformed);
                } else {
                    ordinary=true;
                    if (name=="connection" || name=="keep-alive" || name=="proxy-connection" || name=="transfer-encoding" || name=="upgrade" ||
                        (name=="te" && value!="trailers")) return std::unexpected(AuthError::malformed);
                    if (name=="hysteria-auth" && role==Role::request) destination=&result.credential;
                    else if (name=="hysteria-cc-rx") destination=&result.rate;
                    else if (name=="hysteria-udp" && role==Role::response) destination=&result.udp;
                    else if (name=="hysteria-padding") destination=&result.padding;
                    else if (name=="host" && role==Role::request) destination=&result.host;
                }
                if (destination) {
                    if (*destination) return std::unexpected(AuthError::duplicate);
                    *destination=value;
                }
            }
            return result;
        }
    }
    // HTTP/3 decoding owns the strings. Returned credentials borrow that
    // field section; no password copy, logging, QPACK or I/O occurs here.
    inline auto parse_client_auth(std::span<http::HeaderField const> fields) noexcept -> std::expected<ClientAuthView,AuthError> {
        auto parsed=auth_detail::inspect(fields,auth_detail::Role::request);
        if (!parsed) return std::unexpected(parsed.error());
        auto const& view=*parsed;
        if (!view.method || !view.scheme || !view.path || (!view.authority && !view.host)) return std::unexpected(AuthError::malformed);
        if (view.authority && view.host && *view.authority!=*view.host) return std::unexpected(AuthError::malformed);
        auto authority=view.authority ? *view.authority : *view.host;
        if (*view.method!="POST" || *view.scheme!="https" || authority!="hysteria" || *view.path!="/auth") return std::unexpected(AuthError::not_auth);
        if (!view.credential || view.credential->empty()) return std::unexpected(AuthError::credentials);
        if (view.credential->size()>max_credential_bytes) return std::unexpected(AuthError::too_large);
        auto rate=view.rate ? auth_detail::decimal(*view.rate) : std::nullopt;
        if (!rate) return std::unexpected(AuthError::rate);
        return ClientAuthView{*view.credential,*rate};
    }
    inline auto parse_server_auth(std::span<http::HeaderField const> fields) noexcept -> std::expected<ServerAuth,AuthError> {
        auto parsed=auth_detail::inspect(fields,auth_detail::Role::response);
        if (!parsed) return std::unexpected(parsed.error());
        auto const& view=*parsed;
        if (!view.status || view.status->size()!=3) return std::unexpected(AuthError::status);
        auto status=auth_detail::decimal(*view.status);
        if (!status || *status<100 || *status>599) return std::unexpected(AuthError::status);
        if (*status!=233) return std::unexpected(AuthError::rejected);
        if (!view.udp || (*view.udp!="true" && *view.udp!="false")) return std::unexpected(AuthError::udp);
        if (!view.rate) return std::unexpected(AuthError::rate);
        if (*view.rate=="auto") return ServerAuth{*view.udp=="true",true,0};
        auto rate=auth_detail::decimal(*view.rate);
        if (!rate) return std::unexpected(AuthError::rate);
        return ServerAuth{*view.udp=="true",false,*rate};
    }
    // Numeric storage is owned; credentials and optional padding continue to
    // borrow the supplied immutable profile. fields() builds fresh views, so
    // moving this value before obtaining the views does not leave self-pointers.
    class ClientAuthHeaders {
        std::string_view credential_,padding_;
        std::array<char,20> rate_{};
        std::size_t size_=0;
    public:
        static auto create(std::string_view credential,std::uint64_t rate,std::string_view padding={}) noexcept
            -> std::expected<ClientAuthHeaders,AuthError> {
            if (credential.empty() || !auth_detail::value_valid(credential)) return std::unexpected(AuthError::credentials);
            if (credential.size()>max_credential_bytes || padding.size()>max_auth_bytes/2) return std::unexpected(AuthError::too_large);
            if (!auth_detail::value_valid(padding)) return std::unexpected(AuthError::malformed);
            ClientAuthHeaders result;
            result.credential_=credential; result.padding_=padding;
            auto converted=std::to_chars(result.rate_.data(),result.rate_.data()+result.rate_.size(),rate);
            result.size_=static_cast<std::size_t>(converted.ptr-result.rate_.data());
            return result;
        }
        auto fields() const noexcept -> std::array<http::HeaderField,7> {
            return {{{":method","POST"},{":scheme","https"},{":authority","hysteria"},{":path","/auth"},
                {"hysteria-auth",credential_},{"hysteria-cc-rx",{rate_.data(),size_}},{"hysteria-padding",padding_}}};
        }
    };
    class ServerAuthHeaders {
        std::string_view padding_;
        std::array<char,20> rate_{};
        std::size_t size_=0;
        bool udp_=false,automatic_=false;
    public:
        static auto create(ServerAuth options,std::string_view padding={}) noexcept -> std::expected<ServerAuthHeaders,AuthError> {
            if (padding.size()>max_auth_bytes/2) return std::unexpected(AuthError::too_large);
            if (!auth_detail::value_valid(padding)) return std::unexpected(AuthError::malformed);
            ServerAuthHeaders result;
            result.udp_=options.udp; result.automatic_=options.automatic; result.padding_=padding;
            auto converted=std::to_chars(result.rate_.data(),result.rate_.data()+result.rate_.size(),options.receive_bps);
            result.size_=static_cast<std::size_t>(converted.ptr-result.rate_.data());
            return result;
        }
        auto fields() const noexcept -> std::array<http::HeaderField,4> {
            return {{{":status","233"},{"hysteria-udp",udp_ ? "true" : "false"},
                {"hysteria-cc-rx",automatic_ ? std::string_view{"auto"} : std::string_view{rate_.data(),size_}},{"hysteria-padding",padding_}}};
        }
    };
}

