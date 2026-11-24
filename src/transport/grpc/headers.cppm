export module grpc.headers;
import std;
import http.header;

export namespace grpc {
    struct FieldView { std::string_view name,value; };
    enum class HeaderStatus { accepted,malformed,too_large,method,path,content_type,encoding,status,ended };
    enum class ResponsePolicy { standard,sing_box_lite };
    namespace header_detail {
        inline auto fields(std::span<FieldView const> values) noexcept -> HeaderStatus {
            if (values.size()>100) return HeaderStatus::too_large;
            std::size_t bytes=0;
            for (auto [name,value]:values) {
                if (name.size()>8192-bytes || value.size()>8192-bytes-name.size() || 32>8192-bytes-name.size()-value.size()) return HeaderStatus::too_large;
                bytes+=name.size()+value.size()+32;
                auto token=name.starts_with(':') ? name.substr(1) : name;
                if (token.empty() || !std::ranges::all_of(token,[](char c) { return http::header_token(c) && !(c>='A' && c<='Z'); }) ||
                    !http::valid_header_field_value(value)) return HeaderStatus::malformed;
                if (name=="connection" || name=="upgrade" || name=="keep-alive" || name=="proxy-connection" || name=="transfer-encoding") return HeaderStatus::malformed;
            }
            return HeaderStatus::accepted;
        }
        inline auto content_type(std::string_view type) noexcept -> bool {
            type=http::trim_header_ows(type.substr(0,type.find(';')));
            return type=="application/grpc" || type=="application/grpc+proto";
        }
        inline auto unsigned_value(std::string_view value,std::uint32_t& number) noexcept -> bool {
            auto [end,error]=std::from_chars(value.data(),value.data()+value.size(),number);
            return !value.empty() && (value.size()==1 || value.front()!='0') && error==std::errc{} && end==value.data()+value.size();
        }
    }
    inline auto parse_timeout(std::string_view text) noexcept -> std::optional<std::chrono::nanoseconds> {
        if (text.size()<2 || text.size()>9) return {};
        auto digits=text.substr(0,text.size()-1);
        std::uint64_t value=0;
        auto [end,error]=std::from_chars(digits.data(),digits.data()+digits.size(),value);
        if (error!=std::errc{} || end!=digits.data()+digits.size()) return {};
        std::uint64_t scale;
        switch (text.back()) {
        case 'H': scale=3600000000000; break;
        case 'M': scale=60000000000; break;
        case 'S': scale=1000000000; break;
        case 'm': scale=1000000; break;
        case 'u': scale=1000; break;
        case 'n': scale=1; break;
        default: return {};
        }
        auto max=static_cast<std::uint64_t>(std::chrono::nanoseconds::max().count());
        return std::chrono::nanoseconds(value>max/scale ? max : value*scale);
    }
    class RequestProfile {
        std::string authority_,path_,scheme_;
    public:
        static auto create(std::string_view service,std::string_view authority,bool secure)
            -> std::expected<RequestProfile,HeaderStatus> {
            if (service.size()>255 || !std::ranges::all_of(service,[](char c) {
                return (c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') || c=='_' || c=='-' || c=='.'; })) return std::unexpected(HeaderStatus::path);
            if (authority.empty() || authority.size()>512 || std::ranges::any_of(authority,[](unsigned char c) {
                return c<33 || c>126 || std::string_view("/?#@\\").contains(char(c)); })) return std::unexpected(HeaderStatus::malformed);
            RequestProfile result; result.authority_=authority; result.path_="/"; result.path_.append(service); result.path_.append("/Tun");
            result.scheme_=secure ? "https" : "http"; return result;
        }
        auto path() const noexcept -> std::string_view { return path_; }
        auto authority() const noexcept -> std::string_view { return authority_; }
        auto scheme() const noexcept -> std::string_view { return scheme_; }
        auto request_fields() const noexcept -> std::array<FieldView,7> {
            return {{{":method","POST"},{":scheme",scheme_},{":path",path_},{":authority",authority_},
                {"content-type","application/grpc"},{"te","trailers"},{"grpc-accept-encoding","identity"}}};
        }
    };
    struct RequestHeaders { HeaderStatus status=HeaderStatus::malformed; std::optional<std::chrono::nanoseconds> timeout; };
    inline auto parse_request_headers(std::span<FieldView const> fields,RequestProfile const& profile) noexcept -> RequestHeaders {
        auto checked=header_detail::fields(fields);
        if (checked!=HeaderStatus::accepted) return {checked};
        bool method=false,path=false,scheme=false,authority=false,type=false,te=false,encoding=false,timeout=false;
        std::optional<std::chrono::nanoseconds> budget;
        for (auto [name,value]:fields) {
            if (name==":method") { if (method || value!="POST") return {HeaderStatus::method}; method=true; }
            else if (name==":path") { if (path || value!=profile.path()) return {HeaderStatus::path}; path=true; }
            else if (name==":scheme") {
                bool ok = value==profile.scheme() || (profile.scheme()=="https" && value=="http");
                if (scheme || !ok) return {HeaderStatus::malformed};
                scheme=true;
            }
            else if (name==":authority") { if (authority || value!=profile.authority()) return {HeaderStatus::malformed}; authority=true; }
            else if (name=="content-type") { if (type || !header_detail::content_type(value)) return {HeaderStatus::content_type}; type=true; }
            else if (name=="te") { if (te || value!="trailers") return {HeaderStatus::malformed}; te=true; }
            else if (name=="grpc-encoding") { if (encoding || value!="identity") return {HeaderStatus::encoding}; encoding=true; }
            else if (name=="grpc-timeout") { if (timeout || !(budget=parse_timeout(value))) return {HeaderStatus::malformed}; timeout=true; }
            else if (name=="grpc-status" || name.starts_with(':')) return {HeaderStatus::malformed};
        }
        return {method && path && scheme && authority && type ? HeaderStatus::accepted : HeaderStatus::malformed,budget};
    }
    inline auto response_fields() noexcept -> std::array<FieldView,2> {
        return {{{":status","200"},{"content-type","application/grpc"}}};
    }
    inline auto success_trailers() noexcept -> std::array<FieldView,1> { return {{{"grpc-status","0"}}}; }
    // HTTP2 signals END_STREAM separately from message framing. Standard
    // success requires grpc-status; the fixed sing-box lite exception is an
    // explicit policy and never selected by inspecting a missing trailer.
    class ResponseHeaders {
        ResponsePolicy policy_;
        bool initial_=false,ended_=false;
        std::optional<std::uint32_t> remote_status_;
    public:
        explicit ResponseHeaders(ResponsePolicy policy=ResponsePolicy::standard) noexcept : policy_(policy) {}
        auto receive(std::span<FieldView const> fields,bool end_stream) noexcept -> HeaderStatus {
            if (ended_) return HeaderStatus::ended;
            auto checked=header_detail::fields(fields);
            if (checked!=HeaderStatus::accepted) return checked;
            bool status=false,type=false,encoding=false,grpc_status=false;
            std::optional<std::uint32_t> code;
            for (auto [name,value]:fields) {
                if (name==":status") { if (initial_ || status || value!="200") return HeaderStatus::status; status=true; }
                else if (name=="content-type") { if (initial_ || type || !header_detail::content_type(value)) return HeaderStatus::content_type; type=true; }
                else if (name=="grpc-encoding") { if (initial_ || encoding || value!="identity") return HeaderStatus::encoding; encoding=true; }
                else if (name=="grpc-status") {
                    std::uint32_t number;
                    if (grpc_status || !header_detail::unsigned_value(value,number)) return HeaderStatus::malformed;
                    grpc_status=true; code=number;
                } else if (name.starts_with(':')) return HeaderStatus::malformed;
            }
            if (!initial_ && (!status || !type)) return HeaderStatus::malformed;
            if (grpc_status && !end_stream) return HeaderStatus::malformed;
            if (initial_ && !end_stream) return HeaderStatus::malformed;
            if (end_stream && !grpc_status && policy_==ResponsePolicy::standard) return HeaderStatus::malformed;
            initial_=true;
            if (end_stream) { ended_=true; remote_status_=code; }
            return code && *code ? HeaderStatus::status : HeaderStatus::accepted;
        }
        auto data_end() noexcept -> HeaderStatus {
            if (ended_) return HeaderStatus::ended;
            if (!initial_ || policy_==ResponsePolicy::standard) return HeaderStatus::malformed;
            ended_=true; return HeaderStatus::accepted;
        }
        auto initial() const noexcept -> bool { return initial_; }
        auto ended() const noexcept -> bool { return ended_; }
        auto remote_status() const noexcept -> std::optional<std::uint32_t> { return remote_status_; }
    };
}
