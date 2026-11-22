module;
#include <proxy/proxy_macros.h>

export module cli.rule_fetch_response;
import std;
import nexus.compat;
import http.header;
import tls.byte_stream;
import proxy.v4;
import nexus.thirdparty.capy;

export namespace cli::rule_fetch {
    // A consumer may suspend while processing a chunk. Its view stays valid
    // until it returns, and false aborts the response.
    using BodySink=nexus::function_ref<nex::capy::task<bool>(std::string_view,std::chrono::steady_clock::time_point)>;
    using TransferResult=std::expected<unsigned,std::string>;
    using ResponseHeaders=nexus::function_ref<void(std::string_view,std::string_view)>;
    struct ResponsePolicy {
        bool conditional=false;
        bool redirect=false;

        [[nodiscard]] auto accepts(unsigned code) const noexcept -> bool {
            return code==200 || (conditional && code==304) || (redirect && http::redirect_status(code));
        }
    };
    struct Response {
        unsigned status;
        std::string body;
    };
    using Result=std::expected<Response,std::string>;
    using Http2Deadline=std::optional<std::chrono::steady_clock::time_point>;

    PRO_DEF_MEM_DISPATCH(HttpStreamRead,read);
    PRO_DEF_MEM_DISPATCH(HttpStreamSend,send);
    PRO_DEF_MEM_DISPATCH(HttpStreamClose,close_output);
    PRO_DEF_MEM_DISPATCH(HttpStreamCancel,cancel);
    struct Http2StreamFacade : pro::facade_builder
        ::add_convention<HttpStreamRead,nex::capy::task<std::expected<std::size_t,tls::detail::ByteStreamError>>(
            std::span<std::uint8_t>,Http2Deadline)>
        ::add_convention<HttpStreamSend,nex::capy::task<bool>(std::span<std::uint8_t const>,Http2Deadline)>
        ::add_convention<HttpStreamClose,nex::capy::task<bool>(Http2Deadline)>
        ::add_convention<HttpStreamCancel,void() noexcept>
        ::build {};
    using Http2Stream=pro::proxy<Http2StreamFacade>;

    struct Transfer {
        std::string_view authority,target;
        std::size_t maximum;
        std::chrono::steady_clock::time_point deadline;
        std::span<http::HeaderField const> extra_fields;
        ResponsePolicy policy;
        ResponseHeaders const* headers;
        BodySink sink;
    };

}
