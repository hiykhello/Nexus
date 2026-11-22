export module quic.http3_headers;
import std;
import http.header;
import nexus.thirdparty.nghttp3;

export namespace quic {
    enum class Http3HeaderError { count_limit,byte_limit,invalid_reference };
    // Holds native reference-counted fields without copying names, values or
    // credentials. Views live until clear/destruction; native's allocator
    // context must remain alive through that release, including after H3 stop.
    template<std::size_t Fields=64,std::size_t Bytes=16384>
    class Http3Headers {
        struct References { nex::nghttp3::nghttp3_rcbuf* name=nullptr; nex::nghttp3::nghttp3_rcbuf* value=nullptr; };
        std::array<References,Fields> references_{};
        std::array<http::HeaderField,Fields> views_{};
        std::size_t count_=0,bytes_=0;
    public:
        Http3Headers()=default;
        ~Http3Headers() { clear(); }
        Http3Headers(Http3Headers const&)=delete;
        auto operator=(Http3Headers const&) -> Http3Headers& = delete;
        Http3Headers(Http3Headers&&)=delete;
        auto operator=(Http3Headers&&) -> Http3Headers& = delete;
        auto clear() noexcept -> void {
            for (std::size_t i=0;i<count_;++i) {
                nex::nghttp3::nghttp3_rcbuf_decref(references_[i].name);
                nex::nghttp3::nghttp3_rcbuf_decref(references_[i].value);
                references_[i]={}; views_[i]={};
            }
            count_=bytes_=0;
        }
        auto append(nex::nghttp3::nghttp3_rcbuf* name,nex::nghttp3::nghttp3_rcbuf* value) noexcept -> std::expected<void,Http3HeaderError> {
            using namespace nex::nghttp3;
            if (!name || !value) return std::unexpected(Http3HeaderError::invalid_reference);
            if (count_==Fields) return std::unexpected(Http3HeaderError::count_limit);
            auto key=nghttp3_rcbuf_get_buf(name),text=nghttp3_rcbuf_get_buf(value);
            if (key.len>Bytes-bytes_ || text.len>Bytes-bytes_-key.len) return std::unexpected(Http3HeaderError::byte_limit);
            nghttp3_rcbuf_incref(name); nghttp3_rcbuf_incref(value);
            references_[count_]={name,value};
            views_[count_]={std::string_view(reinterpret_cast<char const*>(key.base),key.len),std::string_view(reinterpret_cast<char const*>(text.base),text.len)};
            ++count_; bytes_+=key.len+text.len; return {};
        }
        auto fields() const noexcept -> std::span<http::HeaderField const> { return std::span(views_).first(count_); }
        auto size() const noexcept -> std::size_t { return count_; }
        auto bytes() const noexcept -> std::size_t { return bytes_; }
    };
}
