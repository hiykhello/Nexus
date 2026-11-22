export module trojan.stream;
import std;
import trojan;
import trojan.auth;
import crypto;
import tls.byte_stream;
import tls.corosio_application;
import nexus.thirdparty.capy;

export namespace trojan::detail {
    struct AcceptedRequest { Request request; std::size_t user; };
    template<class Socket, class Stream = tls::detail::ByteStream<Socket>>
    class Client {
        Stream stream_;
        bool started_=false;
    public:
        explicit Client(tls::detail::ApplicationConnection<Socket>& connection)
            requires (!std::is_reference_v<Stream>) : stream_(connection) {}
        explicit Client(Stream stream) requires std::is_reference_v<Stream> : stream_(stream) {}
        auto stream() noexcept -> auto& { return stream_; }
        auto start(std::span<std::uint8_t const> key,Request const& request,tls::detail::ApplicationDeadline deadline={}) -> nex::capy::task<bool> {
            if (started_) co_return false;
            started_=true;
            auto header=encode_request(key,request);
            if (!header) { stream_.cancel(); co_return false; }
            struct Erase { std::vector<std::uint8_t>& bytes; ~Erase() { crypto::cleanse(bytes); } } erase{*header};
            auto sent=co_await stream_.send(*header,deadline);
            co_return sent;
        }
        auto read(std::span<std::uint8_t> bytes,tls::detail::ApplicationDeadline deadline={}) { return stream_.read(bytes,deadline); }
        auto send(std::span<std::uint8_t const> bytes,tls::detail::ApplicationDeadline deadline={}) { return stream_.send(bytes,deadline); }
        auto close_output() { return stream_.close_output(); }
        auto cancel() noexcept -> void { stream_.cancel(); }
    };
    // Authentication and request parsing are the only protocol work. After
    // the header, the same byte stream serves TCP or a datagram framer.
    template<class Socket, class Stream = tls::detail::ByteStream<Socket>>
    class Inbound {
        Stream stream_;
        std::span<PasswordKey const> users_;
        std::array<std::uint8_t,4096> buffer_{};
        std::vector<std::uint8_t> unread_;
        std::size_t unread_off_=0;
        bool started_=false;
    public:
        Inbound(tls::detail::ApplicationConnection<Socket>& connection,std::span<PasswordKey const> users)
            requires (!std::is_reference_v<Stream>) : stream_(connection),users_(users) {}
        Inbound(Stream stream,std::span<PasswordKey const> users)
            requires std::is_reference_v<Stream> : stream_(stream),users_(users) {}
        ~Inbound() { crypto::cleanse(buffer_); crypto::cleanse(unread_); }
        auto stream() noexcept -> auto& { return stream_; }
        auto read_request(tls::detail::ApplicationDeadline deadline={}) -> nex::capy::task<std::optional<AcceptedRequest>> {
            if (started_) co_return std::nullopt;
            started_=true;
            RequestDecoder decoder;
            for (;;) {
                auto received=co_await stream_.read(buffer_,deadline);
                if (!received || !*received) { stream_.cancel(); co_return std::nullopt; }
                auto fed=decoder.feed(std::span(buffer_).first(*received));
                if (fed.status==Status::incomplete) continue;
                if (fed.status!=Status::accepted) { stream_.cancel(); co_return std::nullopt; }
                auto const* header=decoder.request();
                auto user=header ? authenticate(users_,header->key) : std::nullopt;
                if (!user) { stream_.cancel(); co_return std::nullopt; }
                auto accepted=AcceptedRequest{header->request,*user};
                auto tail=std::span(buffer_).subspan(fed.consumed,*received-fed.consumed);
                if (!tail.empty()) {
                    unread_.assign(tail.begin(),tail.end());
                    unread_off_=0;
                }
                crypto::cleanse(std::span(buffer_).first(fed.consumed));
                co_return accepted;
            }
        }
        auto read(std::span<std::uint8_t> bytes,tls::detail::ApplicationDeadline deadline={})
            -> nex::capy::task<std::expected<std::size_t,tls::detail::ByteStreamError>> {
            if (unread_off_<unread_.size()) {
                auto n=std::min(bytes.size(),unread_.size()-unread_off_);
                std::copy_n(unread_.data()+unread_off_,n,bytes.begin());
                unread_off_+=n;
                if (unread_off_==unread_.size()) { crypto::cleanse(unread_); unread_.clear(); unread_off_=0; }
                co_return n;
            }
            auto r=co_await stream_.read(bytes,deadline);
            if (!r) co_return std::unexpected(tls::detail::ByteStreamError::io);
            co_return *r;
        }
        auto read_sniff(std::span<std::uint8_t> bytes,tls::detail::ApplicationDeadline deadline)
            -> nex::capy::task<std::expected<std::size_t,tls::detail::ByteStreamError>> {
            if (unread_off_<unread_.size()) {
                auto n=std::min(bytes.size(),unread_.size()-unread_off_);
                std::copy_n(unread_.data()+unread_off_,n,bytes.begin());
                unread_off_+=n;
                if (unread_off_==unread_.size()) { crypto::cleanse(unread_); unread_.clear(); unread_off_=0; }
                co_return n;
            }
            if constexpr (requires { stream_.read(bytes,deadline,tls::detail::ReadTimeoutPolicy::preserve_connection); }) {
                co_return co_await stream_.read(bytes,deadline,tls::detail::ReadTimeoutPolicy::preserve_connection);
            } else {
                auto r=co_await stream_.read(bytes,deadline);
                if (!r) co_return std::unexpected(tls::detail::ByteStreamError::io);
                co_return *r;
            }
        }
        auto send(std::span<std::uint8_t const> bytes,tls::detail::ApplicationDeadline deadline={}) { return stream_.send(bytes,deadline); }
        auto close_output() { return stream_.close_output(); }
        auto cancel() noexcept -> void { stream_.cancel(); }
    };
}
