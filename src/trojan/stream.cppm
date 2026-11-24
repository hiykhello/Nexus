export module trojan.stream;
import std;
import trojan;
import trojan.auth;
import crypto;
import tls.byte_stream;
import tls.corosio_application;
import capy;

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
        auto start(std::span<std::uint8_t const> key,Request const& request,tls::detail::ApplicationDeadline deadline={}) -> capy::task<bool> {
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
        std::size_t unread_off_=0, unread_end_=0;
        bool started_=false;
        using ReadTask = capy::task<std::expected<std::size_t,tls::detail::ByteStreamError>>;
        static auto reject_empty() -> ReadTask { co_return std::unexpected(tls::detail::ByteStreamError::state); }
        auto read_unread(std::span<std::uint8_t> bytes) -> ReadTask {
            if (bytes.empty()) co_return std::unexpected(tls::detail::ByteStreamError::state);
            auto n=std::min(bytes.size(),unread_end_-unread_off_);
            std::copy_n(buffer_.data()+unread_off_,n,bytes.begin());
            unread_off_+=n;
            if (unread_off_==unread_end_) {
                crypto::cleanse(std::span(buffer_).first(unread_end_));
                unread_off_=unread_end_=0;
            }
            co_return n;
        }
        auto read_adapted(std::span<std::uint8_t> bytes,tls::detail::ApplicationDeadline deadline) -> ReadTask {
            auto r=co_await stream_.read(bytes,deadline);
            if (!r) co_return std::unexpected(tls::detail::ByteStreamError::io);
            co_return *r;
        }
    public:
        Inbound(tls::detail::ApplicationConnection<Socket>& connection,std::span<PasswordKey const> users)
            requires (!std::is_reference_v<Stream>) : stream_(connection),users_(users) {}
        Inbound(Stream stream,std::span<PasswordKey const> users)
            requires std::is_reference_v<Stream> : stream_(stream),users_(users) {}
        ~Inbound() { crypto::cleanse(buffer_); }
        auto stream() noexcept -> auto& { return stream_; }
        auto read_request(tls::detail::ApplicationDeadline deadline={}) -> capy::task<std::optional<AcceptedRequest>> {
            if (started_) co_return std::nullopt;
            started_=true;
            struct Guard {
                Inbound& owner;
                bool done=false;
                ~Guard() { if (!done) { crypto::cleanse(owner.buffer_); owner.stream_.cancel(); } }
            } guard{*this};
            RequestDecoder decoder;
            for (;;) {
                auto received=co_await stream_.read(buffer_,deadline);
                if (!received || !*received) co_return std::nullopt;
                auto fed=decoder.feed(std::span(buffer_).first(*received));
                if (fed.status==Status::incomplete) {
                    crypto::cleanse(std::span(buffer_).first(*received));
                    continue;
                }
                if (fed.status!=Status::accepted) co_return std::nullopt;
                auto const* header=decoder.request();
                auto user=header ? authenticate(users_,header->key) : std::nullopt;
                if (!user) co_return std::nullopt;
                auto accepted=AcceptedRequest{header->request,*user};
                if (fed.consumed < *received) {
                    unread_off_=fed.consumed;
                    unread_end_=*received;
                }
                crypto::cleanse(std::span(buffer_).first(fed.consumed));
                guard.done=true;
                co_return accepted;
            }
        }
        auto read(std::span<std::uint8_t> bytes,tls::detail::ApplicationDeadline deadline={}) -> ReadTask {
            if (bytes.empty()) return reject_empty();
            if (unread_off_<unread_end_) return read_unread(bytes);
            if constexpr (std::same_as<decltype(stream_.read(bytes,deadline)),ReadTask>) {
                return stream_.read(bytes,deadline);
            } else {
                return read_adapted(bytes,deadline);
            }
        }
        auto read_sniff(std::span<std::uint8_t> bytes,tls::detail::ApplicationDeadline deadline) -> ReadTask {
            if (bytes.empty()) return reject_empty();
            if (unread_off_<unread_end_) return read_unread(bytes);
            if constexpr (requires { stream_.read(bytes,deadline,tls::detail::ReadTimeoutPolicy::preserve_connection); }) {
                return stream_.read(bytes,deadline,tls::detail::ReadTimeoutPolicy::preserve_connection);
            } else if constexpr (std::same_as<decltype(stream_.read(bytes,deadline)),ReadTask>) {
                return stream_.read(bytes,deadline);
            } else {
                return read_adapted(bytes,deadline);
            }
        }
        auto send(std::span<std::uint8_t const> bytes,tls::detail::ApplicationDeadline deadline={}) { return stream_.send(bytes,deadline); }
        auto close_output() { return stream_.close_output(); }
        auto cancel() noexcept -> void { stream_.cancel(); }
    };
}
