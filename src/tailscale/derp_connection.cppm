export module tailscale.derp_connection;
import std;
import crypto;
import http.header;
import tailscale.derp_handshake;
import tailscale.derp_info;
import tailscale.derp_messages;
import tls.byte_stream;
import tls.connector;
import nexus.thirdparty.capy;

export namespace tailscale::derp {
    // DERP runs on a separate authenticated TLS connection. Node identity
    // and relay authentication never establish trust in inner WireGuard IP.
    template<class Connector>
    class Connection {
        using Clock = std::chrono::steady_clock;
        using TlsStream = tls::detail::ByteStream<typename Connector::Socket>;
        using Bytes = std::span<const std::uint8_t>;

        Connector connector_;
        std::optional<TlsStream> stream_;
        std::optional<PinnedClientHandshake> handshake_;
        std::vector<std::uint8_t> input_;
        std::optional<ServerSettings> settings_;
        std::string authority_;
        crypto::X25519Private const& identity_;
        Key pin_;
        bool ready_ = false, stopped_ = false;

        static auto lower(std::string_view value) -> std::string {
            std::string text(value);
            for (char& c : text) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 'a' - 'A');
            return text;
        }

        auto upgrade(Clock::time_point deadline) -> nex::capy::task<bool> {
            if (authority_.empty() || authority_.size() > 259 || !http::valid_header_field_value(authority_)) co_return false;
            auto request = std::format("GET /derp HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: DERP\r\n\r\n", authority_);
            if (!co_await stream_->send(Bytes(reinterpret_cast<const std::uint8_t*>(request.data()),request.size()), deadline))
                co_return false;
            std::vector<std::uint8_t> buffer(http::max_header_bytes);
            std::size_t used = 0;
            while (used < buffer.size()) {
                auto count = co_await stream_->read(std::span(buffer).subspan(used),deadline);
                if (!count || !*count) co_return false;
                used += *count;
                auto head = http::inspect_header(std::string_view(reinterpret_cast<const char*>(buffer.data()),used));
                if (head.status == http::HeaderStatus::incomplete) continue;
                if (head.status != http::HeaderStatus::complete ||
                    (head.first != "HTTP/1.1 101" && !head.first.starts_with("HTTP/1.1 101 "))) co_return false;
                http::HeaderFieldCursor cursor(head.field_lines);
                bool upgrade_seen = false, connection_seen = false;
                for (;;) {
                    auto item = cursor.next();
                    if (item.status == http::HeaderFieldStatus::end) break;
                    if (item.status != http::HeaderFieldStatus::field) co_return false;
                    auto name = lower(item.field.name), value = lower(item.field.value);
                    if (name == "connection") {
                        if (connection_seen || value != "upgrade") co_return false;
                        connection_seen = true;
                    } else if (name == "upgrade") {
                        if (upgrade_seen || value != "derp") co_return false;
                        upgrade_seen = true;
                    } else if (name == "transfer-encoding" || (name == "content-length" && value != "0")) co_return false;
                }
                if (!upgrade_seen || !connection_seen) co_return false;
                buffer.resize(used);
                buffer.erase(buffer.begin(),buffer.begin()+head.consumed);
                co_return buffer.empty() || stream_->prepend_owned(std::move(buffer));
            }
            co_return false;
        }

        auto read_exact(std::span<std::uint8_t> target, Clock::time_point deadline) -> nex::capy::task<bool> {
            while (!target.empty()) {
                auto count = co_await stream_->read(target,deadline);
                if (!count || !*count) co_return false;
                target = target.subspan(*count);
            }
            co_return true;
        }

        auto frame(Clock::time_point deadline) -> nex::capy::task<std::optional<Frame>> {
            std::array<std::uint8_t,header_size> wire{};
            if (!co_await read_exact(wire,deadline)) co_return std::nullopt;
            auto head = parse_header(wire);
            if (!head || head->length > payload_limit(head->type) || head->length > max_packet_size + key_size)
                co_return std::nullopt;
            input_.resize(head->length);
            if (!co_await read_exact(input_,deadline)) co_return std::nullopt;
            co_return Frame{head->type,input_};
        }

    public:
        template<class... Args>
        Connection(std::string authority, crypto::X25519Private const& identity, Key pin, Args&&... args)
            : connector_(std::forward<Args>(args)...), authority_(std::move(authority)), identity_(identity), pin_(pin) {}
        Connection(Connection const&) = delete;
        auto operator=(Connection const&) -> Connection& = delete;
        ~Connection() { cancel(); }

        auto cancel() noexcept -> void {
            stopped_ = true;
            ready_ = false;
            if (handshake_) handshake_->cancel();
            if (stream_) stream_->cancel();
            connector_.cancel();
        }

        auto start(Clock::time_point deadline) -> nex::capy::task<bool> {
            if (stopped_ || stream_) co_return false;
            auto started = Clock::now();
            auto result = co_await connector_.start(deadline);
            if (result != tls::detail::ConnectResult::connected || stopped_ || !connector_.application()) co_return false;
            stream_.emplace(*connector_.application());
            if (!co_await upgrade(deadline)) co_return false;
            handshake_.emplace(identity_,pin_,started,deadline);
            auto server_key = co_await frame(deadline);
            Nonce nonce;
            if (!server_key || !crypto::random_bytes(nonce)) co_return false;
            auto hello = handshake_->start(*server_key,nonce,Clock::now());
            if (!hello || !co_await stream_->send(*hello,deadline)) co_return false;
            auto server_info = co_await frame(deadline);
            if (!server_info) co_return false;
            auto confirmed = handshake_->finish(*server_info,Clock::now());
            if (!confirmed || stopped_) co_return false;
            settings_ = *confirmed;
            ready_ = true;
            co_return true;
        }

        [[nodiscard]] auto settings() const noexcept -> std::optional<ServerSettings> {
            return ready_ ? settings_ : std::nullopt;
        }

        // Each task sees stable frame bytes until the next receive call.
        auto receive(Clock::time_point deadline) -> nex::capy::task<std::optional<Packet>> {
            while (ready_) {
                auto message = co_await frame(deadline);
                if (!message) break;
                if (message->type == Type::recv_packet) {
                    auto packet = parse_packet(*message);
                    if (!packet) break;
                    co_return *packet;
                }
                if (message->type == Type::ping) {
                    auto ping = parse_ping(*message);
                    auto pong = ping ? encode_frame(Type::pong,*ping) : std::expected<std::vector<std::uint8_t>,Error>{std::unexpected(Error::invalid)};
                    if (!pong || !co_await stream_->send(*pong,deadline)) break;
                }
                if (message->type == Type::restarting) break;
            }
            cancel();
            co_return std::nullopt;
        }

        auto send(Key const& peer, Bytes bytes, Clock::time_point deadline) -> nex::capy::task<bool> {
            if (!ready_) co_return false;
            auto message = encode_packet(Type::send_packet,peer,bytes);
            if (!message) co_return false;
            if (co_await stream_->send(*message,deadline)) co_return true;
            cancel();
            co_return false;
        }
    };
}
