module relay:xhttp_http2_client;
import std;
import http.header;
import http2.client_channel;
import http2.client_types;
import http2.headers;
import xhttp.client;
import xhttp.wire;
import capy;
import corosio;
import :types;
import :session_interface;
import :xhttp_http1;
import :xhttp_http1_dial;

namespace relay::vless_xhttp {
    class Http2Carrier {
        static constexpr std::size_t capacity = 3 * 256;
        using Client = http2::Client<capacity>;
        using Channel = http2::ClientChannel<Lower, capacity>;
        CarrierDns dns_;
        Connection connection_;
        std::optional<Channel> channel_;
        std::array<std::optional<http2::StreamTicket>, capacity> retired_{};
        capy::async_event ready_;
        bool connecting_ = true, stopped_ = false;
        std::uint16_t last_status_ = 0;

        auto reap() noexcept -> void {
            for (auto& ticket : retired_) {
                if (!ticket) continue;
                auto state = channel_->response(*ticket);
                if (state && !state->closed && !channel_->failure()) continue;
                auto result = channel_->release(*ticket);
                if (!result || *result) ticket.reset();
            }
        }
    public:
        using Ticket = http2::StreamTicket;
        Http2Carrier(Session& session, corosio::io_context& context, Peer const& peer,
                std::optional<std::size_t> bootstrap, TcpSocketOptions const& options)
            : dns_(session, context), connection_(dns_.session, context, peer, bootstrap, options) {}
        auto connect(std::shared_ptr<Http2Carrier> owner, corosio::io_context& context, Clock::time_point until)
            -> capy::task<bool> {
            struct Signal {
                Http2Carrier& carrier;
                ~Signal() { carrier.connecting_ = false; carrier.ready_.set(); }
            } signal{*this};
            if (stopped_) co_return false;
            auto connected = co_await connection_.connect(until);
            if (!connected || stopped_) co_return false;
            http2::ClientLimits limits;
            limits.header_bytes = http::max_header_bytes;
            limits.max_body_chunk = 8 * 1024 * 1024;
            limits.shared_bytes = 64 * 1024 * 1024;
            auto client = Client::create(limits);
            if (!client) co_return false;
            channel_.emplace(connection_.stream, std::move(*client));
            auto run = [](std::shared_ptr<Http2Carrier> carrier) -> capy::task<> {
                (void)co_await carrier->channel_->run();
                carrier->cancel();
            };
            capy::run_async(context.get_executor(), [owner] {}, [owner](std::exception_ptr) { owner->cancel(); })(run(owner));
            co_return true;
        }
        auto cancel() noexcept -> void {
            if (std::exchange(stopped_, true)) return;
            ready_.set();
            if (channel_) channel_->cancel();
            connection_.cancel();
        }
        auto wait_ready(Clock::time_point until) -> capy::task<bool> {
            if (connecting_ && !stopped_) {
                auto [error] = co_await corosio::timeout(ready_.wait(), until);
                if (error) co_return false;
            }
            co_return channel_.has_value() && !stopped_;
        }
        auto failed() const noexcept -> bool {
            return stopped_ || (!connecting_ && (!channel_ || channel_->failure() || channel_->goaway()));
        }
        auto last_http_status() const noexcept -> std::uint16_t { return last_status_; }
        auto record_peer(Session& session) const noexcept -> void {
            if (connection_.connected_peer) session.record_physical_peer(*connection_.connected_peer);
        }
        auto open(xhttp::Request const& request, Peer const& peer, http2::BodyView body, Clock::time_point until)
            -> capy::task<std::optional<Ticket>> {
            std::vector<http2::FieldView> fields{{":method", request.method}, {":scheme", peer.secure() ? "https" : "http"},
                {":path", request.target}, {":authority", peer.endpoint.authority}};
            for (auto const& [name, value] : request.fields) fields.push_back({name, value});
            auto length = std::to_string(body.bytes.size());
            if (body.end_stream && request.method == "POST") fields.push_back({"content-length", length});
            while (!failed()) {
                reap();
                auto stream = channel_->submit(fields, body);
                if (stream) co_return *stream;
                if (stream.error().error != http2::ClientError::limit) break;
                if (!co_await channel_->wait_change(until)) break;
            }
            co_return std::nullopt;
        }
        auto read(http2::StreamTicket stream, std::span<std::uint8_t> output, Deadline until)
            -> capy::task<std::expected<std::size_t, IoError>> {
            if (output.empty()) co_return 0;
            for (;;) {
                auto state = channel_->response(stream);
                if (!state || state->failure) co_return std::unexpected(IoError::io);
                if (state->status && state->status != 200) { last_status_ = state->status; co_return std::unexpected(IoError::protocol); }
                if (state->status == 200) {
                    auto data = channel_->peek(stream);
                    if (!data) co_return std::unexpected(IoError::io);
                    if (!data->empty()) {
                        auto count = std::min(data->size(), output.size());
                        std::ranges::copy(data->first(count), output.begin());
                        if (!channel_->consume(stream, count)) co_return std::unexpected(IoError::io);
                        co_return count;
                    }
                    if (state->remote_end) co_return 0;
                }
                if (!co_await channel_->wait_change(until))
                    co_return std::unexpected(until && Clock::now() >= *until ? IoError::timeout : IoError::io);
            }
        }
        auto transmit(http2::StreamTicket stream, http2::BodyView body, Deadline until) -> capy::task<bool> {
            auto accepted = channel_->provide(stream, body);
            if (!accepted || !*accepted) co_return false;
            for (;;) {
                auto state = channel_->response(stream);
                if (!state || state->failure) break;
                if (state->status && state->status != 200) { last_status_ = state->status; break; }
                if (body.end_stream ? state->local_end : state->body_released) co_return true;
                if (!co_await channel_->wait_change(until)) break;
            }
            release(stream);
            co_return false;
        }
        auto release(http2::StreamTicket stream) noexcept -> void {
            auto released = channel_->release(stream);
            if (released && !*released) retired_[stream.slot] = stream;
        }
    };
}
