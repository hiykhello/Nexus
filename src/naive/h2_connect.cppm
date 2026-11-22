export module naive.h2_connect;
import std;
import naive.padding;
import http2.headers;
import http2.client_types;
import http2.client;
import http2.client_channel;
import tls.corosio_application;
import tls.byte_stream;
import net.stream_relay;
import nexus.thirdparty.nghttp2;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

export namespace naive {
    using Clock = std::chrono::steady_clock;
    using Deadline = std::optional<Clock::time_point>;

    inline constexpr std::size_t kH2StreamCapacity = 32;

    inline auto make_h2_limits() noexcept -> http2::ClientLimits {
        http2::ClientLimits limits;
        limits.stream_window = 65535;
        limits.header_fields = 100;
        limits.header_bytes = 16384;
        limits.max_body_chunk = 2 * 1024 * 1024;
        limits.shared_bytes = 64 * 1024 * 1024;
        return limits;
    }

    template<class Lower>
    class H2ClientStream {
    public:
        using Channel = http2::ClientChannel<Lower, kH2StreamCapacity>;

    private:
        Channel* channel_ = nullptr;
        http2::StreamTicket ticket_{};
        PaddingEncoder encoder_{false};
        PaddingDecoder decoder_{false};
        std::vector<std::uint8_t> encoded_;
        std::vector<std::uint8_t> decoded_;
        std::size_t decoded_offset_ = 0;
        bool canceled_ = false;
        bool output_closed_ = false;

        auto wait_tx(Deadline deadline) -> nex::capy::task<bool> {
            for (;;) {
                auto tx = channel_->tx_consumed(ticket_);
                if (!tx) co_return false;
                if (*tx) co_return true;
                if (canceled_ || !co_await channel_->wait_change(deadline)) co_return false;
            }
        }

    public:
        H2ClientStream() = default;
        H2ClientStream(Channel& channel, http2::StreamTicket ticket, bool use_padding) noexcept
            : channel_(&channel), ticket_(ticket), encoder_(use_padding), decoder_(use_padding) {}
        H2ClientStream(H2ClientStream const&) = delete;
        auto operator=(H2ClientStream const&) -> H2ClientStream& = delete;
        ~H2ClientStream() { release(); }

        auto release() noexcept -> void {
            if (!channel_) return;
            canceled_ = true;
            (void)channel_->release(ticket_);
            channel_ = nullptr;
        }

        auto cancel() noexcept -> void {
            if (std::exchange(canceled_, true)) return;
            if (channel_) (void)channel_->reset(ticket_);
        }

        auto send(std::span<std::uint8_t const> bytes, Deadline deadline = {}) -> nex::capy::task<bool> {
            if (!channel_ || canceled_ || output_closed_) co_return false;
            if (bytes.empty()) co_return true;
            if (!co_await wait_tx(deadline)) {
                cancel();
                co_return false;
            }
            std::span<std::uint8_t const> wire = bytes;
            if (!encoder_.in_passthrough()) {
                encoded_.clear();
                encoder_.encode(bytes, encoded_);
                wire = encoded_;
            } else {
                encoded_.assign(bytes.begin(), bytes.end());
                wire = encoded_;
            }
            while (!wire.empty()) {
                auto chunk = wire.first(std::min<std::size_t>(wire.size(), 1024 * 1024));
                auto accepted = channel_->provide(ticket_, {chunk, false});
                if (!accepted) {
                    cancel();
                    co_return false;
                }
                if (!*accepted) {
                    if (!co_await wait_tx(deadline)) {
                        cancel();
                        co_return false;
                    }
                    continue;
                }
                if (!co_await wait_tx(deadline)) {
                    cancel();
                    co_return false;
                }
                wire = wire.subspan(chunk.size());
            }
            co_return true;
        }

        auto read(std::span<std::uint8_t> out, Deadline deadline = {})
            -> nex::capy::task<std::expected<std::size_t, std::string>> {
            if (!channel_ || canceled_) co_return std::unexpected("HTTP/2 stream closed");
            if (out.empty()) co_return std::size_t{0};
            for (;;) {
                if (decoded_offset_ < decoded_.size()) {
                    auto count = std::min(out.size(), decoded_.size() - decoded_offset_);
                    std::copy_n(decoded_.begin() + static_cast<std::ptrdiff_t>(decoded_offset_), count, out.begin());
                    decoded_offset_ += count;
                    if (decoded_offset_ == decoded_.size()) {
                        decoded_.clear();
                        decoded_offset_ = 0;
                    }
                    co_return count;
                }
                auto state = channel_->response(ticket_);
                if (!state || state->failure) co_return std::unexpected("HTTP/2 stream failed");
                auto data = channel_->peek(ticket_);
                if (!data) co_return std::unexpected("HTTP/2 stream peek failed");
                if (!data->empty()) {
                    std::span<std::uint8_t const> raw = *data;
                    if (decoder_.in_passthrough()) {
                        auto count = std::min(out.size(), raw.size());
                        std::copy_n(raw.begin(), count, out.begin());
                        if (!channel_->consume(ticket_, count))
                            co_return std::unexpected("HTTP/2 stream consume failed");
                        co_return count;
                    }
                    decoded_.clear();
                    decoded_offset_ = 0;
                    if (!decoder_.feed(raw, decoded_))
                        co_return std::unexpected("NaiveProxy padding decode failed");
                    if (!channel_->consume(ticket_, raw.size()))
                        co_return std::unexpected("HTTP/2 stream consume failed");
                    continue;
                }
                if (state->remote_end) co_return std::size_t{0};
                if (!co_await channel_->wait_change(deadline))
                    co_return std::unexpected("HTTP/2 read timed out");
            }
        }

        auto close_output(Deadline deadline = {}) -> nex::capy::task<bool> {
            if (!channel_ || canceled_) co_return false;
            if (output_closed_) co_return true;
            output_closed_ = true;
            if (!co_await wait_tx(deadline)) co_return false;
            auto provided = channel_->provide(ticket_, {{}, true});
            if (!provided || !*provided) co_return false;
            for (;;) {
                auto state = channel_->response(ticket_);
                if (!state || state->failure) co_return false;
                if (state->local_end) co_return true;
                if (!co_await channel_->wait_change(deadline)) co_return false;
            }
        }
    };

    template<class Connector>
    class OwnedH2Connection {
    public:
        using Stream = tls::detail::ByteStream<typename Connector::Socket>;
        using Client = http2::Client<kH2StreamCapacity>;
        using Channel = http2::ClientChannel<Stream, kH2StreamCapacity>;

    private:
        std::unique_ptr<Connector> connector_;
        std::optional<Stream> stream_;
        std::optional<Channel> channel_;
        std::array<std::optional<http2::StreamTicket>, kH2StreamCapacity> retired_{};
        bool starting_ = false, running_ = false, stopped_ = false, canceled_ = false;
        std::uint16_t leased_ = 0;
        unsigned active_calls_ = 0;

        auto clear() noexcept -> void {
            if (active_calls_ > 1 || starting_ || running_ || leased_ || !canceled_) return;
            channel_.reset();
            stream_.reset();
            connector_.reset();
        }
        struct Call {
            OwnedH2Connection& owner;
            explicit Call(OwnedH2Connection& v) noexcept : owner(v) { ++owner.active_calls_; }
            ~Call() { owner.clear(); --owner.active_calls_; }
        };
        struct StartGuard {
            OwnedH2Connection& owner;
            bool done = false;
            ~StartGuard() { Call call(owner); owner.starting_ = false; if (!done) owner.stop(); }
        };
        struct RootGuard {
            OwnedH2Connection* owner;
            explicit RootGuard(OwnedH2Connection& v) noexcept : owner(&v) {}
            RootGuard(RootGuard const&) = delete;
            RootGuard(RootGuard&& o) noexcept : owner(std::exchange(o.owner, nullptr)) {}
            ~RootGuard() { if (owner) { Call call(*owner); owner->stop(); owner->running_ = false; } }
        };
        static auto root(RootGuard guard) -> nex::capy::task<> {
            (void)co_await guard.owner->channel_->run();
        }

        auto reap() noexcept -> void {
            if (!channel_) return;
            for (auto& ticket : retired_) {
                if (!ticket) continue;
                auto state = channel_->response(*ticket);
                if (state && !state->closed && !channel_->failure()) continue;
                auto res = channel_->release(*ticket);
                if (!res || *res) ticket.reset();
            }
        }

    public:
        template<class... Args>
        explicit OwnedH2Connection(Args&&... args) : connector_(std::make_unique<Connector>(std::forward<Args>(args)...)) {}
        ~OwnedH2Connection() {
            if (starting_ || running_ || leased_ || active_calls_) std::terminate();
            stop();
            clear();
        }
        OwnedH2Connection(OwnedH2Connection const&) = delete;
        auto operator=(OwnedH2Connection const&) -> OwnedH2Connection& = delete;

        auto acquired() noexcept -> void { ++leased_; }
        auto released() noexcept -> void { Call call(*this); --leased_; }
        auto cancel() noexcept -> void { stop(); }
        auto stop() noexcept -> void {
            Call call(*this);
            stopped_ = canceled_ = true;
            if (channel_) channel_->cancel();
            if (connector_) connector_->cancel();
        }
        auto usable() const noexcept -> bool {
            return !canceled_ && !stopped_ && channel_ && !channel_->failure() && !channel_->goaway();
        }
        auto available() const noexcept -> bool { return usable() && leased_ < kH2StreamCapacity; }
        auto drained() const noexcept -> bool { return !starting_ && !running_ && !leased_ && !active_calls_; }
        auto connector() noexcept -> Connector* { return connector_.get(); }

        enum class StartResult { connected, non_h2_tls, failed, timeout };

        auto start(Clock::time_point deadline) -> nex::capy::task<StartResult> {
            if (Clock::now() >= deadline) co_return StartResult::timeout;
            if (starting_ || running_ || channel_ || canceled_ || !connector_) co_return StartResult::failed;
            starting_ = true;
            StartGuard guard{*this};
            if (!co_await connector_->connect(deadline) || canceled_)
                co_return Clock::now() >= deadline ? StartResult::timeout : StartResult::failed;
            if (connector_->negotiated_alpn() != "h2") {
                guard.done = true;
                co_return StartResult::non_h2_tls;
            }
            co_return finish_adopt_connected(guard, deadline);
        }

        // Adopts an already TLS-connected connector whose negotiated ALPN is "h2".
        auto adopt_connected(Clock::time_point deadline) -> StartResult {
            if (starting_ || running_ || channel_ || canceled_ || !connector_) return StartResult::failed;
            starting_ = true;
            StartGuard guard{*this};
            return finish_adopt_connected(guard, deadline);
        }

    private:
        auto finish_adopt_connected(StartGuard& guard, Clock::time_point deadline) -> StartResult {
            if (Clock::now() >= deadline) return StartResult::timeout;
            auto* app = connector_->application();
            if (!app) return StartResult::failed;
            auto client = Client::create(make_h2_limits());
            if (!client) return StartResult::failed;
            stream_.emplace(*app);
            channel_.emplace(*stream_, std::move(*client));
            guard.done = true;
            return StartResult::connected;
        }

    public:
        auto take_non_h2_connector() noexcept -> std::unique_ptr<Connector> {
            if (running_ || channel_) return nullptr;
            canceled_ = stopped_ = true;
            return std::move(connector_);
        }

        auto run(nex::corosio::io_context& context) -> bool {
            if (starting_ || running_ || !usable()) return false;
            running_ = true;
            try {
                nex::capy::run_async(context.get_executor(), [] {}, [this](std::exception_ptr) noexcept { stop(); })(root(RootGuard(*this)));
            } catch (...) {
                running_ = false;
                stop();
                throw;
            }
            return true;
        }

        auto open_connect(std::string_view authority, std::string_view auth_header,
                          std::span<std::pair<std::string, std::string> const> extra_headers,
                          bool request_padding, Clock::time_point deadline)
            -> nex::capy::task<std::optional<std::unique_ptr<H2ClientStream<Stream>>>> {
            if (!usable()) co_return std::nullopt;
            std::string pad_val;
            std::vector<http2::FieldView> fields;
            fields.reserve(4 + extra_headers.size());
            fields.push_back({":method", "CONNECT"});
            fields.push_back({":authority", authority});
            if (!auth_header.empty()) fields.push_back({"proxy-authorization", auth_header});
            if (request_padding) {
                pad_val = generate_padding_header();
                fields.push_back({"padding", pad_val});
                fields.push_back({"padding-type-request", "1, 0"});
            }
            for (auto const& [k, v] : extra_headers) fields.push_back({k, v});

            std::optional<http2::StreamTicket> ticket;
            while (usable()) {
                reap();
                auto submitted = channel_->submit(fields, http2::BodyView{{}, false});
                if (submitted) {
                    ticket = *submitted;
                    break;
                }
                if (submitted.error().error != http2::ClientError::limit) co_return std::nullopt;
                if (!co_await channel_->wait_change(deadline)) co_return std::nullopt;
            }
            if (!ticket) co_return std::nullopt;

            auto retire = [&](http2::StreamTicket t) noexcept {
                auto released = channel_->release(t);
                if (released && !*released) retired_[t.slot] = t;
            };
            while (usable()) {
                auto state = channel_->response(*ticket);
                if (!state || state->failure || state->closed) {
                    retire(*ticket);
                    co_return std::nullopt;
                }
                if (state->status != 0) {
                    if (state->status != 200) {
                        retire(*ticket);
                        co_return std::nullopt;
                    }
                    bool use_padding = false;
                    if (request_padding) {
                        for (auto const& h : state->headers) {
                            if (header_ci_equal(h.name, "padding-type-reply") && parse_padding_type_reply(h.value)) {
                                use_padding = true;
                                break;
                            }
                        }
                    }
                    co_return std::make_unique<H2ClientStream<Stream>>(*channel_, *ticket, use_padding);
                }
                if (!co_await channel_->wait_change(deadline)) break;
            }
            retire(*ticket);
            co_return std::nullopt;
        }
    };
}
