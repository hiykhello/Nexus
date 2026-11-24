// Pooled HTTP/2 and handshake manager for DNS-over-HTTPS queries.
export module dns.https_pool;
import std;
import capy;
import corosio;
import dns.corosio_query;
import dns.doh_exchange;
import dns.doh_pool;
import dns.input_budget;
import http2.client_channel;

export namespace dns::doh_detail {
    struct HttpsProfile {
        StreamFactory stream;
        std::optional<std::chrono::milliseconds> connect_timeout;
        std::string authority, path;
    };

    class H2Connection {
        static constexpr std::size_t capacity = 8;
        struct ByteStream {
            Stream& owner;

            auto read(std::span<std::uint8_t> bytes, StreamDeadline deadline) -> StreamRead {
                return owner->read(bytes, deadline);
            }
            auto send(std::span<std::uint8_t const> bytes, StreamDeadline deadline) -> capy::task<bool> {
                return owner->send(bytes, deadline);
            }
            auto close_output(StreamDeadline deadline) -> capy::task<bool> {
                return owner->close_output(deadline);
            }
            auto cancel() noexcept -> void { owner->cancel(); }
        };
        using Channel = http2::ClientChannel<ByteStream, capacity>;
        using Ticket = http2::StreamTicket;

        struct Outgoing {
            Bytes data;
            InputBudget::Lease charge;
        };
        struct Slot {
            Ticket ticket;
            Outgoing request;
            bool abandoned = false;
        };

        std::shared_ptr<HttpsProfile const> profile_;
        Endpoint endpoint_;
        std::array<std::optional<Slot>, capacity> slots_;
        Stream stream_;
        ByteStream lower_{stream_};
        Channel channel_;
        Clock::time_point last_used_ = Clock::now();
        std::size_t waiting_ = 0;
        bool stopped_ = false;

        auto discard(Ticket ticket) noexcept -> void {
            auto& slot = slots_[ticket.slot];
            if (channel_.release(ticket).value_or(false)) slot.reset();
            else slot->abandoned = true;
        }

        auto leave(Ticket ticket) noexcept -> void {
            discard(ticket);
            --waiting_;
            last_used_ = Clock::now();
        }

        auto prune() noexcept -> void {
            for (auto& slot : slots_) {
                if (slot && slot->abandoned && channel_.release(slot->ticket).value_or(false))
                    slot.reset();
            }
        }

    public:
        H2Connection(std::shared_ptr<HttpsProfile const> profile, Endpoint endpoint,
            Stream stream, std::unique_ptr<http2::Client<capacity>> client)
            : profile_(std::move(profile)), endpoint_(endpoint), stream_(std::move(stream)),
              channel_(lower_, std::move(client)) {}

        auto stop() noexcept -> void {
            if (!std::exchange(stopped_, true)) channel_.cancel();
        }

        auto start(Io& context, std::shared_ptr<H2Connection> const& owner) -> void {
            try {
                capy::run_async(context.get_executor(), [owner](auto) noexcept { owner->stop(); },
                    [owner](std::exception_ptr) noexcept { owner->stop(); })(channel_.run());
            } catch (...) {
                stop();
                throw;
            }
        }

        [[nodiscard]] auto idle() const noexcept -> bool { return !waiting_; }

        [[nodiscard]] auto evict(Clock::time_point now) noexcept -> bool {
            return idle() && (stopped_ || channel_.failure() || channel_.goaway() ||
                now - last_used_ >= std::chrono::seconds(15));
        }

        [[nodiscard]] auto accepts(HttpsProfile const& profile, Endpoint endpoint) noexcept -> bool {
            if (profile_.get() != &profile || endpoint_ != endpoint || stopped_ ||
                channel_.failure() || channel_.goaway() || channel_.finished()) return false;
            prune();
            return std::ranges::any_of(slots_, [](auto const& slot) { return !slot; });
        }

        auto query(QueryMessage const& question, std::uint16_t id, Bytes wire,
            Clock::time_point deadline, InputBudget& budget, std::stop_token stop)
            -> capy::task<std::expected<Response, Error>> {
            auto fail = [&](Error error) {
                return stop.stop_requested() ? Error::canceled : Clock::now() >= deadline ? Error::timeout : error;
            };
            if (stop.stop_requested() || Clock::now() >= deadline) co_return std::unexpected(fail(Error::transport));

            auto charge = default_message_override_budget().acquire(wire.capacity());
            if (!charge) co_return std::unexpected(Error::budget_exhausted);
            Outgoing pending{std::move(wire), std::move(*charge)};
            auto length = std::to_string(pending.data.size());
            std::string host = profile_->authority;
            if (endpoint_.port() != 443) host += ':' + std::to_string(endpoint_.port());
            auto fields = detail::h2_fields(host, profile_->path, length);
            auto submitted = channel_.submit(fields, {pending.data});
            if (!submitted) co_return std::unexpected(fail(Error::transport));
            auto ticket = *submitted;
            slots_[ticket.slot].emplace(Slot{ticket, std::move(pending)});
            ++waiting_;
            struct Registration {
                H2Connection& owner;
                Ticket ticket;
                ~Registration() { owner.leave(ticket); }
            } registration{*this, ticket};
            std::stop_callback cancellation(stop, [this] noexcept { channel_.notify_waiters(); });

            detail::Body body(budget);
            auto accepted = co_await detail::receive_h2(channel_, ticket, deadline, body, stop);
            if (!accepted || stop.stop_requested() || Clock::now() >= deadline)
                co_return std::unexpected(fail(body.error));
            co_return detail::finish(std::move(body), question, id);
        }

        static auto client() { return http2::Client<capacity>::create(); }
    };

    class Handshake {
        std::shared_ptr<HttpsProfile const> profile_;
        Endpoint endpoint_;
        Stream stream_;
        capy::async_event changed_;
        std::optional<Error> error_;
        std::size_t waiters_ = 0;
        bool done_ = false;

        auto connect(Clock::time_point deadline) -> capy::task<> {
            if (done_) co_return;
            if (co_await stream_->start(deadline)) {
                if (!done_) complete();
            } else if (!done_) {
                complete(Clock::now() >= deadline ? Error::timeout : Error::transport);
            }
        }
        auto complete(std::optional<Error> error = {}) noexcept -> void {
            error_ = error;
            done_ = true;
            changed_.set();
        }

    public:
        Handshake(std::shared_ptr<HttpsProfile const> profile, Endpoint endpoint, Stream stream)
            : profile_(std::move(profile)), endpoint_(endpoint), stream_(std::move(stream)) {}

        [[nodiscard]] auto unused() const noexcept -> bool { return !waiters_ && done_; }

        [[nodiscard]] auto accepts(HttpsProfile const& profile, Endpoint endpoint) const noexcept -> bool {
            return &profile == profile_.get() && endpoint == endpoint_ && !error_ && stream_ && waiters_ < 8;
        }

        auto start(Io& io, std::shared_ptr<Handshake> const& owner) -> void {
            auto limit = profile_->connect_timeout.value_or(std::chrono::seconds(5));
            try {
                capy::run_async(io.get_executor(), [owner] {},
                    [owner](std::exception_ptr) noexcept {
                        if (!owner->done_) owner->complete(Error::transport);
                    })(connect(Clock::now() + limit));
            } catch (...) {
                stop();
                throw;
            }
        }

        auto stop() noexcept -> void {
            if (stream_) stream_->cancel();
            complete(Error::canceled);
        }

        auto wait(Clock::time_point deadline, std::stop_token stop) -> capy::task<std::expected<void, Error>> {
            ++waiters_;
            struct Registration {
                Handshake& owner;
                ~Registration() { if (!--owner.waiters_ && !owner.done_) owner.stop(); }
            } registration{*this};
            std::stop_callback cancellation(stop, [this] noexcept { changed_.set(); });
            while (!done_ && !stop.stop_requested() && Clock::now() < deadline) {
                changed_.clear();
                auto [error] = co_await corosio::timeout(changed_.wait(), deadline);
                if (error && !capy::is_timeout(error)) co_return std::unexpected(Error::canceled);
            }
            if (stop.stop_requested()) co_return std::unexpected(Error::canceled);
            if (Clock::now() >= deadline) co_return std::unexpected(Error::timeout);
            if (error_) co_return std::unexpected(*error_);
            co_return std::expected<void, Error>{};
        }

        auto take() noexcept -> Stream { return std::move(stream_); }
    };

    class HttpsPool final : public capy::execution_context::service {
        static constexpr std::size_t capacity = 16;
        std::vector<std::shared_ptr<H2Connection>> connections_;
        std::vector<std::shared_ptr<Handshake>> handshakes_;
        bool stopped_ = false;
        auto shutdown() noexcept -> void override { stop(); }

    public:
        explicit HttpsPool(capy::execution_context&) {}
        auto stop() noexcept -> void {
            stopped_ = true;
            for (auto const& connection : connections_) connection->stop();
            connections_.clear();
            for (auto const& handshake : handshakes_) handshake->stop();
            handshakes_.clear();
        }
        auto resume() noexcept -> void { stopped_ = false; }
        [[nodiscard]] auto stopped() const noexcept -> bool { return stopped_; }
        auto reap(Clock::time_point now) noexcept -> void {
            std::erase_if(handshakes_, [](auto const& handshake) { return handshake->unused(); });
            std::erase_if(connections_, [now](auto const& connection) {
                if (!connection->evict(now)) return false;
                connection->stop();
                return true;
            });
        }
        auto find(HttpsProfile const& profile, Endpoint endpoint) -> std::shared_ptr<H2Connection> {
            reap(Clock::now());
            auto existing = std::ranges::find_if(connections_, [&](auto const& connection) {
                return connection->accepts(profile, endpoint);
            });
            return existing == connections_.end() ? nullptr : *existing;
        }
        auto join(Io& io, std::shared_ptr<HttpsProfile const> const& profile, Endpoint endpoint)
            -> std::expected<std::shared_ptr<Handshake>, Error> {
            auto existing = std::ranges::find_if(handshakes_, [&](auto const& handshake) {
                return handshake->accepts(*profile, endpoint);
            });
            if (existing != handshakes_.end()) return *existing;
            if (handshakes_.size() == capacity) return std::shared_ptr<Handshake>{};
            auto stream = profile->stream(io, endpoint);
            if (!stream) return std::unexpected(stream.error());
            auto handshake = std::make_shared<Handshake>(profile, endpoint, std::move(*stream));
            handshakes_.push_back(handshake);
            handshake->start(io, handshake);
            return handshake;
        }

        auto adopt(std::shared_ptr<HttpsProfile const> const& profile, Endpoint endpoint,
            Stream& stream) -> std::shared_ptr<H2Connection> {
            if (stopped_) return {};
            if (connections_.size() == capacity) {
                auto idle = std::ranges::find_if(connections_, [](auto const& connection) { return connection->idle(); });
                if (idle == connections_.end()) return {};
                (*idle)->stop();
                connections_.erase(idle);
            }
            auto client = H2Connection::client();
            if (!client) return {};
            auto connection = std::make_shared<H2Connection>(profile, endpoint, std::move(stream), std::move(*client));
            connections_.push_back(connection);
            return connection;
        }
    };
}
