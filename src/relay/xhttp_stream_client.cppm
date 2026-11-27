module;
#include <boost/capy/ex/run.hpp>

module relay:xhttp_stream_client;
import std;
import crypto;
import http2.client_types;
import platform.socket_options;
import xhttp.client;
import xhttp.config;
import xhttp.wire;
import capy;
import corosio;
import :types;
import :session_interface;
import :xhttp_http1;
import :xhttp_http1_dial;
import :xhttp_http2_pool;

namespace relay::vless_xhttp {
    template<class Carrier>
    class HttpStream {
        using Worker = HttpWorker<Carrier>;
        using Pool = HttpPool<Carrier>;
        using Ticket = typename Carrier::Ticket;
        Session& session_;
        corosio::io_context& context_;
        Profile const& profile_;
        TcpSocketOptions options_;
        std::shared_ptr<Worker> worker_;
        typename Pool::Lease up_, down_;
        xhttp::StreamTickets<Ticket> tickets_;
        xhttp::Mode mode_;
        std::string id_;
        std::uint64_t sequence_ = 0;
        Clock::time_point last_post_{};
        std::stop_source stop_;
        bool stopped_ = false, output_closed_ = false;
        std::uint16_t last_http_status_ = 0;
        auto note_status(typename Pool::Lease const& lease) noexcept -> void {
            if (lease) if (auto s = lease->last_http_status(); s && s != 200) last_http_status_ = s;
        }
        auto request(Peer const& peer, xhttp::RequestKind kind) -> std::optional<xhttp::Request> {
            auto random = entropy();
            if (!random) return {};
            return xhttp::request(profile_.transport, peer.endpoint, kind, id_, sequence_, *random, peer.secure());
        }
        auto open(typename Pool::Lease& carrier, Peer const& peer, xhttp::RequestKind kind, http2::BodyView body, Clock::time_point until)
            -> capy::task<std::optional<Ticket>> {
            auto headers = request(peer, kind);
            if (!headers) co_return std::nullopt;
            co_return co_await carrier->open(*headers, peer, body, until);
        }
        auto downlink() noexcept -> typename Pool::Lease& { return mode_ == xhttp::Mode::stream_one ? up_ : down_; }
        auto packet(std::span<std::uint8_t const> data, Clock::time_point until) -> capy::task<bool> {
            auto start = last_post_ + profile_.transport.limits.post_interval;
            if (start > Clock::now()) {
                if (start >= until) co_return false;
                corosio::steady_timer timer(context_);
                timer.expires_at(start);
                auto [error] = co_await timer.wait();
                if (error || stopped_) co_return false;
            }
            if (sequence_ == std::numeric_limits<std::uint64_t>::max()) co_return false;
            if (!up_ || !up_.request()) {
                up_.reset();
                up_ = co_await worker_->up.acquire(session_, profile_.up, profile_.bootstrap, options_, until);
                if (!up_ || stopped_ || !up_.request()) co_return false;
            }
            auto stream = co_await open(up_, profile_.up, xhttp::RequestKind::packet, {data, true}, until);
            if (!stream) co_return false;
            struct Pending {
                Carrier& carrier;
                Ticket stream;
                ~Pending() { carrier.release(stream); }
            } pending{*up_.operator->(), *stream};
            last_post_ = Clock::now();
            std::array<std::uint8_t, 1024> reply;
            std::size_t remaining = 8192;
            for (;;) {
                auto result = co_await up_->read(*stream, reply, until);
                if (!result || *result > remaining) {
                    note_status(up_);
                    co_return false;
                }
                if (!*result) break;
                remaining -= *result;
            }
            ++sequence_;
            co_return true;
        }
    public:
        HttpStream(Session& session, corosio::io_context& context, Profile const& profile, TcpSocketOptions const& options,
                   std::shared_ptr<Worker> worker)
            : session_(session), context_(context), profile_(profile), options_(options),
              worker_(std::move(worker)),
              mode_(xhttp::select_mode(profile.transport.mode, profile.transport.endpoint.version, profile.up.reality.has_value(), profile.down.has_value())) {}
        ~HttpStream() { cancel(); }
    private:
        auto start_impl(Clock::time_point until) -> capy::task<bool> {
            if (mode_ == xhttp::Mode::stream_one) {
                up_ = co_await worker_->up.acquire(session_, profile_.up, profile_.bootstrap, options_, until);
                if (!up_ || stopped_ || !up_.request()) co_return false;
                if (auto stream = co_await open(up_, profile_.up, xhttp::RequestKind::stream, {{}, false}, until))
                    tickets_.bind_shared(*stream);
                co_return tickets_.upload.has_value() && !stopped_;
            }
            std::array<std::uint8_t, 16> random;
            if (!crypto::random_bytes(random)) co_return false;
            id_ = xhttp::session_id(random);
            auto const& peer = profile_.down ? *profile_.down : profile_.up;
            down_ = co_await worker_->down.acquire(session_, peer, profile_.bootstrap, options_, until);
            if (!down_ || stopped_ || !down_.request()) co_return false;
            if (auto dl = co_await open(down_, peer, xhttp::RequestKind::download, {}, until))
                tickets_.bind_download(*dl);
            if (!tickets_.download || stopped_) co_return false;
            if (mode_ == xhttp::Mode::packet_up) co_return true;
            up_ = co_await worker_->up.acquire(session_, profile_.up, profile_.bootstrap, options_, until);
            if (!up_ || stopped_ || !up_.request()) co_return false;
            if (auto ul = co_await open(up_, profile_.up, xhttp::RequestKind::upload, {{}, false}, until))
                tickets_.bind_upload(*ul);
            co_return tickets_.upload.has_value() && !stopped_;
        }
    public:
        auto start(Clock::time_point until) -> capy::task<bool> {
            co_return co_await boost::capy::run(stop_.get_token())(start_impl(until));
        }
        auto last_http_status() const noexcept -> std::uint16_t { return last_http_status_; }
        auto read(std::span<std::uint8_t> output, Deadline until = {})
            -> capy::task<std::expected<std::size_t, IoError>> {
            if (!tickets_.download || stopped_) co_return std::unexpected(IoError::state);
            auto result = co_await downlink()->read(*tickets_.download, output, until);
            if (!result) note_status(downlink());
            co_return result;
        }
    private:
        auto send_impl(std::span<std::uint8_t const> input, Deadline until) -> capy::task<bool> {
            if (stopped_ || output_closed_) co_return false;
            bool ok = true;
            if (tickets_.upload) ok = co_await up_->transmit(*tickets_.upload, {input, false}, until);
            else while (!input.empty()) {
                auto size = std::min(profile_.transport.limits.post_bytes, input.size());
                auto stop = until.value_or(Clock::now() + std::chrono::milliseconds(profile_.timeout));
                if (!co_await packet(input.first(size), stop)) { ok = false; break; }
                input = input.subspan(size);
            }
            if (!ok) {
                note_status(up_);
                cancel();
            }
            co_return ok;
        }
    public:
        auto send(std::span<std::uint8_t const> input, Deadline until = {}) -> capy::task<bool> {
            co_return co_await boost::capy::run(stop_.get_token())(send_impl(input, until));
        }
        auto close_output(Deadline until = {}) -> capy::task<bool> {
            if (stopped_) co_return false;
            if (output_closed_) co_return true;
            output_closed_ = true;
            if (!tickets_.upload) co_return true;
            auto ok = co_await up_->transmit(*tickets_.upload, {{}, true}, until);
            if (!ok) note_status(up_);
            co_return ok;
        }
        auto cancel() noexcept -> void {
            stopped_ = true;
            stop_.request_stop();
            tickets_.release_all(
                [this](Ticket const& t) noexcept { if (auto& dl = downlink()) dl->release(t); },
                [this](Ticket const& t) noexcept { if (up_) up_->release(t); });
        }
    };
}
