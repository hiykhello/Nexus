module relay:xhttp_carrier;
import std;
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
import :xhttp_http1_client;
import :xhttp_http2_client;
import :xhttp_http3_client;

namespace relay::vless_xhttp {
    class HttpCarrier {
        using Native = std::variant<std::shared_ptr<Http1Carrier>, std::shared_ptr<Http2Carrier>, std::shared_ptr<Http3Carrier>>;
        Native connection_;

        static auto make(Session& session, corosio::io_context& context, Peer const& peer,
            std::optional<std::size_t> bootstrap, TcpSocketOptions const& options) -> Native {
            switch (peer.endpoint.version) {
            case xhttp::HttpVersion::http1: return std::make_shared<Http1Carrier>(session, context, peer, bootstrap, options);
            case xhttp::HttpVersion::http2: return std::make_shared<Http2Carrier>(session, context, peer, bootstrap, options);
            case xhttp::HttpVersion::http3: return std::make_shared<Http3Carrier>(session, context, peer, bootstrap, options);
            }
            std::unreachable();
        }
    public:
        using Ticket = std::variant<Http1Carrier::Ticket, Http2Carrier::Ticket, Http3Carrier::Ticket>;
        HttpCarrier(Session& session, corosio::io_context& context, Peer const& peer,
            std::optional<std::size_t> bootstrap, TcpSocketOptions const& options)
            : connection_(make(session, context, peer, bootstrap, options)) {}
        auto connect(std::shared_ptr<HttpCarrier>, corosio::io_context& ctx, Clock::time_point until) {
            return std::visit([&](auto const& carrier) { return carrier->connect(carrier, ctx, until); }, connection_);
        }
        auto wait_ready(Clock::time_point until) {
            return std::visit([&](auto const& carrier) { return carrier->wait_ready(until); }, connection_);
        }
        auto failed() const noexcept -> bool {
            return std::visit([](auto const& carrier) { return carrier->failed(); }, connection_);
        }
        auto last_http_status() const noexcept -> std::uint16_t {
            return std::visit([](auto const& carrier) { return carrier->last_http_status(); }, connection_);
        }
        auto record_peer(Session& session) const noexcept -> void {
            std::visit([&](auto const& carrier) { carrier->record_peer(session); }, connection_);
        }
        auto cancel() noexcept -> void {
            std::visit([](auto const& carrier) { carrier->cancel(); }, connection_);
        }
        auto retire() noexcept -> void {
            std::visit([](auto const& carrier) {
                if constexpr (requires { carrier->retire(carrier); }) carrier->retire(carrier);
                else carrier->cancel();
            }, connection_);
        }
    private:
        template<class Carrier>
        static auto submit(Carrier& carrier, xhttp::Request const& request, Peer const& peer, http2::BodyView body,
            Clock::time_point until) -> capy::task<std::optional<Ticket>> {
            auto stream = co_await carrier.open(request, peer, body, until);
            if (!stream) co_return std::nullopt;
            co_return Ticket(*stream);
        }
    public:
        auto open(xhttp::Request const& request, Peer const& peer, http2::BodyView body, Clock::time_point until) {
            return std::visit([&](auto const& carrier) { return submit(*carrier, request, peer, body, until); }, connection_);
        }
        auto read(Ticket stream, std::span<std::uint8_t> output, Deadline until) {
            return std::visit([&](auto const& carrier) {
                using Carrier = typename std::decay_t<decltype(carrier)>::element_type;
                return carrier->read(std::get<typename Carrier::Ticket>(stream), output, until);
            }, connection_);
        }
        auto transmit(Ticket stream, http2::BodyView body, Deadline until) {
            return std::visit([&](auto const& carrier) {
                using Carrier = typename std::decay_t<decltype(carrier)>::element_type;
                return carrier->transmit(std::get<typename Carrier::Ticket>(stream), body, until);
            }, connection_);
        }
        auto release(Ticket stream) noexcept -> void {
            std::visit([&](auto const& carrier) {
                using Carrier = typename std::decay_t<decltype(carrier)>::element_type;
                carrier->release(std::get<typename Carrier::Ticket>(stream));
            }, connection_);
        }
    };
}
