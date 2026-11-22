export module masque.client_session;
import std;
import nexus.compat;
import crypto;
import http.header;
import masque.capsule;
import masque.connect_ip;
import masque.session;
import masque.http3;
import masque.datagram;
import masque.ip_control;
import masque.ip_receiver;
import masque.udp_session;
export import masque.client_profile;
import quic.ech_config;
import quic.native_memory;
import quic.cid_registry;
import quic.datagram_port;
import quic.datagram_session;
import net.datagram_driver;
import net.udp_connect;
import hysteria2.transport_options;
import platform.socket_options;
import nexus.thirdparty.ngtcp2;
import nexus.thirdparty.nghttp3;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

export namespace masque {
    struct HttpResponse {
        unsigned status=0;
        std::vector<std::pair<std::string,std::string>> fields;
        std::string body;
    };

    using HttpHeaderSink=nexus::function_ref<void(std::string_view,std::string_view)>;
    using HttpBodySink=nexus::function_ref<nex::capy::task<bool>(std::string_view,std::chrono::steady_clock::time_point)>;

    enum class HttpError { transport, response };

    struct HttpPost {
        std::string_view media_type;
        std::span<std::uint8_t const> bytes;
    };

    template<class Socket = nex::corosio::udp_socket>
    class Client {
        using Clock = std::chrono::steady_clock;
        using Registry = quic::CidRegistry<1, 8>;
        static constexpr std::size_t stream_window=16*1024;

#include "client_hooks.hpp"

    public:
        using MasqueSession = Session<ClientProfile::Tls, Hooks>;
        using QuicSession = quic::DatagramSession<ClientProfile::Tls, MasqueSession>;

    private:
        struct Bundle {
            std::unique_ptr<ClientProfile::Tls> tls;
            Hooks hooks;
            quic::NativeMemory<> memory;
            MasqueSession app;
            QuicSession session;
            Bundle(std::unique_ptr<ClientProfile::Tls> t, Registry& reg, quic::SessionHandle owner,
                   nex::capy::async_event& ev, nex::corosio::endpoint const& local, ClientProfile const& p)
                : tls(std::move(t)), hooks(reg, owner, ev), memory(p.transport().native_bytes),
                  app(*tls, hooks, false, memory.http3()), session(*tls, app, local) {}
        };
        struct Factory {
            using Session = Client::QuicSession;
            std::unique_ptr<Bundle> bundle;
            bool joined = false;
            int failure = 0;
            auto admit(nex::ngtcp2::ngtcp2_pkt_hd const&, nex::corosio::endpoint const&, Clock::time_point) const noexcept -> bool { return false; }
            auto create(quic::SessionHandle, Registry&, std::span<std::uint8_t const>, nex::ngtcp2::ngtcp2_pkt_hd const&,
                        nex::corosio::endpoint const&, Clock::time_point) noexcept -> std::expected<Session*, int> {
                return std::unexpected(nex::ngtcp2::err_callback_failure);
            }
            auto application_drained(quic::SessionHandle, Session const&) const noexcept -> bool { return joined; }
            auto failed(quic::SessionHandle, int err) noexcept -> void { failure = err; }
            auto destroy(quic::SessionHandle, Session&) noexcept -> void { bundle.reset(); }
        };

    public:
        using Port = quic::DatagramPort<Factory, 1, 8, 8, true>;
        using Driver = net::DatagramDriver<Port, Socket>;

    private:
        ClientProfile const& profile_;
        Socket socket_;
        nex::corosio::endpoint local_;
        Factory factory_;
        Port port_{factory_};
        Driver driver_{socket_, port_};
        std::optional<quic::SessionHandle> owner_;
        bool started_ = false;

        static auto field(std::string_view k, std::string_view v) noexcept -> nex::nghttp3::nghttp3_nv {
            return {reinterpret_cast<std::uint8_t const*>(k.data()), reinterpret_cast<std::uint8_t const*>(v.data()),
                    k.size(), v.size(), nex::nghttp3::nv_flag_none};
        }

    public:
        Client(nex::corosio::io_context& ctx, ClientProfile const& p) : profile_(p), socket_(ctx) {}
        Client(Client const&) = delete;
        auto operator=(Client const&) -> Client& = delete;
        auto socket() noexcept -> Socket& { return socket_; }

        auto start(nex::corosio::endpoint peer, platform::SocketBinding const* binding = nullptr,
                   quic::EchConfig const* ech = nullptr, std::chrono::nanoseconds keep_alive = {},
                   platform::SocketDeadline deadline = platform::SocketDeadline::max(),std::error_code* socket_error=nullptr)
            -> std::expected<void, std::string> {
            if (started_) return std::unexpected("MASQUE client already started");
            if constexpr (std::same_as<Socket,nex::corosio::udp_socket>) {
                if (auto error=net::prepare_udp_socket(socket_,peer,binding,deadline)) {
                    if (socket_error) *socket_error=error;
                    return std::unexpected(error.message());
                }
            } else if (binding) {
                return std::unexpected("socket binding belongs to the lower datagram transport");
            }
            local_ = socket_.local_endpoint();
            auto reserved = port_.registry().reserve();
            if (!reserved) { socket_.close(); return std::unexpected("MASQUE capacity exhausted"); }
            struct Reservation {
                Client& owner;
                quic::SessionHandle id;
                bool committed = false;
                ~Reservation() {
                    if (committed) return;
                    owner.factory_.bundle.reset();
                    (void)owner.port_.registry().release(id);
                    owner.socket_.close();
                }
            } reservation{*this,*reserved};
            std::array<std::uint8_t, 8> src_bytes{};
            std::array<std::uint8_t, 16> dst_bytes{};
            if (!crypto::random_bytes(src_bytes) || !crypto::random_bytes(dst_bytes) ||
                !port_.registry().insert(*reserved, src_bytes))
                return std::unexpected("cannot create MASQUE QUIC CIDs");
            auto tls=profile_.tls_client(peer,ech);
            if (!tls) return std::unexpected(tls.error());
            auto settings = hysteria2::TransportProfile<4, stream_window>::settings(profile_.transport());
            auto params = hysteria2::TransportProfile<4, stream_window>::parameters(profile_.transport());
            if (!settings || !params) return std::unexpected("invalid MASQUE QUIC options");
            if (deadline!=Clock::time_point::max()) {
                auto now=Clock::now();
                if (now>=deadline) return std::unexpected("MASQUE connection deadline expired");
                auto remaining=std::chrono::duration_cast<std::chrono::nanoseconds>(deadline-now).count();
                settings->handshake_timeout=std::min(settings->handshake_timeout,static_cast<std::uint64_t>(remaining));
            }
            factory_.bundle = std::make_unique<Bundle>(std::move(*tls), port_.registry(), *reserved, driver_.changed(), local_, profile_);
            nex::ngtcp2::ngtcp2_cid src{}, dst{};
            nex::ngtcp2::ngtcp2_cid_init(&src, src_bytes.data(), src_bytes.size());
            nex::ngtcp2::ngtcp2_cid_init(&dst, dst_bytes.data(), dst_bytes.size());
            auto err = factory_.bundle->session.start(false, dst, src, peer, *settings, *params, factory_.bundle->memory.transport(), Clock::now());
            if (err || !port_.attach(*reserved, factory_.bundle->session))
                return std::unexpected("cannot start MASQUE QUIC connection");
            if (keep_alive.count() > 0)
                nexus_ngtcp2_abi::ngtcp2_conn_set_keep_alive_timeout(factory_.bundle->session.transport().native(),
                    static_cast<std::uint64_t>(keep_alive.count()));
            owner_ = *reserved;
            started_ = true;
            reservation.committed = true;
            driver_.notify();
            return {};
        }

        auto run() -> nex::capy::task<nex::capy::results<>> { return driver_.run(); }

#include "client_http.hpp"

        auto request_stop() noexcept -> void {
            if (factory_.bundle) {
                factory_.bundle->hooks.ready = false;
                factory_.bundle->hooks.rx_dgrams.clear();
                factory_.bundle->hooks.tx_dgrams.clear();
            }
            driver_.changed().set();
            driver_.finish();
        }

        auto connect_udp(std::string_view target_host, std::uint16_t target_port, Clock::time_point deadline) -> nex::capy::task<bool> {
            while (factory_.bundle && !factory_.bundle->app.stopping()) {
                if (factory_.bundle->app.can_open()) break;
                driver_.changed().clear();
                auto [err] = co_await nex::corosio::timeout(driver_.changed().wait(), deadline);
                if (err || !driver_.running()) co_return false;
            }
            if (!factory_.bundle || !factory_.bundle->app.can_open()) co_return false;
            std::int64_t id = -1;
            if (nex::ngtcp2::ngtcp2_conn_open_bidi_stream(factory_.bundle->session.transport().native(), &id, nullptr))
                co_return false;
            factory_.bundle->hooks.stream = id;
            std::string encoded_host;
            encoded_host.reserve(target_host.size() * 3);
            for (unsigned char c : target_host) {
                if (c == ':') encoded_host += "%3A";
                else encoded_host.push_back(static_cast<char>(c));
            }
            auto path = std::format("/.well-known/masque/udp/{}/{}/", encoded_host, target_port);
            std::array req{
                field(":method", "CONNECT"),
                field(":protocol", "connect-udp"),
                field(":scheme", "https"),
                field(":authority", profile_.authority()),
                field(":path", path),
                field("proxy-authorization", profile_.authorization()),
                field("capsule-protocol", "?1")
            };
            if (factory_.bundle->app.h3().request(id, req, true)) co_return false;
            driver_.notify();
            while (factory_.bundle && !factory_.bundle->app.stopping()) {
                if (factory_.bundle->hooks.ready) co_return true;
                if (factory_.bundle->hooks.rejected || factory_.bundle->hooks.conn_closed) co_return false;
                driver_.changed().clear();
                auto [err] = co_await nex::corosio::timeout(driver_.changed().wait(), deadline);
                if (err || !driver_.running()) co_return false;
            }
            co_return false;
        }

        auto connect_ip(std::string_view path, Clock::time_point deadline, std::size_t budget = 1350,
            std::string_view protocol="connect-ip",std::span<std::pair<std::string,std::string> const> headers={}) -> nex::capy::task<bool> {
            while (factory_.bundle && !factory_.bundle->app.stopping()) {
                if (factory_.bundle->app.can_open()) break;
                driver_.changed().clear();
                auto [err] = co_await nex::corosio::timeout(driver_.changed().wait(), deadline);
                if (err || !driver_.running()) co_return false;
            }
            if (!factory_.bundle || !factory_.bundle->app.can_open()) co_return false;
            std::int64_t id = -1;
            if (nex::ngtcp2::ngtcp2_conn_open_bidi_stream(factory_.bundle->session.transport().native(), &id, nullptr))
                co_return false;
            factory_.bundle->hooks.stream = id;
            factory_.bundle->hooks.ip_mode = true;
            factory_.bundle->hooks.max_budget = budget;
            std::array req{
                field(":method", "CONNECT"),
                field(":protocol",protocol),
                field(":scheme", "https"),
                field(":authority", profile_.authority()),
                field(":path", path.empty() ? std::string_view{"/.well-known/masque/ip/*/*/"} : path),
                field("proxy-authorization", profile_.authorization()),
                field("capsule-protocol", "?1")
            };
            std::vector<nex::nghttp3::nghttp3_nv> extended;
            std::span<nex::nghttp3::nghttp3_nv const> fields=req;
            if (!headers.empty()) {
                extended.reserve(req.size()+headers.size());
                extended.append_range(req);
                for (auto const& [name,value]:headers) {
                    auto header=field(name,value);
                    header.flags=nex::nghttp3::nv_flag_never_index;
                    extended.push_back(header);
                }
                fields=extended;
            }
            if (factory_.bundle->app.h3().request(id, fields, true)) co_return false;
            driver_.notify();
            while (factory_.bundle && !factory_.bundle->app.stopping()) {
                if (factory_.bundle->hooks.ready) co_return true;
                if (factory_.bundle->hooks.rejected || factory_.bundle->hooks.conn_closed) co_return false;
                driver_.changed().clear();
                auto [err] = co_await nex::corosio::timeout(driver_.changed().wait(), deadline);
                if (err || !driver_.running()) co_return false;
            }
            co_return false;
        }

        auto assigned_addresses() const noexcept -> std::span<AddressEntry const> {
            if (!factory_.bundle) return {};
            auto const& sink = factory_.bundle->hooks.ip_sink;
            return std::span(sink.addresses).first(sink.address_count);
        }
        auto advertised_routes() const noexcept -> std::span<RouteEntry const> {
            if (!factory_.bundle) return {};
            auto const& sink = factory_.bundle->hooks.ip_sink;
            return std::span(sink.routes_list).first(sink.route_count);
        }
        auto address_epoch() const noexcept -> std::uint64_t {
            return factory_.bundle ? factory_.bundle->hooks.ip_sink.epoch : 0;
        }
        auto route_epoch() const noexcept -> std::uint64_t {
            return factory_.bundle ? factory_.bundle->hooks.ip_sink.route_epoch : 0;
        }
        auto discard_ip_datagrams(bool include_received = false) noexcept -> void {
            if (!factory_.bundle || !factory_.bundle->hooks.ip_mode) return;
            auto& hooks = factory_.bundle->hooks;
            hooks.tx_dgrams.clear();
            if (include_received) hooks.rx_dgrams.clear();
            if (hooks.tx_cap_packet && !hooks.tx_cap_submitted) hooks.tx_capsule.clear();
        }
        auto try_receive() noexcept -> std::optional<std::vector<std::uint8_t>> {
            if (!factory_.bundle || factory_.bundle->hooks.rx_dgrams.empty()) return std::nullopt;
            auto pkt = std::move(factory_.bundle->hooks.rx_dgrams.front());
            factory_.bundle->hooks.rx_dgrams.pop_front();
            return pkt;
        }
        auto rx_event() noexcept -> nex::capy::async_event& { return driver_.changed(); }
        auto ready() const noexcept -> bool {
            return factory_.bundle && factory_.bundle->hooks.ready && !factory_.bundle->app.stopping() && driver_.running();
        }

    private:
        auto queue_ip_capsule(std::uint64_t kind, std::span<std::uint8_t const> payload) -> bool {
            auto& bundle = *factory_.bundle;
            auto& hooks = bundle.hooks;
            if (!hooks.tx_capsule.empty()) return false;
            bool packet = kind == datagram_capsule_type;
            std::array<std::uint8_t, 16> prefix{};
            auto length = write_capsule_prefix(prefix, kind, payload.size() + packet);
            if (!length) return false;
            hooks.tx_capsule.reserve(*length + packet + payload.size());
            hooks.tx_capsule.insert(hooks.tx_capsule.end(), prefix.begin(), prefix.begin() + *length);
            if (packet) hooks.tx_capsule.push_back(0);
            hooks.tx_capsule.insert(hooks.tx_capsule.end(), payload.begin(), payload.end());
            hooks.tx_cap_packet = packet;
            if (bundle.app.h3().resume(hooks.stream)) {
                hooks.tx_capsule.clear();
                return false;
            }
            driver_.notify();
            return true;
        }

    public:
        // Request IDs are unique for this CONNECT-IP stream.
        auto request_addresses(bool ipv4, bool ipv6) -> bool {
            if (!ready() || !factory_.bundle->hooks.ip_mode || (!ipv4 && !ipv6)) return false;
            auto& hooks = factory_.bundle->hooks;
            if (hooks.requested_addresses) return false;
            std::array<std::uint8_t, 28> body{};
            std::size_t size = 0;
            for (auto version : {std::uint8_t{4}, std::uint8_t{6}}) {
                if (version == 4 ? !ipv4 : !ipv6) continue;
                auto n = write_address_entry(std::span(body).subspan(size), {version, version, 0, {}}, true);
                if (!n) return false;
                size += *n;
            }
            hooks.requested_addresses = queue_ip_capsule(address_request_capsule, std::span(body).first(size));
            if (hooks.requested_addresses) {
                hooks.ip_sink.requested_v4 = ipv4;
                hooks.ip_sink.requested_v6 = ipv6;
            }
            return hooks.requested_addresses;
        }

        auto send(std::span<std::uint8_t const> payload) -> bool {
            if (!factory_.bundle || !factory_.bundle->hooks.ready)
                return false;
            auto& bundle = *factory_.bundle;
            auto& hooks = bundle.hooks;
            if (hooks.ip_mode && payload.size() >= hooks.max_budget) return false;
            if (hooks.ip_mode && !bundle.app.datagram_fits(hooks.stream, payload.size() + 1)) {
                return queue_ip_capsule(datagram_capsule_type, payload);
            }
            if (hooks.tx_dgrams.size() >= 64) return false;
            std::vector<std::uint8_t> framed;
            framed.reserve(1 + payload.size());
            framed.push_back(0);
            framed.insert(framed.end(), payload.begin(), payload.end());
            hooks.tx_dgrams.push_back({static_cast<std::uint64_t>(hooks.stream), std::move(framed)});
            driver_.notify();
            return true;
        }

        auto receive(Clock::time_point deadline) -> nex::capy::task<std::optional<std::vector<std::uint8_t>>> {
            while (factory_.bundle && !factory_.bundle->app.stopping()) {
                if (!factory_.bundle->hooks.rx_dgrams.empty()) {
                    auto pkt = std::move(factory_.bundle->hooks.rx_dgrams.front());
                    factory_.bundle->hooks.rx_dgrams.pop_front();
                    co_return pkt;
                }
                if (!factory_.bundle->hooks.ready) co_return std::nullopt;
                driver_.changed().clear();
                auto [err] = co_await nex::corosio::timeout(driver_.changed().wait(), deadline);
                if (err || !driver_.running()) co_return std::nullopt;
            }
            co_return std::nullopt;
        }

        auto finish() noexcept -> void {
            factory_.joined = true;
            port_.request_stop();
            driver_.finish();
            port_.stop();
            socket_.close();
            if (owner_) (void)port_.registry().release(*owner_);
            owner_.reset();
            factory_.bundle.reset();
        }
    };
}
