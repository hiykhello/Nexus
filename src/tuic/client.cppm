export module tuic.client;
import std;
import containers.inplace_vector;
import crypto;
import tuic.wire;
export import tuic.transport_options;
import tuic.application;
export import tuic.stream;
import quic.tls_client;
import quic.optional_client_resumption;
import quic.ech_config;
import quic.transport_memory;
import quic.cid_registry;
import quic.datagram_port;
import quic.datagram_session;
import net.datagram_driver;
import net.udp_connect;
import tls.profiles;
import tls.fingerprint;
import tls.certificate_trust;
import platform.ip_address;
import platform.socket_options;
import ngtcp2;
import capy;
import corosio;

export namespace tuic {
    class ClientProfile {
        tls::ClientProfile tls_;
        std::array<std::uint8_t, 16> uuid_{};
        std::string password_;
        ClientTransportOptions options_;
        tls::Fingerprint fingerprint_ = tls::Fingerprint::native;

#ifdef NEXUS_QUIC_RESUMPTION
        using Tickets=quic::SharedResumptionCache<>;
        mutable Tickets tickets_;
        std::vector<std::span<std::uint8_t const>> anchors_;
#endif

        ClientProfile(tls::ClientProfile tls, std::array<std::uint8_t, 16> uuid, std::string password,
                      ClientTransportOptions opts, tls::Fingerprint fp);

    public:
        ~ClientProfile();
        ClientProfile(ClientProfile const&) = delete;
        auto operator=(ClientProfile const&) -> ClientProfile& = delete;

        class CertificatePolicy {
            ClientProfile const& profile_;
        public:
            explicit CertificatePolicy(ClientProfile const& p) noexcept : profile_(p) {}
            auto operator()(std::span<std::span<std::uint8_t const> const> chain) const
                -> std::expected<void, tls::CertificateTrustError>;
        };

#ifdef NEXUS_QUIC_RESUMPTION
        using Tls=quic::SelectableTlsClient<CertificatePolicy,Tickets>;
#else
        using Tls=quic::TlsClient<CertificatePolicy>;
#endif

        static auto load(
            std::string_view server_name,
            std::string_view ca_file,
            std::string_view uuid_file,
            std::string_view password_file,
            std::uint16_t key_share = 0x001d,
            bool hybrid_only = false,
            ClientTransportOptions options = {},
            tls::Fingerprint fingerprint = tls::Fingerprint::native,
            std::span<std::array<std::uint8_t,32> const> pins = {}) -> std::expected<std::unique_ptr<ClientProfile>, std::string>;

        [[nodiscard]] auto tls_client(corosio::endpoint const& peer,quic::EchConfig const* ech = nullptr) const
            -> std::expected<std::unique_ptr<Tls>, std::string>;
        [[nodiscard]] auto tls_client(quic::EchConfig const* ech = nullptr) const
            -> std::expected<std::unique_ptr<Tls>, std::string> { return tls_client({},ech); }

        auto uuid() const noexcept -> std::array<std::uint8_t, 16> const& { return uuid_; }
        auto password() const noexcept -> std::string_view { return password_; }
        auto transport() const noexcept -> ClientTransportOptions const& { return options_; }
    };

    template<class Socket = corosio::udp_socket>
    class Client {
        using Clock = std::chrono::steady_clock;
        using Registry = quic::CidRegistry<1, 8>;

        struct Hooks {
            Registry& registry;
            quic::SessionHandle owner;
            capy::async_event& changed_event;
            void (*notify_fn)(void*) noexcept = nullptr;
            void* notify_ctx = nullptr;
            std::deque<IncomingUdpPacket> udp_rx;
            containers::inplace_vector<std::uint16_t,256> udp_associations;
            std::uint32_t next_association=1;
            Hooks(Registry& r, quic::SessionHandle h, capy::async_event& ev,
                  void (*nfn)(void*) noexcept = nullptr, void* nctx = nullptr) noexcept
                : registry(r), owner(h), changed_event(ev), notify_fn(nfn), notify_ctx(nctx) {}
            auto changed() noexcept -> void {
                if (notify_fn) notify_fn(notify_ctx);
                else changed_event.set();
            }
            auto authenticated(std::size_t) noexcept -> void {}
            auto connect_stream(StreamHandle, TargetAddress const&) noexcept -> void {}
            auto has_udp(std::uint16_t id) const noexcept -> bool {
                return std::ranges::contains(udp_associations,id);
            }
            auto udp_packet(IncomingUdpPacket pkt) -> void {
                if (udp_rx.size()>=256 || !has_udp(pkt.assoc_id)) return;
                if (std::ranges::count(udp_rx,pkt.assoc_id,&IncomingUdpPacket::assoc_id)<16)
                    udp_rx.push_back(std::move(pkt));
            }
            auto udp_dissociate(std::uint16_t) noexcept -> void {}
            auto transport_closed() noexcept -> void {}
            auto add_connection_id(ngtcp2::ngtcp2_cid const& id, ngtcp2::ngtcp2_stateless_reset_token const&) noexcept -> int {
                return registry.insert(owner, {id.data, id.datalen}) ? 0 : ngtcp2::err_callback_failure;
            }
            auto remove_connection_id(ngtcp2::ngtcp2_cid const& id) noexcept -> int {
                (void)registry.remove(owner, {id.data, id.datalen});
                return 0;
            }
        };

    public:
        using App = Application<ClientProfile::Tls, Hooks, 64, 32768>;
        using Session = quic::DatagramSession<ClientProfile::Tls, App>;

    private:
        struct Bundle {
            std::unique_ptr<ClientProfile::Tls> tls;
            Hooks hooks;
            quic::NativeTransportMemory<> memory;
            App app;
            Session session;
            Bundle(std::unique_ptr<ClientProfile::Tls> t, Registry& reg, quic::SessionHandle owner,
                   capy::async_event& ev, void (*nfn)(void*) noexcept, void* nctx,
                   corosio::endpoint const& local, ClientProfile const& p)
                : tls(std::move(t)), hooks(reg, owner, ev, nfn, nctx), memory(p.transport().native_bytes),
                  app(*tls, hooks, p.uuid(), std::string(p.password())), session(*tls, app, local) {}
        };
        struct Factory {
            using Session = Client::Session;
            std::unique_ptr<Bundle> bundle;
            bool joined = false;
            int failure = 0;
            auto admit(ngtcp2::ngtcp2_pkt_hd const&, corosio::endpoint const&, Clock::time_point) const noexcept -> bool { return false; }
            auto create(quic::SessionHandle, Registry&, std::span<std::uint8_t const>, ngtcp2::ngtcp2_pkt_hd const&,
                        corosio::endpoint const&, Clock::time_point) noexcept -> std::expected<Session*, int> {
                return std::unexpected(ngtcp2::err_callback_failure);
            }
            auto application_drained(quic::SessionHandle, Session const&) const noexcept -> bool { return joined; }
            auto failed(quic::SessionHandle, int err) noexcept -> void { failure = err; }
            auto destroy(quic::SessionHandle, Session&) noexcept -> void { bundle.reset(); }
        };

    public:
        using Port = quic::DatagramPort<Factory, 1, 8, 8, true>;
        using Driver = net::DatagramDriver<Port, Socket>;
        using Channel = TcpStream<App, Driver>;

    private:
        ClientProfile const& profile_;
        Socket socket_;
        corosio::endpoint local_;
        Factory factory_;
        Port port_{factory_};
        Driver driver_{socket_, port_};
        std::optional<quic::SessionHandle> owner_;
        bool started_ = false;

    public:
        Client(corosio::io_context& ctx, ClientProfile const& profile) : profile_(profile), socket_(ctx) {}
        Client(Client const&) = delete;
        auto operator=(Client const&) -> Client& = delete;

        auto socket() noexcept -> Socket& { return socket_; }
        auto driver() noexcept -> Driver& { return driver_; }

        auto start(corosio::endpoint peer, platform::SocketBinding const* binding = nullptr,
                   quic::EchConfig const* ech = nullptr,
                   platform::SocketDeadline deadline = platform::SocketDeadline::max(),std::error_code* socket_error=nullptr)
            -> std::expected<void,std::string> {
            if (started_) return std::unexpected("TUIC client already started");
            if constexpr (std::same_as<Socket, corosio::udp_socket>) {
                if (auto error=net::prepare_udp_socket(socket_,peer,binding,deadline)) {
                    if (socket_error) *socket_error=error;
                    return std::unexpected(error.message());
                }
                local_=socket_.local_endpoint();
            } else if constexpr (requires { socket_.is_layered(); }) {
                if (!socket_.is_layered()) {
                    if (auto error=socket_.prepare_physical(peer,binding,deadline)) {
                        if (socket_error) *socket_error=error;
                        return std::unexpected(error.message());
                    }
                } else if (binding) {
                    return std::unexpected("socket binding belongs to physical datagram transport");
                }
                local_=socket_.local_endpoint();
            } else {
                if (binding) return std::unexpected("socket binding belongs to physical datagram transport");
                local_ = socket_.local_endpoint();
            }
            auto now=Clock::now();
            if (now>=deadline) {socket_.close();return std::unexpected("TUIC connection deadline expired");}
            auto reserved = port_.registry().reserve();
            if (!reserved) { socket_.close(); return std::unexpected("TUIC connection capacity exhausted"); }
            std::array<std::uint8_t, 8> src_bytes{};
            std::array<std::uint8_t, 16> dst_bytes{};
            if (!crypto::random_bytes(src_bytes) || !crypto::random_bytes(dst_bytes) ||
                !port_.registry().insert(*reserved, src_bytes)) {
                (void)port_.registry().release(*reserved);
                socket_.close();
                return std::unexpected("cannot create TUIC QUIC CIDs");
            }
            auto tls = profile_.tls_client(peer,ech);
            if (!tls) {
                (void)port_.registry().release(*reserved);
                socket_.close();
                return std::unexpected(tls.error());
            }
            ngtcp2::ngtcp2_settings settings{};
            ngtcp2::ngtcp2_transport_params params{};
            apply_tuic_quic_config(profile_.transport(), 64, 32768, settings, params);
            if (deadline!=Clock::time_point::max()) {
                auto remaining=std::chrono::duration_cast<std::chrono::nanoseconds>(deadline-now).count();
                settings.handshake_timeout=std::min(settings.handshake_timeout,static_cast<std::uint64_t>(remaining));
            }
            factory_.bundle = std::make_unique<Bundle>(
                std::move(*tls), port_.registry(), *reserved, driver_.changed(),
                [](void* p) noexcept { static_cast<Driver*>(p)->notify(); }, &driver_, local_, profile_);
            ngtcp2::ngtcp2_cid src{}, dst{};
            ngtcp2::ngtcp2_cid_init(&src, src_bytes.data(), src_bytes.size());
            ngtcp2::ngtcp2_cid_init(&dst, dst_bytes.data(), dst_bytes.size());
            auto err = factory_.bundle->session.start(false, dst, src, peer, settings, params, factory_.bundle->memory.transport(), Clock::now());
            if (err || !port_.attach(*reserved, factory_.bundle->session)) {
                factory_.bundle.reset();
                (void)port_.registry().release(*reserved);
                socket_.close();
                return std::unexpected("cannot start TUIC QUIC connection");
            }
            auto heartbeat=std::chrono::duration_cast<std::chrono::nanoseconds>(profile_.transport().heartbeat).count();
            ngtcp2_abi::ngtcp2_conn_set_keep_alive_timeout(factory_.bundle->session.transport().native(),
                static_cast<std::uint64_t>(heartbeat));
            owner_ = *reserved;
            started_ = true;
            driver_.notify();
            return {};
        }

        auto run() -> capy::task<capy::results<>> { return driver_.run(); }

        auto ready(Clock::time_point deadline) -> capy::task<bool> {
            while (factory_.bundle && !factory_.bundle->app.stopping()) {
                if (factory_.bundle->app.authenticated()) co_return true;
                driver_.changed().clear();
                auto [err] = co_await corosio::timeout(driver_.changed().wait(), deadline);
                if (err || !driver_.running()) co_return false;
            }
            co_return false;
        }

        auto open_channel(TargetAddress const& target) -> std::expected<std::unique_ptr<Channel>, std::string> {
            if (!factory_.bundle) return std::unexpected("TUIC client not ready");
            auto h = factory_.bundle->app.open_connect(target);
            if (!h) return std::unexpected("failed opening TUIC TCP stream");
            driver_.notify();
            return std::make_unique<Channel>(factory_.bundle->app, driver_, *h);
        }

        auto open_udp() noexcept -> std::optional<std::uint16_t> {
            if (!active()) return {};
            auto& hooks=factory_.bundle->hooks;
            if (hooks.udp_associations.size()==hooks.udp_associations.capacity()) return {};
            if (hooks.next_association>65535) return {};
            auto id=static_cast<std::uint16_t>(hooks.next_association++);
            hooks.udp_associations.push_back(id);
            return id;
        }

        auto send_udp(std::uint16_t assoc_id, TargetAddress const& target, std::span<std::uint8_t const> payload) -> bool {
            if (!factory_.bundle) return false;
            auto& bundle=*factory_.bundle;
            auto& hooks=bundle.hooks;
            auto known=hooks.has_udp(assoc_id);
            if (!known && (assoc_id<hooks.next_association ||
                hooks.udp_associations.size()==hooks.udp_associations.capacity())) return false;
            if (!bundle.app.send_udp(assoc_id,target,payload,profile_.transport().udp_over_stream)) return false;
            if (!known) {
                hooks.udp_associations.push_back(assoc_id);
                hooks.next_association=std::max(hooks.next_association,std::uint32_t(assoc_id)+1);
            }
            driver_.notify();
            return true;
        }

        auto take_udp(std::optional<std::uint16_t> assoc_id={}) noexcept -> std::optional<IncomingUdpPacket> {
            if (!factory_.bundle) return {};
            auto& queue=factory_.bundle->hooks.udp_rx;
            auto selected=assoc_id ? std::ranges::find(queue,*assoc_id,&IncomingUdpPacket::assoc_id) : queue.begin();
            if (selected==queue.end()) return {};
            auto packet=std::move(*selected);
            queue.erase(selected);
            return packet;
        }

        auto wait_udp(Clock::time_point deadline,std::optional<std::uint16_t> assoc_id={})
            -> capy::task<std::optional<IncomingUdpPacket>> {
            while (active()) {
                if (assoc_id && !factory_.bundle->hooks.has_udp(*assoc_id)) co_return std::nullopt;
                if (auto packet=take_udp(assoc_id)) co_return packet;
                driver_.changed().clear();
                auto [error]=co_await corosio::timeout(driver_.changed().wait(),deadline);
                if (error) break;
            }
            co_return std::nullopt;
        }

        auto dissociate(std::uint16_t assoc_id) -> bool {
            if (!factory_.bundle) return false;
            auto& bundle=*factory_.bundle;
            containers::erase(bundle.hooks.udp_associations,assoc_id);
            std::erase_if(bundle.hooks.udp_rx,[assoc_id](auto const& packet){return packet.assoc_id==assoc_id;});
            bundle.hooks.changed();
            auto queued=bundle.app.send_dissociate(assoc_id);
            if (queued) driver_.notify();
            return queued;
        }

        auto active() const noexcept -> bool {
            return factory_.bundle && !factory_.bundle->app.stopping() && driver_.running();
        }

        auto retryable_handshake(Clock::time_point deadline) const noexcept -> bool {
            if (factory_.bundle && factory_.bundle->tls->complete()) return false;
            if (factory_.failure) return factory_.failure==ngtcp2::err_handshake_timeout;
            auto const& failure=driver_.failure();
            if (!failure) return Clock::now()>=deadline;
            auto* socket=std::get_if<net::DatagramFailure>(&*failure);
            return socket && (platform::network::retry_interface_error(socket->system) ||
                socket->system==std::errc::connection_refused);
        }

        auto retired() const noexcept -> bool {
            return factory_.bundle && factory_.bundle->app.stopping();
        }

        auto clear_udp_sessions() noexcept -> void {
            if (!factory_.bundle) return;
            factory_.bundle->hooks.udp_associations.clear();
            factory_.bundle->hooks.udp_rx.clear();
            factory_.bundle->hooks.changed();
        }
        auto begin_shutdown() noexcept -> void {
            // The worker may still have channel readers unwinding. Keep
            // their application object alive until the worker is destroyed.
            clear_udp_sessions();
            driver_.finish();
        }
        auto shutdown_drained() const noexcept -> bool { return port_.drained(); }
        auto shutdown_failed() const noexcept -> bool { return factory_.failure != 0; }
        auto finish() noexcept -> void {
            clear_udp_sessions();
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
