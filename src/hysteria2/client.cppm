export module hysteria2.client;
import std;
import crypto;
import hysteria2.client_profile;
import quic.ech_config;
import hysteria2.auth;
import hysteria2.application;
import hysteria2.stream_state;
import hysteria2.tcp_channel;
import hysteria2.sessions;
import hysteria2.fragments;
import hysteria2.transport_options;
import hysteria2.salamander;
import hysteria2.udp_receiver;
import hysteria2.udp_transmitter;
import quic.native_memory;
import quic.cid_registry;
import quic.datagram_port;
import quic.datagram_session;
import net.datagram_driver;
import net.udp_connect;
import platform.socket_options;
import nexus.thirdparty.ngtcp2;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

export namespace hysteria2 {
    // One executor owns this connection, its driver and all borrowed channels.
    // The caller runs the driver and joins channel work before joined().
    template<class Socket>
    class BasicClient {
        using Clock=std::chrono::steady_clock;
        using Registry=quic::CidRegistry<1,8>;
        struct Hooks {
            Registry& registry;
            quic::SessionHandle owner;
            nex::capy::async_event& changed_event;
            UdpTransmitter transmitter;
            UdpReceiver<Hooks,64,16,8> receiver;
            std::optional<UdpSessionHandle> sending;
            Hooks(Registry& r,quic::SessionHandle h,nex::capy::async_event& event)
                :registry(r),owner(h),changed_event(event),receiver(*this,false) {}
            auto changed() noexcept -> void {changed_event.set();}
            auto stopping() noexcept -> void {receiver.close();transmitter.cancel();sending.reset();}
            auto authenticate(ClientAuthView) noexcept -> bool {return false;}
            auto session_created(UdpSessionHandle,std::uint32_t) noexcept -> bool {return true;}
            auto session_closed(UdpSessionHandle owner,std::uint32_t) noexcept -> void {
                if (sending && *sending==owner && transmitter.busy()) transmitter.cancel();
                if (sending && *sending==owner) sending.reset();
                changed();
            }
            auto datagram(std::span<std::uint8_t const> wire) noexcept -> int {
                (void)receiver.receive(wire,Clock::now());changed();return 0;
            }
            auto datagram_output() noexcept -> std::optional<UdpWriteView> {return transmitter.pending();}
            auto datagram_accepted() noexcept -> void {(void)transmitter.accepted();if (!transmitter.busy()) sending.reset();changed();}
            auto datagram_rejected() noexcept -> void {transmitter.cancel();sending.reset();changed();}
            auto add_connection_id(nex::ngtcp2::ngtcp2_cid const& id,nex::ngtcp2::ngtcp2_stateless_reset_token const&) noexcept -> int {
                return registry.insert(owner,{id.data,id.datalen}) ? 0 : nex::ngtcp2::err_callback_failure;
            }
            auto remove_connection_id(nex::ngtcp2::ngtcp2_cid const& id) noexcept -> int {
                (void)registry.remove(owner,{id.data,id.datalen});return 0;
            }
        };
    public:
        using ApplicationType=Application<ClientProfile::Tls,Hooks,16,16384>;
        using Session=quic::DatagramSession<ClientProfile::Tls,ApplicationType>;
    private:
        struct Bundle {
            std::unique_ptr<ClientProfile::Tls> tls;
            Hooks hooks;
            quic::NativeMemory<> memory;
            ApplicationType application;
            Session session;
            Bundle(std::unique_ptr<ClientProfile::Tls> value,Registry& registry,quic::SessionHandle owner,
                nex::capy::async_event& changed,nex::corosio::endpoint const& local,ClientProfile const& profile)
                :tls(std::move(value)),hooks(registry,owner,changed),memory(profile.transport().native_bytes),
                 application(*tls,hooks,false,memory.http3(),profile.credential(),ServerAuth{false,true,0},
                     profile.transport().congestion,profile.transport().receive_windows.max_stream),session(*tls,application,local) {}
        };
        struct Factory {
            using Session=typename BasicClient::Session;
            std::unique_ptr<Bundle> bundle;
            bool business_joined=false;
            int failure=0;
            auto admit(nex::ngtcp2::ngtcp2_pkt_hd const&,nex::corosio::endpoint const&,Clock::time_point) const noexcept -> bool {return false;}
            auto create(quic::SessionHandle,Registry&,std::span<std::uint8_t const>,nex::ngtcp2::ngtcp2_pkt_hd const&,
                nex::corosio::endpoint const&,Clock::time_point) noexcept -> std::expected<Session*,int> {
                return std::unexpected(nex::ngtcp2::err_callback_failure);
            }
            auto application_drained(quic::SessionHandle,Session const&) const noexcept -> bool {return business_joined;}
            auto failed(quic::SessionHandle,int error) noexcept -> void {failure=error;}
            auto destroy(quic::SessionHandle,Session&) noexcept -> void {bundle.reset();}
        };
    public:
        using Port=quic::DatagramPort<Factory,1,8,8,true>;
        using Driver=net::DatagramDriver<SalamanderPort<Port>,Socket>;
        using Channel=TcpChannel<ApplicationType,Driver>;
    private:
        ClientProfile const& profile_;
        Socket socket_;
        nex::corosio::endpoint local_;
        Factory factory_;
        Port port_{factory_};
        SalamanderPort<Port> wire_{port_,profile_.transport().salamander_password};
        Driver driver_{socket_,wire_};
        std::optional<quic::SessionHandle> owner_;
        bool started_=false;
    public:
        BasicClient(nex::corosio::io_context& context,ClientProfile const& profile):profile_(profile),socket_(context) {}
        BasicClient(BasicClient const&)=delete;
        auto operator=(BasicClient const&) -> BasicClient& = delete;
        auto socket() noexcept -> Socket& {return socket_;}
        // The parent profile outlives this object, and no channel may outlive it.
        auto start(nex::corosio::endpoint peer, platform::SocketBinding const* binding = nullptr,
                   quic::EchConfig const* ech = nullptr,
                   platform::SocketDeadline deadline = platform::SocketDeadline::max(),
                   std::error_code* socket_error = nullptr,
                   ClientProfile::Tickets* tickets = nullptr) -> std::expected<void,std::string> {
            if (started_) return std::unexpected("Hysteria2 client already started");
            if constexpr(std::same_as<Socket,nex::corosio::udp_socket>) {
                if (auto error=net::prepare_udp_socket(socket_,peer,binding,deadline)) {
                    if (socket_error) *socket_error=error;
                    return std::unexpected(error.message());
                }
                local_=socket_.local_endpoint();
            } else {
                if (binding) return std::unexpected("socket binding belongs to the lower datagram transport");
                local_=socket_.local_endpoint();
            }
            auto reserved=port_.registry().reserve();
            if (!reserved) {socket_.close();return std::unexpected("Hysteria2 connection capacity exhausted");}
            struct Reservation {
                BasicClient& owner;quic::SessionHandle id;bool committed=false;
                ~Reservation() {
                    if (committed) return;
                    owner.factory_.bundle.reset();
                    (void)owner.port_.registry().release(id);
                    owner.socket_.close();
                }
            } reservation{*this,*reserved};
            std::array<std::uint8_t,8> source_bytes{};std::array<std::uint8_t,16> destination_bytes{};
            if (!crypto::random_bytes(source_bytes) || !crypto::random_bytes(destination_bytes) || !port_.registry().insert(*reserved,source_bytes))
                return std::unexpected("cannot create QUIC connection identifiers");
            auto tls=profile_.tls_client(peer,ech,tickets);if (!tls) return std::unexpected(tls.error());
            auto settings=TransportProfile<16,16384>::settings(profile_.transport());
            auto parameters=TransportProfile<16,16384>::parameters(profile_.transport());
            if (!settings || !parameters) return std::unexpected("invalid QUIC transport configuration");
            factory_.bundle=std::make_unique<Bundle>(std::move(*tls),port_.registry(),*reserved,driver_.changed(),local_,profile_);
            nex::ngtcp2::ngtcp2_cid source{},destination{};
            nex::ngtcp2::ngtcp2_cid_init(&source,source_bytes.data(),source_bytes.size());
            nex::ngtcp2::ngtcp2_cid_init(&destination,destination_bytes.data(),destination_bytes.size());
            auto now=Clock::now();
            if (now>=deadline) return std::unexpected("Hysteria2 connection deadline expired");
            if (deadline!=platform::SocketDeadline::max())
                settings->handshake_timeout=std::min(settings->handshake_timeout,static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::nanoseconds>(deadline-now).count()));
            auto error=factory_.bundle->session.start(false,destination,source,peer,*settings,*parameters,factory_.bundle->memory.transport(),now);
            if (error || !port_.attach(*reserved,factory_.bundle->session)) return std::unexpected("cannot initialize Hysteria2 QUIC connection");
            if (!profile_.transport().port_ranges.empty()) {
                std::vector<std::pair<std::uint16_t,std::uint16_t>> ranges;
                ranges.reserve(profile_.transport().port_ranges.size());
                for (auto const& r : profile_.transport().port_ranges) ranges.emplace_back(r.first,r.last);
                wire_.configure_hopping(peer.port(),ranges,profile_.transport().hop_interval,now);
            }
            reservation.committed=true;
            owner_=*reserved;started_=true;driver_.notify();return {};
        }
        auto run() -> nex::capy::task<nex::capy::results<>> {return driver_.run();}
        auto ready(Clock::time_point deadline) -> nex::capy::task<bool> {
            while (factory_.bundle && !factory_.bundle->application.stopping()) {
                if (factory_.bundle->application.authenticated()) co_return true;
                driver_.changed().clear();
                auto [error]=co_await nex::corosio::timeout(driver_.changed().wait(),deadline);
                if (error || !driver_.running()) co_return false;
            }
            co_return false;
        }
        [[nodiscard]] auto retryable_handshake(Clock::time_point deadline) const noexcept -> bool {
            if (factory_.bundle && factory_.bundle->application.handshake_complete()) return false;
            if (factory_.failure) return factory_.failure==nex::ngtcp2::err_handshake_timeout;
            auto const& failure=driver_.failure();
            if (!failure) return Clock::now()>=deadline;
            auto* socket=std::get_if<net::DatagramFailure>(&*failure);
            return socket && (platform::network::retry_interface_error(socket->system) ||
                socket->system==std::errc::connection_refused);
        }
        auto open_tcp(std::string_view destination) -> std::expected<StreamHandle,ApplicationError> {
            if (!factory_.bundle) return std::unexpected(ApplicationError::state);
            auto stream=factory_.bundle->application.open(destination);if (stream) driver_.notify();return stream;
        }
        auto application() noexcept -> ApplicationType& {return factory_.bundle->application;}
        auto driver() noexcept -> Driver& {return driver_;}
        auto open_udp(std::uint32_t id) noexcept -> std::expected<UdpSessionHandle,UdpSessionError> {
            if (!profile_.transport().udp || !factory_.bundle || !factory_.bundle->application.authenticated() ||
                !factory_.bundle->application.peer_auth()->udp || !factory_.bundle->application.datagram_budget())
                return std::unexpected(UdpSessionError::expired);
            auto& receiver=factory_.bundle->hooks.receiver;
            auto now=Clock::now();(void)receiver.expire(now);return receiver.open(id,now);
        }
        // Address and payload are borrowed until udp_sent() reports completion
        // or the ticket is canceled; only one submission may be active.
        auto submit_udp(UdpSessionHandle owner,std::uint16_t packet,std::string_view address,
            std::span<std::uint8_t const> payload) noexcept -> std::expected<UdpSendTicket,UdpSendError> {
            if (!factory_.bundle) return std::unexpected(UdpSendError::state);
            auto& bundle=*factory_.bundle;auto now=Clock::now();
            auto id=bundle.hooks.receiver.id(owner);
            if (!id || !bundle.hooks.receiver.live(owner,now) || !bundle.hooks.receiver.open(*id,now))
                return std::unexpected(UdpSendError::state);
            auto budget=bundle.application.datagram_budget();
            if (!budget) return std::unexpected(UdpSendError::state);
            auto ticket=bundle.hooks.transmitter.submit(*id,packet,address,payload,budget);
            if (ticket) {bundle.hooks.sending=owner;driver_.notify();}
            return ticket;
        }
        auto udp_sent(UdpSendTicket ticket) const noexcept -> std::expected<bool,UdpSendError> {
            if (!factory_.bundle) return std::unexpected(UdpSendError::state);
            return factory_.bundle->hooks.transmitter.done(ticket);
        }
        auto cancel_udp_send() noexcept -> void {
            if (!factory_.bundle) return;
            factory_.bundle->hooks.transmitter.cancel();factory_.bundle->hooks.sending.reset();driver_.notify();
        }
        // A returned packet borrows storage until consume_udp() or expiration.
        auto udp_packet() noexcept -> std::optional<ReassembledPacket> {
            return factory_.bundle ? factory_.bundle->hooks.receiver.packet(Clock::now()) : std::nullopt;
        }
        auto consume_udp() noexcept -> bool {return factory_.bundle && factory_.bundle->hooks.receiver.consume();}
        auto close_udp(UdpSessionHandle owner) noexcept -> bool {
            return factory_.bundle && factory_.bundle->hooks.receiver.release(owner,Clock::now());
        }
        auto maintain_udp() noexcept -> void {
            if (factory_.bundle) (void)factory_.bundle->hooks.receiver.expire(Clock::now());
        }
        // Keep the driver alive while a single CONNECTION_CLOSE is committed.
        // The owner bounds this wait and calls finish() on timeout or error.
        auto begin_shutdown() noexcept -> void {port_.begin_shutdown();driver_.notify();}
        auto shutdown_drained() const noexcept -> bool {return port_.quiescent();}
        auto shutdown_failed() const noexcept -> bool {return port_.shutdown_unsent() || port_.shutdown_failure().has_value() || driver_.failure().has_value();}
        auto finish() noexcept -> void {
            if (factory_.bundle) {
                factory_.bundle->hooks.receiver.close();
                factory_.bundle->hooks.transmitter.cancel();
                factory_.bundle->hooks.sending.reset();
            }
            driver_.changed().set();
            driver_.finish();
        }
        auto stop() noexcept -> void {finish();}
        // Call after all channel/packet borrowers have completed or canceled.
        auto joined() noexcept -> void {
            factory_.business_joined=true;
            if (!driver_.running()) {port_.stop();port_.drain();}
            else port_.maintain();
        }
        // The caller must also join any scheduled run() task before destruction.
        auto drained() const noexcept -> bool {return !driver_.running() && port_.drained();}
        auto native_failure() const noexcept -> int {return factory_.failure;}
    };
    using Client=BasicClient<nex::corosio::udp_socket>;
}
