export module wireguard.tun;
import std;
import packet.fd;
import packet.tun_linux;
import wireguard;
import wireguard.crypto;
import wireguard.port_types;
import wireguard.packet_link;

export namespace wireguard {
    // One nonpersistent TUN device plus a stable borrowed UDP port. This is an
    // L3 path: the OS owns TCP/UDP; no userspace NAT or TCP stack is involved.
    template<class Port> class LinuxTunPort {
        using Link=PortPacketLink<Port>;
        using Pump=packet::StaticFdPump<Link,Port::packet_bytes>;
    public:
        using Failure=std::variant<packet::TunFailure,typename Pump::Failure,PortFailure>;
        struct Progress { PortProgress network; typename Pump::Step device; };
        class ConstructionKey { friend class LinuxTunPort; ConstructionKey()=default; public: ConstructionKey(ConstructionKey&&)=default; };
    private:
        union PumpSlot {
            Pump value;
            PumpSlot() noexcept {}
            ~PumpSlot() noexcept {}
        };
        packet::LinuxTun tun_;
        Port* port_;
        Link link_;
        PumpSlot pump_;
        bool pump_active_=false;
        bool network_claimed_=false;
        struct Prepared { packet::LinuxTun tun; typename Pump::Setup pump; };
        static auto prepare(Port& port,std::string_view name,std::size_t mtu) -> std::expected<Prepared,Failure> {
            if (!port.opened() || port.stopped()) return std::unexpected(Failure{PortFailure{.code=port.stopped() ? PortError::closed : PortError::not_open}});
            if (mtu<68 || mtu>Port::packet_bytes-transport_overhead)
                return std::unexpected(Failure{typename Pump::Failure{packet::FdError::invalid_limit}});
            auto tun=packet::LinuxTun::create(name);
            if (!tun) return std::unexpected(Failure{tun.error()});
            auto setup=Pump::prepare(tun->native_handle(),mtu);
            if (!setup) return std::unexpected(Failure{setup.error()});
            return Prepared{std::move(*tun),std::move(*setup)};
        }
    public:
        LinuxTunPort(ConstructionKey,packet::LinuxTun tun,typename Pump::Setup setup,Port& port) noexcept
            : tun_(std::move(tun)),port_(&port),link_(port) {
            std::construct_at(&pump_.value,std::move(setup),link_);
            pump_active_=true;
        }
        ~LinuxTunPort() { stop(); }
        LinuxTunPort(LinuxTunPort const&)=delete;
        auto operator=(LinuxTunPort const&) -> LinuxTunPort& = delete;
        LinuxTunPort(LinuxTunPort&&)=delete;
        auto operator=(LinuxTunPort&&) -> LinuxTunPort& = delete;
        // The caller configures MTU, addresses and routes in its namespace.
        // Port must outlive this owner. Stopping this adapter also stops Port.
        [[nodiscard]] static auto create(Port& port,std::string_view name={},std::size_t mtu=1420) -> std::expected<LinuxTunPort,Failure> {
            auto setup=prepare(port,name,mtu); if (!setup) return std::unexpected(setup.error());
            return std::expected<LinuxTunPort,Failure>(std::in_place,ConstructionKey{},std::move(setup->tun),std::move(setup->pump),port);
        }
        [[nodiscard]] static auto emplace_into(std::optional<LinuxTunPort>& target,Port& port,std::string_view name={},std::size_t mtu=1420)
            -> std::expected<void,Failure> {
            if (target) return std::unexpected(Failure{PortFailure{.code=PortError::configuration}});
            auto setup=prepare(port,name,mtu); if (!setup) return std::unexpected(setup.error());
            target.emplace(ConstructionKey{},std::move(setup->tun),std::move(setup->pump),port); return {};
        }
        // The sealed token borrows this stable private owner. A network lease
        // must finish before this adapter is destroyed; no mutable owner leaks.
        [[nodiscard]] auto claim_network() & -> std::expected<packet::LinuxTun::NetworkToken,packet::TunFailure> {
            if (!pump_active_) return std::unexpected(packet::TunFailure{packet::TunError::invalid_device});
            auto token=tun_.claim_network();
            if (token) network_claimed_=true;
            return token;
        }
        auto claim_network() && -> std::expected<packet::LinuxTun::NetworkToken,packet::TunFailure> = delete;
        [[nodiscard]] auto step(Clock::time_point now,std::chrono::system_clock::time_point wall) -> std::expected<Progress,Failure> {
            if (!pump_active_) return std::unexpected(Failure{PortFailure{.code=PortError::closed}});
            auto network=port_->poll(now,wall);
            if (!network) {
                auto failure=network.error();
                if (network_claimed_) quiesce();
                else stop();
                return std::unexpected(Failure{std::move(failure)});
            }
            link_.time(now);
            auto device=pump_.value.step();
            if (device.input_delivered || port_->delivery_packets()) network->next_poll=now;
            return Progress{std::move(*network),std::move(device)};
        }
        [[nodiscard]] auto name() const noexcept -> std::string_view { return tun_.name(); }
        [[nodiscard]] auto native_handle() const noexcept -> int { return tun_.native_handle(); }
        [[nodiscard]] auto pending() const noexcept -> bool { return pump_active_ && pump_.value.pending(); }
        // Revoke data-plane work and fd borrowing while the lease still holds
        // the device for checked route/address cleanup.
        auto quiesce() noexcept -> void {
            port_->stop();
            if (pump_active_) {
                pump_.value.clear();
                std::destroy_at(&pump_.value);
                pump_active_=false;
            }
        }
        auto stop() noexcept -> void {
            quiesce();
            tun_.close();
        }
        [[nodiscard]] auto drained() noexcept -> bool { return !pump_active_ && tun_.native_handle()<0 && port_->drained(); }
    };
}
