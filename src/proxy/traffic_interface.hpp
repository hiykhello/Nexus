// Declarations included inside the proxy module.
#pragma once

    export struct TrafficBytes {
        std::uint64_t upload=0,download=0;
    };
    export enum class TrafficProtocol {
        socks5, http_connect, http_forward, socks_udp, trojan, shadowsocks, vless,
        grpc_vless, anytls, snell, shadowtls, hysteria2, tuic,
        trojan_udp, shadowsocks_uot, anytls_uot, snell_udp, hysteria2_udp, tun_tcp, tun_udp, tuic_udp, shadowsocks_udp, xudp, masque_udp, masque_ip, redirect, tproxy, tproxy_udp, fixed_tcp,
        naive, http3_connect, http3_udp
    };
    export [[nodiscard]] auto traffic_protocol_name(TrafficProtocol) noexcept -> std::string_view;
    export enum class ConnectPath { dialing, direct, tunnel, datagrams };
    export enum class TrafficCloseRequest { queued, missing, unavailable };
    export struct TransparentDatagram {
        net::UdpEndpoint original_destination;
        std::uint32_t ingress_ifindex=0;
    };
    export enum class TrafficRouteMode { indexed, ordered };
    export struct TrafficRoute {
        TrafficRouteMode mode;
        std::size_t outbound;
        std::optional<std::size_t> rule;
        std::optional<std::size_t> predicate;
        net::UdpEndpoint target;
        auto operator==(TrafficRoute const&) const -> bool = default;
    };
    export struct ActiveConnection {
        std::uint64_t id=0;
        std::optional<net::UdpEndpoint> source;
        std::uint16_t destination_port=0;
        Clock::time_point started;
        TrafficProtocol protocol=TrafficProtocol::socks5;
        ConnectPath path=ConnectPath::dialing;
        TrafficBytes bytes;
        bool can_close=false;
        std::optional<std::uint32_t> source_uid;
        std::string process_path;
        std::string inbound_name;
        std::optional<TransparentDatagram> transparent_datagram;
        std::uint64_t route_generation=0;
        std::optional<TrafficRoute> route;
    };
    export struct TrafficSnapshot {
        TrafficBytes bytes;
        std::vector<ActiveConnection> active;
    };
    class TrafficRegistry {
    public:
        struct Slot {
            ActiveConnection connection;
            std::size_t active_index=0;
            std::atomic<ConnectPath> path{ConnectPath::dialing};
            std::atomic_bool close_requested{false};
            std::atomic<std::uint64_t> upload{0},download{0};
            auto bytes() const noexcept -> TrafficBytes;
        };
        explicit TrafficRegistry(std::size_t);
        auto add(ActiveConnection) -> Slot*;
        auto remove(Slot&) noexcept -> void;
        auto record_route(Slot&,TrafficRoute,ConnectPath) noexcept -> void;
        auto snapshot() const -> TrafficSnapshot;
        auto request_close(std::uint64_t id) -> TrafficCloseRequest;
    private:
        mutable std::mutex mutex_;
        std::vector<Slot> slots_;
        std::vector<Slot*> free_,active_;
        TrafficBytes finished_;
        std::uint64_t next_id_=1;
    };

    export class TrafficRegistration {
        friend class Server;
        friend struct Session;
        TrafficRegistry* registry_=nullptr;
        TrafficRegistry::Slot* slot_=nullptr;
        explicit TrafficRegistration(TrafficRegistry* registry) noexcept : registry_(registry) {}
        auto begin(std::optional<net::UdpEndpoint>,std::uint16_t,TrafficProtocol,Clock::time_point,
            bool can_close=false,std::optional<std::uint32_t> source_uid={},std::string_view process_path={},
            std::optional<TransparentDatagram> transparent_datagram={},std::uint64_t route_generation=0,
            std::string_view inbound_name={}) -> void;
        auto reset() noexcept -> void;
    public:
        TrafficRegistration()=default;
        TrafficRegistration(TrafficRegistration&&) noexcept;
        auto operator=(TrafficRegistration&&) noexcept -> TrafficRegistration&;
        TrafficRegistration(TrafficRegistration const&)=delete;
        auto operator=(TrafficRegistration const&) -> TrafficRegistration& =delete;
        ~TrafficRegistration();
        [[nodiscard]] auto close_requested() const noexcept -> bool {
            return slot_ && slot_->close_requested.load(std::memory_order_relaxed);
        }
        auto select_path(ConnectPath path) noexcept -> void {
            if (slot_) slot_->path.store(path,std::memory_order_relaxed);
        }
        auto count(bool upstream,std::size_t bytes) noexcept -> void {
            if (slot_) {
                auto& counter=upstream ? slot_->upload : slot_->download;
                counter.fetch_add(bytes,std::memory_order_relaxed);
            }
        }
    };
