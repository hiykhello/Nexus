export module nexus.test.quic_datagram_link;
import std;
import crypto;
import net.datagram_driver;
import quic.connection;
import nexus.thirdparty.ngtcp2;
import nexus.thirdparty.nghttp3;
import nexus.thirdparty.corosio;
import nexus.test.quic_tls_link;
import nexus.test.http3_link;

export namespace nexus::test::quic_datagram_link {
    namespace n=nex::ngtcp2;
    namespace io=nex::corosio;
    namespace support=nexus::test::quic_tls;
    namespace app=nexus::test::http3_link;
    using Clock=std::chrono::steady_clock;
    inline auto time(Clock::time_point point) noexcept -> std::uint64_t { return std::chrono::duration_cast<std::chrono::nanoseconds>(point.time_since_epoch()).count(); }
    struct Path {
        n::ngtcp2_sockaddr_union local{},remote{};
        n::ngtcp2_path value{};
        auto assign(io::endpoint const& source,io::endpoint const& target) -> void {
            auto convert=[](auto& output,io::endpoint const& input) -> n::ngtcp2_addr {
                auto port=std::bit_cast<std::uint16_t>(std::array<std::uint8_t,2>{static_cast<std::uint8_t>(input.port()>>8),static_cast<std::uint8_t>(input.port())});
                if (input.address().is_v4()) {
                    output.in.sin_family=n::af_inet; output.in.sin_port=port; auto bytes=input.address().to_v4().to_bytes(); std::memcpy(&output.in.sin_addr.s_addr,bytes.data(),4);
                    return {reinterpret_cast<n::ngtcp2_sockaddr*>(&output.in),sizeof(output.in)};
                }
                output.in6.sin6_family=n::af_inet6; output.in6.sin6_port=port; auto bytes=input.address().to_v6().to_bytes(); std::memcpy(output.in6.sin6_addr.s6_addr,bytes.data(),16);
                return {reinterpret_cast<n::ngtcp2_sockaddr*>(&output.in6),sizeof(output.in6)};
            };
            value={convert(local,source),convert(remote,target),nullptr};
        }
    };
    inline auto random_cid() -> n::ngtcp2_cid {
        std::array<std::uint8_t,8> bytes{}; if (!crypto::random_bytes(bytes)) throw std::runtime_error("CID entropy");
        n::ngtcp2_cid out{}; n::ngtcp2_cid_init(&out,bytes.data(),bytes.size()); return out;
    }
    // Test composition only: the production driver consumes these static
    // hooks, while all native TLS/QUIC/H3 algorithms remain the real owners.
    template<class Tls,class Socket=io::udp_socket> struct Endpoint {
        using Failure=int;
        using Driver=net::DatagramDriver<Endpoint,Socket>;
        Socket& socket;
        Tls& tls;
        support::Memory memory;
        app::Application<Tls> app;
        quic::Connection<Tls,app::Application<Tls>> connection;
        Path path;
        io::endpoint local,remote;
        Driver* driver=nullptr;
        bool server=false,started=false,stopping=false,auth_sent=false,get_sent=false,passed=false,close_pending=false;
        bool wait_peer_close=false;
        std::uint64_t token=0,pending_token=0;
        unsigned received=0,transmissions=0,expiries=0;
        std::uint64_t initial_rtt=0;
        Endpoint(Socket& socket,Tls& tls,bool server,io::endpoint const& remote)
            :socket(socket),tls(tls),app(tls),connection(tls,app),local(socket.local_endpoint()),remote(remote),server(server) {
            app.server=server; app.transport=&connection; app.defer_native=true;
        }
        ~Endpoint() { stop(); drain(); }
        auto start(n::ngtcp2_cid const& destination,n::ngtcp2_cid const& source,n::ngtcp2_transport_params const& parameters,Clock::time_point now) -> int {
            path.assign(local,remote); auto settings=support::settings(); settings.initial_ts=time(now);
            if (initial_rtt) settings.initial_rtt=initial_rtt;
            auto error=connection.start(server,destination,source,path.value,settings,parameters,memory.transport()); started=!error; return error;
        }
        auto initialize() -> int { return server ? 0 : start(random_cid(),random_cid(),support::parameters(false),Clock::now()); }
        auto request_stop() noexcept -> void { stopping=true; app.stop_requested=true; app.http3.stop(); }
        auto stop() noexcept -> void { app.io_joined=true; connection.stop(); }
        auto drain() noexcept -> void { app.drain(); }
        auto next_expiry() const noexcept -> net::DatagramDeadline {
            auto expiry=connection.expiry(); if (!expiry || *expiry==std::numeric_limits<std::uint64_t>::max()) return {};
            return Clock::time_point(std::chrono::nanoseconds(*expiry));
        }
        auto expire(Clock::time_point now) -> std::expected<void,int> {
            ++expiries; auto error=connection.expire(time(now)); return error ? std::expected<void,int>(std::unexpected(error)) : std::expected<void,int>{};
        }
        auto receive(io::endpoint const& source,std::span<std::uint8_t const> bytes,Clock::time_point now) -> std::expected<void,int> {
            if (stopping) return {};
            if (!started) {
                n::ngtcp2_pkt_hd first{}; if (n::ngtcp2_accept(&first,bytes.data(),bytes.size()) || first.version!=1) return {};
                remote=source; auto parameters=support::parameters(true); parameters.original_dcid=first.dcid;
                if (auto error=start(first.scid,random_cid(),parameters,now)) return std::unexpected(error);
            }
            if (source!=remote) return {};
            ++received; app.time=time(now); auto error=connection.read(path.value,nullptr,bytes,app.time);
            if (app.stop_requested) { driver->finish(); return {}; }
            if (wait_peer_close && error==n::err_draining && complete()) { passed=true; driver->finish(); return {}; }
            if (error) return std::unexpected(error);
            return {};
        }
        auto complete() -> bool {
            if (!app.authenticated || !app.refs_valid() || app.input!=app.framing+app.payload) return false;
            auto& data=app.slot(4);
            if (server) return data.acked==12000;
            if (!data.fin || data.received!=12000) return false;
            for (std::size_t i=0;i<data.received;++i) if (data.body[i]!=static_cast<std::uint8_t>(i*73)) return false;
            return true;
        }
        auto output(std::span<std::uint8_t> bytes,Clock::time_point now) -> std::expected<std::optional<net::DatagramOutput>,int> {
            if (!started || stopping) return std::optional<net::DatagramOutput>{};
            if (!server && app.completed && !auth_sent) { if (auto error=app::request(*this,true)) return std::unexpected(error); auth_sent=true; }
            if (!server && app.authenticated && !get_sent) { if (auto error=app::request(*this,false)) return std::unexpected(error); get_sent=true; }
            std::size_t size=0;
            if (complete() && !wait_peer_close) {
                passed=true;
                n::ngtcp2_ccerr error{}; n::ngtcp2_ccerr_default(&error); n::ngtcp2_ccerr_set_application_error(&error,nex::nghttp3::h3_no_error,nullptr,0);
                auto written=connection.write_close(bytes,nullptr,nullptr,error,time(now)); if (!written) return std::unexpected(written.error());
                size=*written; close_pending=bool(size);
            } else {
                auto stamp=time(now); auto written=app::write(*this,bytes,stamp,false,0); if (!written) return std::unexpected(written.error()); size=written->bytes;
            }
            if (app.stop_requested) { driver->finish(); return std::optional<net::DatagramOutput>{}; }
            if (!size) return std::optional<net::DatagramOutput>{};
            pending_token=++token; return net::DatagramOutput{remote,size,pending_token};
        }
        auto transmitted(std::uint64_t current,Clock::time_point now) -> std::expected<void,int> {
            if (stopping || !connection.native() || current!=pending_token) return std::unexpected(n::err_callback_failure);
            ++transmissions; n::ngtcp2_conn_update_pkt_tx_time(connection.native(),time(now));
            if (close_pending) driver->finish(); return {};
        }
        auto clean() const noexcept -> bool {
            return !connection.native() && !connection.key_slots() && !memory.used && !app.http3.native() && !app.memory.used && !app.broken &&
                app.quic_closed==(started ? 1u : 0u) && app.http3_closed<=1 && !tls.pending_handshake_bytes();
        }
    };
}
