export module test.hysteria2_application_link;
import std;
import crypto;
import hysteria2.application;
import hysteria2.auth;
import hysteria2.stream_state;
import hysteria2.wire;
import hysteria2.tcp_channel;
import net.datagram_driver;
import quic.connection;
import quic.tls_client;
import quic.tls_server;
import tls.server_credential;
import ngtcp2;
import capy;
import corosio;
import test.quic_tls_link;
import test.quic_datagram_link;


export namespace test::hysteria2_application_link {
namespace n = ::ngtcp2;
namespace q=quic;
namespace h=hysteria2;
namespace io = ::corosio;
namespace capy = ::capy;
namespace support=test::quic_tls;
namespace udp=test::quic_datagram_link;
using namespace std::chrono_literals;
using Clock=std::chrono::steady_clock;

struct Hooks {
    capy::async_event work;
    bool allow=true;
    auto changed() noexcept -> void { work.set(); }
    auto authenticate(h::ClientAuthView auth) noexcept -> bool { return allow && ::crypto::constant_time_equal(support::bytes(auth.credential),support::bytes("test-password")); }
    auto datagram(std::span<std::uint8_t const>) noexcept -> int { return 0; }
};
template<class Tls> struct Endpoint {
    using Failure=int;
    using App=h::Application<Tls,Hooks,4,16384>;
    using Driver=net::DatagramDriver<Endpoint>;
    io::udp_socket& socket;
    Tls& tls;
    Hooks hooks;
    support::Memory memory,h3memory;
    App app;
    q::Connection<Tls,App> connection;
    udp::Path path;
    io::endpoint local,remote;
    Driver* driver=nullptr;
    bool server,started=false,stopping=false,passed=false,close_pending=false;
    std::uint64_t token=0;
    unsigned sent=0,received=0;
    Endpoint(io::udp_socket& socket,Tls& tls,bool server,io::endpoint remote)
        :socket(socket),tls(tls),app(tls,hooks,server,h3memory.http3(),"test-password"),connection(tls,app),local(socket.local_endpoint()),remote(remote),server(server) { app.attach(connection); }
    ~Endpoint() { stop(); drain(); }
    auto start(n::ngtcp2_cid const& destination,n::ngtcp2_cid const& source,n::ngtcp2_transport_params parameters,Clock::time_point now) -> int {
        path.assign(local,remote); auto settings=support::settings(); settings.initial_ts=udp::time(now);
        parameters.initial_max_stream_data_bidi_local=parameters.initial_max_stream_data_bidi_remote=16384;
        parameters.initial_max_streams_bidi=4;
        auto error=connection.start(server,destination,source,path.value,settings,parameters,memory.transport()); started=!error; return error;
    }
    auto initialize() -> int { return server ? 0 : start(udp::random_cid(),udp::random_cid(),support::parameters(false),Clock::now()); }
    auto request_stop() noexcept -> void { stopping=true; app.request_stop(); hooks.work.set(); }
    auto stop() noexcept -> void { app.joined(); connection.stop(); }
    auto drain() noexcept -> void { app.drain(); }
    auto next_expiry() const noexcept -> net::DatagramDeadline {
        auto next=connection.expiry(); if (!next || *next==std::numeric_limits<std::uint64_t>::max()) return {};
        return Clock::time_point(std::chrono::nanoseconds(*next));
    }
    auto expire(Clock::time_point now) -> std::expected<void,int> {
        auto error=connection.expire(udp::time(now)); return error ? std::expected<void,int>(std::unexpected(error)) : std::expected<void,int>{};
    }
    auto receive(io::endpoint const& source,std::span<std::uint8_t const> bytes,Clock::time_point now) -> std::expected<void,int> {
        if (!started) {
            n::ngtcp2_pkt_hd first{}; if (n::ngtcp2_accept(&first,bytes.data(),bytes.size()) || first.version!=1) return {};
            remote=source; auto parameters=support::parameters(true); parameters.original_dcid=first.dcid;
            if (auto error=start(first.scid,udp::random_cid(),parameters,now)) return std::unexpected(error);
        }
        if (source!=remote || close_pending) return {};
        ++received; app.time(udp::time(now)); auto error=connection.read(path.value,nullptr,bytes,udp::time(now));
        if (error==n::err_draining && passed) { driver->finish(); return {}; }
        return error ? std::expected<void,int>(std::unexpected(error)) : std::expected<void,int>{};
    }
    auto output(std::span<std::uint8_t> bytes,Clock::time_point now) -> std::expected<std::optional<net::DatagramOutput>,int> {
        if (!started || stopping) return std::optional<net::DatagramOutput>{};
        if(server && passed){
            n::ngtcp2_ccerr close{};n::ngtcp2_ccerr_default(&close);n::ngtcp2_ccerr_set_application_error(&close,0,nullptr,0);
            auto written=connection.write_close(bytes,nullptr,nullptr,close,udp::time(now));if(!written)return std::unexpected(written.error());
            if(!*written)return std::optional<net::DatagramOutput>{};close_pending=true;return net::DatagramOutput{remote,*written,++token};
        }
        auto written=app.output(bytes,udp::time(now)); if (!written) return std::unexpected(written.error());
        if (!*written) return std::optional<net::DatagramOutput>{};
        return net::DatagramOutput{remote,*written,++token};
    }
    auto transmitted(std::uint64_t current,Clock::time_point now) -> std::expected<void,int> {
        if (current!=token || !connection.native()) return std::unexpected(n::err_callback_failure);
        n::ngtcp2_conn_update_pkt_tx_time(connection.native(),udp::time(now)); ++sent;if(close_pending)driver->finish();return {};
    }
    auto wait() -> capy::task<bool> {
        if (stopping) co_return false;
        hooks.work.clear(); auto [error]=co_await io::timeout(hooks.work.wait(),Clock::now()+8s);
        co_return !error && !stopping;
    }
};
}
