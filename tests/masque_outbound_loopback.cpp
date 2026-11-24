#include <boost/capy/buffers.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/when_all.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/timeout.hpp>
#include <boost/corosio/udp_socket.hpp>
import std;
import crypto;
import dns.local_config;
import hysteria2.transport_options;
import masque.bearer;
import masque.capsule;
import masque.client_session;
import masque.config;
import masque.http3;
import masque.ip_control;
import masque.listener;
import masque.session;
import masque.udp_session;
import net.datagram_driver;
import packet;
import quic.cid_registry;
import quic.datagram_port;
import quic.datagram_session;
import quic.native_memory;
import quic.tls_server;
import quic.varint;
import tcp.receive;
import tcp.send;
import tls.fingerprint;
import tls.server_credential;
import capy;
import corosio;
import nghttp3;
import ngtcp2;
import relay.l3_mux;
import relay.masque_ip_addresses;

namespace io = ::corosio;
namespace m = masque;
using Clock = std::chrono::steady_clock;

namespace {
    struct TempDir {
        std::filesystem::path dir;
        std::string cert_file, key_file, bearer_file, bad_bearer_file, resolv_file, hosts_file;
        TempDir(std::filesystem::path d, std::string c, std::string k, std::string bf, std::string bb, std::string r, std::string h)
            : dir(std::move(d)), cert_file(std::move(c)), key_file(std::move(k)), bearer_file(std::move(bf)),
              bad_bearer_file(std::move(bb)), resolv_file(std::move(r)), hosts_file(std::move(h)) {}
        TempDir(TempDir&& o) noexcept
            : dir(std::exchange(o.dir, {})), cert_file(std::move(o.cert_file)), key_file(std::move(o.key_file)),
              bearer_file(std::move(o.bearer_file)), bad_bearer_file(std::move(o.bad_bearer_file)),
              resolv_file(std::move(o.resolv_file)), hosts_file(std::move(o.hosts_file)) {}
        TempDir& operator=(TempDir&&) = delete;
        ~TempDir() { if (!dir.empty()) { std::error_code ec; std::filesystem::remove_all(dir, ec); } }
    };

    auto make_temp_files() -> std::optional<TempDir> {
        auto dir = std::filesystem::temp_directory_path() /
                   ("nexus-masque-loopback-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(dir);
        TempDir out{dir, (dir / "cert.pem").string(), (dir / "key.pem").string(),
                    (dir / "bearer.txt").string(), (dir / "bad_bearer.txt").string(),
                    (dir / "resolv").string(), (dir / "hosts").string()};
        auto cmd = std::format(
            "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes "
            "-keyout '{}' -out '{}' -subj /CN=localhost -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' -days 1 >/dev/null 2>&1",
            out.key_file, out.cert_file);
        if (std::system(cmd.c_str()) != 0) return std::nullopt;
        std::ofstream(out.bearer_file) << "approved\n";
        std::ofstream(out.bad_bearer_file) << "rejected\n";
        auto priv = std::filesystem::perms::owner_read | std::filesystem::perms::owner_write;
        std::filesystem::permissions(out.bearer_file, priv, std::filesystem::perm_options::replace);
        std::filesystem::permissions(out.bad_bearer_file, priv, std::filesystem::perm_options::replace);
        std::ofstream(out.resolv_file) << "nameserver 127.0.0.1\n";
        std::ofstream(out.hosts_file) << "127.0.0.1 localhost\n";
        return out;
    }

    auto as_u8(std::string_view s) noexcept -> std::span<std::uint8_t const> {
        return {reinterpret_cast<std::uint8_t const*>(s.data()), s.size()};
    }

    auto read_bytes(std::string const& path) -> ::crypto::Bytes {
        std::ifstream f(path, std::ios::binary);
        return {std::istreambuf_iterator<char>(f), {}};
    }


}

#include "support/masque_ip_addresses.hpp"

auto main() -> int {
    if (!check_address_replacement()) {
        std::println(stderr, "CONNECT-IP address replacement did not retire active flows");
        return 26;
    }
    auto tmp = make_temp_files();
    if (!tmp) return 1;
    auto cert = read_bytes(tmp->cert_file);
    auto key = read_bytes(tmp->key_file);
    auto credential = tls::ServerCredential::create_file_contents(cert, key);
    ::crypto::cleanse(key);
    if (!credential) return 2;

    std::string_view secret = "approved";
    auto bearer = m::BearerCredential::create({reinterpret_cast<std::uint8_t const*>(secret.data()), secret.size()});
    if (!bearer) return 3;

    m::DestinationRule rule;
    rule.network.family = 4;
    rule.network.address = {127, 0, 0, 1};
    rule.prefix = 32;
    rule.first_port = 1;
    rule.last_port = 65535;
    m::HostConfig cfg("localhost", std::move(*bearer), {rule});
    dns::LocalSnapshotSource snapshots(tmp->resolv_file, tmp->hosts_file, std::chrono::milliseconds(50));

    io::io_context ctx;
    io::udp_socket udp_echo(ctx);
    auto ep4 = io::endpoint(io::ipv4_address::loopback(), 0);
    if (udp_echo.open(ep4.address().family()) || udp_echo.bind(ep4))
        return 4;
    auto echo_port = udp_echo.local_endpoint().port();

    m::Listener<> listener(ctx, cfg, *credential, snapshots);
    auto bound = listener.prepare(io::endpoint(io::ipv4_address::loopback(), 0));
    if (!bound) return 5;
    listener.start();

    bool stop_echo = false;
    auto echo_loop = [&]() -> capy::task<> {
        std::array<std::uint8_t, 2048> buf{};
        while (!stop_echo) {
            io::endpoint peer;
            auto [ec, n] = co_await io::timeout(
                udp_echo.recv_from(capy::mutable_buffer(buf.data(), buf.size()), peer),
                Clock::now() + std::chrono::seconds(5));
            if (ec || !n) co_return;
            (void)co_await udp_echo.send_to(capy::const_buffer(buf.data(), n), peer);
        }
    };

    int result = 0;
    auto run_clients = [&]() -> capy::task<> {
        struct Shutdown { bool& s; io::udp_socket& u; m::Listener<>& l;
            ~Shutdown() { s = true; u.close(); l.stop(); } } shutdown{stop_echo, udp_echo, listener};
        auto deadline = Clock::now() + std::chrono::seconds(5);

        // 1. Approved bearer + uTLS Firefox CONNECT-UDP roundtrip
        {
            auto prof = m::ClientProfile::load(
                "localhost", tmp->cert_file, "localhost", tmp->bearer_file,
                0x001d, false, hysteria2::TransportOptions{}, tls::Fingerprint::firefox);
            if (!prof) { result = 10; co_return; }
            m::Client<> client(ctx, **prof);
            if (!client.start(*bound)) { result = 11; co_return; }
            auto ops = [&]() -> capy::task<capy::results<>> {
                struct Fin { m::Client<>& c; ~Fin() { c.finish(); } } fin{client};
                if (!co_await client.connect_udp("127.0.0.1", echo_port, deadline)) { result = 12; co_return capy::results<>{}; }
                std::string_view msg = "hello-masque-udp";
                if (!client.send(as_u8(msg))) { result = 13; co_return capy::results<>{}; }
                auto rx = co_await client.receive(deadline);
                if (!rx || std::string_view(reinterpret_cast<char const*>(rx->data()), rx->size()) != msg) {
                    result = 14; co_return capy::results<>{};
                }
                co_return capy::results<>{};
            };
            (void)co_await capy::when_all(client.run(), ops());
            if (result) co_return;
        }

        // 2. Wrong bearer rejected by MASQUE listener
        {
            auto prof = m::ClientProfile::load(
                "localhost", tmp->cert_file, "localhost", tmp->bad_bearer_file,
                0x001d, false, hysteria2::TransportOptions{}, tls::Fingerprint::chrome);
            if (!prof) { result = 15; co_return; }
            m::Client<> bad_client(ctx, **prof);
            if (!bad_client.start(*bound)) { result = 16; co_return; }
            auto ops = [&]() -> capy::task<capy::results<>> {
                struct Fin { m::Client<>& c; ~Fin() { c.finish(); } } fin{bad_client};
                if (co_await bad_client.connect_udp("127.0.0.1", echo_port, Clock::now() + std::chrono::seconds(3))) {
                    result = 17;
                }
                co_return capy::results<>{};
            };
            (void)co_await capy::when_all(bad_client.run(), ops());
            if (result) co_return;
        }

        stop_echo = true;
        udp_echo.close();
        listener.stop();
    };

    capy::run_async(ctx.get_executor())(echo_loop());
    capy::run_async(ctx.get_executor())(run_clients());
    ctx.run_for(std::chrono::seconds(8));
    udp_echo.close();
    listener.stop();
    if (result != 0) return result;

    // 3. CONNECT-IP loopback over real UDP (ADDRESS_ASSIGN + ROUTE_ADVERTISEMENT + IPv4/IPv6 echo + dynamic address rotation)
    {
        namespace q = quic;
        namespace n = ::ngtcp2;
        namespace h = ::nghttp3;
        using Registry = q::CidRegistry<2, 8>;

        struct IpServerHooks {
            Registry& registry;
            q::SessionHandle owner{};
            capy::async_event& notify;
            std::int64_t stream = -1;
            std::vector<std::pair<std::string, std::string>> fields;
            std::vector<std::uint8_t> tx_cap, tx_dgram, pending_echo;
            std::size_t cap_off = 0, cap_ack = 0;
            bool cap_sub = false, ready = false, rotated = false, rotate_requested = false;
            m::UdpCapsules<2048> incoming_capsules;
            auto flush_echo() -> void {
                if (!tx_cap.empty() || pending_echo.empty()) return;
                tx_cap = std::exchange(pending_echo, {});
                (void)sess->h3().resume(stream);
                notify.set();
            }
            m::Session<q::TlsServer, IpServerHooks>* sess = nullptr;
            auto maybe_rotate() -> void {
                if (rotate_requested && !rotated && tx_cap.empty() && sess) {
                    rotated = true;
                    tx_cap = make_assign_cap(99);
                    cap_off = cap_ack = 0; cap_sub = false;
                    (void)sess->h3().resume(stream);
                    notify.set();
                }
            }

            static auto nv(std::string_view k, std::string_view v) noexcept -> h::nghttp3_nv {
                return {reinterpret_cast<std::uint8_t const*>(k.data()), reinterpret_cast<std::uint8_t const*>(v.data()),
                        k.size(), v.size(), h::nv_flag_none};
            }
            static void push_cap(std::vector<std::uint8_t>& out, std::uint64_t type, std::span<std::uint8_t const> body) {
                std::array<std::uint8_t, 16> hdr{};
                auto ts = q::varint_size(type), ls = q::varint_size(body.size());
                (void)q::write_varint(std::span(hdr), type, ts);
                (void)q::write_varint(std::span(hdr).subspan(ts), body.size(), ls);
                out.insert(out.end(), hdr.begin(), hdr.begin() + static_cast<std::ptrdiff_t>(ts + ls));
                out.insert(out.end(), body.begin(), body.end());
            }
            static auto make_assign_cap(std::uint8_t o3) -> std::vector<std::uint8_t> {
                std::vector<std::uint8_t> b4(32), cap;
                auto n4 = m::write_address_entry(b4, {0, 4, 32, {10, 10, 0, o3}}, false);
                std::vector<std::uint8_t> body(b4.begin(), b4.begin() + static_cast<std::ptrdiff_t>(*n4));
                if (o3 == 2) {
                    std::vector<std::uint8_t> b6(32);
                    m::AddressEntry e6{0, 6, 128, {0xfd, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}};
                    auto n6 = m::write_address_entry(b6, e6, false);
                    body.insert(body.end(), b6.begin(), b6.begin() + static_cast<std::ptrdiff_t>(*n6));
                }
                push_cap(cap, m::address_assign_capsule, body);
                return cap;
            }
            static auto make_route_cap() -> std::vector<std::uint8_t> {
                std::vector<std::uint8_t> r4(64), r6(64), body, cap;
                m::RouteEntry e4{4, 0, {0, 0, 0, 0}, {255, 255, 255, 255}};
                auto n4 = m::write_route_entry(r4, e4);
                body.insert(body.end(), r4.begin(), r4.begin() + static_cast<std::ptrdiff_t>(*n4));
                m::RouteEntry e6{6, 0, {}, {}};
                e6.last.fill(0xff);
                auto n6 = m::write_route_entry(r6, e6);
                body.insert(body.end(), r6.begin(), r6.begin() + static_cast<std::ptrdiff_t>(*n6));
                push_cap(cap, m::route_advertisement_capsule, body);
                return cap;
            }
            auto changed() noexcept -> void { notify.set(); }
            auto h3_closed() noexcept -> void { ready = false; }
            auto transport_closed() noexcept -> void { ready = false; }
            auto stream_capacity() const noexcept -> std::size_t { return 4; }
            auto stream_state(std::uint64_t id) noexcept -> m::Http3StreamState {
                return static_cast<std::int64_t>(id) == stream && ready
                    ? m::Http3StreamState{m::Http3StreamKind::datagram, true, true}
                    : m::Http3StreamState{};
            }
            auto closed(std::int64_t, std::uint64_t, std::uint64_t) noexcept -> void { ready = false; }
            auto receive_closed(std::int64_t, std::uint64_t) noexcept -> void { ready = false; }
            auto send_closed(std::int64_t, std::uint64_t) noexcept -> void { ready = false; }
            auto protocol_error() noexcept -> void { ready = false; notify.set(); }
            auto begin_headers(std::int64_t, bool t) -> int { fields.clear(); return t ? h::err_callback_failure : 0; }
            auto header(std::int64_t, h::nghttp3_rcbuf* k, h::nghttp3_rcbuf* v, bool) -> int {
                auto a = h::nghttp3_rcbuf_get_buf(k), b = h::nghttp3_rcbuf_get_buf(v);
                fields.emplace_back(std::string(reinterpret_cast<char const*>(a.base), a.len),
                                    std::string(reinterpret_cast<char const*>(b.base), b.len));
                return 0;
            }
            auto end_headers(std::int64_t id, bool fin, bool t) -> int {
                if (fin || t) return h::err_callback_failure;
                bool ok_proto = false, ok_auth = false, ok_path = false;
                for (auto const& [k, v] : fields) {
                    if (k == ":protocol" && v == "connect-ip") ok_proto = true;
                    if (k == "proxy-authorization" && v == "Bearer approved") ok_auth = true;
                    if (k == ":path" && v == "/.well-known/masque/ip/*/*/") ok_path = true;
                }
                if (!ok_proto || !ok_auth || !ok_path || !sess) return h::err_callback_failure;
                stream = id;
                ready = true;
                std::array resp{nv(":status", "200"), nv("capsule-protocol", "?1")};
                if (sess->h3().response(id, resp, true)) return h::err_callback_failure;
                tx_cap = make_assign_cap(2);
                auto rc = make_route_cap();
                tx_cap.insert(tx_cap.end(), rc.begin(), rc.end());
                (void)sess->h3().resume(id);
                notify.set();
                return 0;
            }
            auto data(std::int64_t, std::span<std::uint8_t const> bytes) -> int {
                auto result = incoming_capsules.feed(bytes, [&](std::span<std::uint8_t const> packet) {
                    std::vector<std::uint8_t> body{0};
                    body.insert(body.end(), packet.begin(), packet.end());
                    push_cap(pending_echo, m::datagram_capsule_type, body);
                    flush_echo();
                });
                return result == m::UdpInput::malformed || result == m::UdpInput::too_large
                    ? h::err_callback_failure : 0;
            }
            auto data_acked(std::int64_t id, std::uint64_t sz) -> int {
                if (id == stream && sz <= tx_cap.size() - cap_ack) {
                    cap_ack += sz;
                    if (cap_ack == tx_cap.size()) { tx_cap.clear(); cap_off = cap_ack = 0; cap_sub = false; maybe_rotate(); flush_echo(); }
                }
                return 0;
            }
            auto end_stream(std::int64_t) -> int { ready = false; return 0; }
            auto shutdown(std::int64_t) -> int { ready = false; return 0; }
            auto read_data(std::int64_t id, std::span<h::nghttp3_vec> out, std::uint32_t& flags) -> h::nghttp3_ssize {
                if (id != stream || cap_sub || cap_off >= tx_cap.size() || out.empty()) return h::err_wouldblock;
                out[0] = {tx_cap.data() + cap_off, tx_cap.size() - cap_off};
                cap_sub = true;
                flags = h::data_flag_none;
                return 1;
            }
            auto datagram(std::uint64_t, std::span<std::uint8_t const> pkt) -> int {
                if (!ready || pkt.size() < 2 || pkt[0] != 0) return n::err_callback_failure;
                tx_dgram.assign(pkt.begin(), pkt.end());
                rotate_requested = true;
                maybe_rotate();
                notify.set();
                return 0;
            }
            struct Packet { std::uint64_t stream{}; std::span<std::uint8_t const> payload; };
            auto datagram_output() const noexcept -> std::optional<Packet> {
                if (tx_dgram.empty()) return std::nullopt;
                return Packet{static_cast<std::uint64_t>(stream), tx_dgram};
            }
            auto datagram_accepted() noexcept -> void { tx_dgram.clear(); }
            auto datagram_rejected() noexcept -> void { tx_dgram.clear(); }
            auto datagram_budget() const noexcept -> std::size_t { return 1200; }
            auto add_connection_id(n::ngtcp2_cid const& id, n::ngtcp2_stateless_reset_token const&) noexcept -> int {
                return registry.insert(owner, {id.data, id.datalen}) ? 0 : n::err_callback_failure;
            }
            auto remove_connection_id(n::ngtcp2_cid const& id) noexcept -> int {
                (void)registry.remove(owner, {id.data, id.datalen});
                return 0;
            }
        };

        using SrvSession = m::Session<q::TlsServer, IpServerHooks>;
        using SrvQuic = q::DatagramSession<q::TlsServer, SrvSession>;
        struct SrvBundle {
            q::TlsServer tls;
            IpServerHooks hooks;
            q::NativeMemory<> memory;
            SrvSession app;
            SrvQuic session;
            SrvBundle(tls::ServerCredential const& cred, Registry& reg, q::SessionHandle id, capy::async_event& ev,
                      io::endpoint const& local, std::size_t nbytes)
                : tls(cred, "h3"), hooks(reg, id, ev), memory(nbytes),
                  app(tls, hooks, true, memory.http3()), session(tls, app, local) { hooks.sess = &app; }
        };
        struct SrvFactory {
            using Session = SrvQuic;
            tls::ServerCredential const& cred;
            std::unique_ptr<SrvBundle> bundle;
            capy::async_event* ev = nullptr;
            bool joined = false;
            auto admit(n::ngtcp2_pkt_hd const&, io::endpoint const&, Clock::time_point) const noexcept -> bool { return true; }
            auto create(q::SessionHandle owner, Registry& reg, std::span<std::uint8_t const> src, n::ngtcp2_pkt_hd const& init,
                        io::endpoint const& peer, Clock::time_point now) noexcept -> std::expected<Session*, int> {
                hysteria2::TransportOptions opts;
                opts.native_bytes = 262144;
                auto settings = hysteria2::TransportProfile<4, 16384>::settings(opts);
                auto params = hysteria2::TransportProfile<4, 16384>::parameters(opts);
                if (!settings || !params) return std::unexpected(n::err_invalid_argument);
                params->max_datagram_frame_size = 1200;
                params->original_dcid = init.dcid;
                params->original_dcid_present = 1;
                bundle = std::make_unique<SrvBundle>(cred, reg, owner, *ev, peer, opts.native_bytes);
                n::ngtcp2_cid sc{};
                n::ngtcp2_cid_init(&sc, src.data(), src.size());
                if (auto err = bundle->session.start(true, init.scid, sc, peer, *settings, *params, bundle->memory.transport(), now)) {
                    bundle.reset(); return std::unexpected(err);
                }
                return &bundle->session;
            }
            auto application_drained(q::SessionHandle, Session const&) const noexcept -> bool { return joined; }
            auto failed(q::SessionHandle, int) noexcept -> void { joined = true; }
            auto destroy(q::SessionHandle, Session&) noexcept -> void { bundle.reset(); }
        };

        io::io_context ip_ctx;
        io::udp_socket srv_sock(ip_ctx);
        auto ep = io::endpoint(io::ipv4_address::loopback(), 0);
        if (srv_sock.open(ep.address().family()) || srv_sock.bind(ep)) return 18;
        auto srv_ep = srv_sock.local_endpoint();
        SrvFactory fac{*credential};
        q::DatagramPort<SrvFactory, 2, 8, 8, false> srv_port(fac);
        net::DatagramDriver<decltype(srv_port)> srv_drv(srv_sock, srv_port);
        fac.ev = &srv_drv.changed();

        auto prof = m::ClientProfile::load("localhost", tmp->cert_file, "localhost", tmp->bearer_file,
                                           0x001d, false, hysteria2::TransportOptions{}, tls::Fingerprint::chrome);
        if (!prof) return 19;
        m::Client<> ip_client(ip_ctx, **prof);
        if (!ip_client.start(srv_ep)) return 20;

        auto ip_test = [&]() -> capy::task<capy::results<>> {
            struct Fin {
                m::Client<>& c;
                SrvFactory& f;
                decltype(srv_port)& p;
                decltype(srv_drv)& d;
                io::udp_socket& s;
                ~Fin() { c.finish(); f.joined = true; p.request_stop(); d.finish(); p.stop(); s.close(); }
            } fin{ip_client, fac, srv_port, srv_drv, srv_sock};
            auto deadline = Clock::now() + std::chrono::seconds(5);
            if (!co_await ip_client.connect_ip("/.well-known/masque/ip/*/*/", deadline)) { result = 21; co_return capy::results<>{}; }
            for (int i = 0; i < 40; ++i) {
                ip_client.rx_event().clear();
                if (ip_client.address_epoch() > 0 && !ip_client.advertised_routes().empty()) break;
                co_await io::timeout(ip_client.rx_event().wait(), Clock::now() + std::chrono::milliseconds(50));
            }
            if (ip_client.address_epoch() != 1 || ip_client.assigned_addresses().size() != 2 || ip_client.advertised_routes().size() != 2) {
                result = 22; co_return capy::results<>{};
            }
            std::vector<std::uint8_t> pkt{0x45, 0, 0, 24, 0, 0, 0, 0, 64, 17, 0, 0, 10, 10, 0, 2, 198, 51, 100, 42, 1, 2, 3, 4};
            if (!ip_client.send(pkt)) { result = 23; co_return capy::results<>{}; }
            auto rx = co_await ip_client.receive(deadline);
            if (!rx || *rx != pkt) { result = 24; co_return capy::results<>{}; }
            for (int i = 0; i < 40; ++i) {
                ip_client.rx_event().clear();
                if (ip_client.address_epoch() >= 2) break;
                co_await io::timeout(ip_client.rx_event().wait(), Clock::now() + std::chrono::milliseconds(50));
            }
            if (ip_client.address_epoch() != 2 || ip_client.assigned_addresses().empty() ||
                ip_client.assigned_addresses()[0].address[3] != 99) {
                result = 25; co_return capy::results<>{};
            }
            // The peer's advertised QUIC DATAGRAM limit is smaller than
            // this IPv6-sized IP packet. Reliable DATA must carry it.
            std::vector<std::uint8_t> payload(1232, 0x57);
            auto sized = ::packet::make_udp6({0xfd, 0x10}, {0xfd, 0x11}, 12345, 53, payload, 1280);
            if (!sized || sized->size() != 1280 || !ip_client.send(*sized)) { result = 27; co_return capy::results<>{}; }
            auto large = co_await ip_client.receive(deadline);
            if (!large || *large != *sized) { result = 28; co_return capy::results<>{}; }
            co_return capy::results<>{};
        };

        auto run_all = [&]() -> capy::task<> {
            (void)co_await capy::when_all(srv_drv.run(), ip_client.run(), ip_test());
        };
        capy::run_async(ip_ctx.get_executor())(run_all());
        ip_ctx.run_for(std::chrono::seconds(8));
        if (result != 0) return result;
    }

    std::println("MASQUE outbound loopback (CONNECT-UDP, bad bearer, CONNECT-IP address updates and Capsule fallback) passed");
}
