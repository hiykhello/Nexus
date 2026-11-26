// Wave 31 Track 31B unit tests: WebSocket Early Data, gRPC HTTP/2 Keepalive PING, and Multiplex h2mux.
import std;
import capy;
import corosio;
import config;
import httpupgrade;
import websocket.handshake;
import websocket.stream;
import tls.byte_stream;
import grpc.headers;
import grpc.session;
import grpc.stream;
import grpc.multiplex;
import grpc.multiplex_channel;
import http2.session_core;
import nghttp2;
import net.socket_stream;
import net.datagram_frame;
import mux.sing_wire;
import mux.smux_wire;
import mux.smux_streams;
import mux.smux_session;
import mux.h2mux_session;

namespace io = ::corosio;
using namespace std::chrono_literals;

namespace {
    void require(bool cond, std::string_view msg) {
        if (!cond) { std::cerr << "FAIL: " << msg << '\n'; std::exit(1); }
    }

    struct WsTestLower {
        net::SocketByteStream<io::local_stream_socket> sock;
        std::vector<std::uint8_t> prefetched;
        std::size_t prefetched_pos = 0;
        std::string tx_capture;
        bool capture_tx = false;
        explicit WsTestLower(io::local_stream_socket& s, bool cap = false) noexcept : sock(s), capture_tx(cap) {}
        auto cancel() noexcept -> void { sock.cancel(); }
        auto prepend_owned(std::vector<std::uint8_t>&& bytes) -> bool {
            if (bytes.empty()) return true;
            std::vector<std::uint8_t> merged(std::move(bytes));
            if (prefetched_pos < prefetched.size())
                merged.insert(merged.end(), prefetched.begin() + static_cast<std::ptrdiff_t>(prefetched_pos), prefetched.end());
            prefetched = std::move(merged); prefetched_pos = 0;
            return true;
        }
        auto read(std::span<std::uint8_t> out, websocket::ApplicationDeadline dl = {},
                  websocket::ReadTimeoutPolicy = websocket::ReadTimeoutPolicy::cancel_connection)
            -> capy::task<std::expected<std::size_t, websocket::ByteStreamError>> {
            if (prefetched_pos < prefetched.size()) {
                auto n = std::min(out.size(), prefetched.size() - prefetched_pos);
                std::copy_n(prefetched.data() + prefetched_pos, n, out.begin());
                prefetched_pos += n;
                if (prefetched_pos == prefetched.size()) { prefetched.clear(); prefetched_pos = 0; }
                co_return n;
            }
            auto r = co_await sock.read(out, dl);
            if (!r) co_return std::unexpected(r.error() == std::errc::timed_out
                ? websocket::ByteStreamError::timeout : websocket::ByteStreamError::io);
            co_return *r;
        }
        auto send(std::span<std::uint8_t const> data, websocket::ApplicationDeadline dl = {}) -> capy::task<bool> {
            if (capture_tx && tx_capture.size() < 16384)
                tx_capture.append(reinterpret_cast<char const*>(data.data()), std::min<std::size_t>(data.size(), 16384 - tx_capture.size()));
            co_return co_await sock.send(data, dl);
        }
        auto close_output(websocket::ApplicationDeadline dl = {}) -> capy::task<bool> { co_return co_await sock.close_output(dl); }
    };
    auto ws_client_task(websocket::GenericStream<WsTestLower>& client, httpupgrade::Profile const& prof,
                        std::vector<std::uint8_t> const& payload, bool& ok) -> capy::task<> {
        auto dl = websocket::Clock::now() + 3s;
        if (!co_await client.activate_websocket(prof, dl) || !co_await client.send(payload, dl)) co_return;
        std::vector<std::uint8_t> echoed; echoed.reserve(payload.size());
        std::array<std::uint8_t, 512> buf{};
        while (echoed.size() < payload.size()) {
            auto r = co_await client.read(buf, dl);
            if (!r || *r == 0) co_return;
            echoed.insert(echoed.end(), buf.begin(), buf.begin() + *r);
        }
        (void)co_await client.close_output(dl);
        ok = (echoed == payload);
    }
    auto ws_server_task(websocket::GenericStream<WsTestLower>& server, httpupgrade::Profile const& prof,
                        std::vector<std::uint8_t> const& payload, bool& ok) -> capy::task<> {
        auto dl = websocket::Clock::now() + 3s;
        if (!co_await server.activate_websocket(prof, dl)) co_return;
        std::vector<std::uint8_t> received; received.reserve(payload.size());
        std::array<std::uint8_t, 333> buf{};
        while (received.size() < payload.size()) {
            auto r = co_await server.read(buf, dl);
            if (!r || *r == 0) co_return;
            received.insert(received.end(), buf.begin(), buf.begin() + *r);
        }
        if (!co_await server.send(received, dl)) co_return;
        (void)co_await server.read(buf, dl);
        ok = (received == payload);
    }
    void run_ws_early_case(std::string_view label, httpupgrade::Profile const& cprof,
                           httpupgrade::Profile const& sprof, std::vector<std::uint8_t> const& payload,
                           std::string_view expected_hdr) {
        auto ctx = io::make_io_context(false);
        io::local_stream_socket cs(ctx), ss(ctx);
        require(!io::connect_pair(cs, ss), "ws connect_pair");
        WsTestLower clower(cs, true), slower(ss, true);
        websocket::GenericStream<WsTestLower> client(clower), server(slower);
        bool c_ok = false, s_ok = false;
        capy::run_async(ctx.get_executor())(ws_client_task(client, cprof, payload, c_ok));
        capy::run_async(ctx.get_executor())(ws_server_task(server, sprof, payload, s_ok));
        ctx.run_for(4s);
        require(c_ok && s_ok, label);
        auto req_end = clower.tx_capture.find("\r\n\r\n"), resp_end = slower.tx_capture.find("\r\n\r\n");
        require(req_end != std::string::npos && resp_end != std::string::npos, "ws upgrade headers captured");
        auto req_hdrs = std::string_view(clower.tx_capture).substr(0, req_end);
        auto resp_hdrs = std::string_view(slower.tx_capture).substr(0, resp_end);
        require(req_hdrs.find(expected_hdr) != std::string_view::npos &&
                resp_hdrs.find("Sec-WebSocket-Protocol") == std::string_view::npos &&
                req_hdrs.find("?ed=") == std::string_view::npos, "ws early wire headers");
    }
    auto ws_reject_server(websocket::GenericStream<WsTestLower>& srv, httpupgrade::Profile const& prof, bool& rej) -> capy::task<> {
        rej = !(co_await srv.activate_websocket(prof, websocket::Clock::now() + 2s)).has_value();
    }
    auto ws_send_bad_b64(io::local_stream_socket& sock) -> capy::task<> {
        std::string bad = "GET /max HTTP/1.1\r\nHost: cover.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
                          "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                          "X-Early-Data: !!!not-base64url!!!\r\n\r\n";
        net::SocketByteStream raw(sock);
        (void)co_await raw.send({reinterpret_cast<std::uint8_t const*>(bad.data()), bad.size()}, websocket::Clock::now() + 2s);
    }
    void test_websocket_early_data() {
        std::vector<std::uint8_t> med(5000), max8k(8192);
        for (std::size_t i = 0; i < med.size(); ++i) med[i] = static_cast<std::uint8_t>((i * 37 + 11) & 0xffu);
        for (std::size_t i = 0; i < max8k.size(); ++i) max8k[i] = static_cast<std::uint8_t>((i * 53 + 7) & 0xffu);
        auto c1 = httpupgrade::Profile::client("cover.example", "/ws", {}, true, 2048, "Sec-WebSocket-Protocol");
        auto s1 = httpupgrade::Profile::server("cover.example", "/ws", {}, true, 2048, "Sec-WebSocket-Protocol");
        require(c1 && s1, "ws profile 1");
        run_ws_early_case("ws explicit early-data 2048 + late frames", *c1, *s1, med, "Sec-WebSocket-Protocol: ");
        auto c2 = httpupgrade::Profile::client("cover.example", "/tunnel?ed=2048", {}, true);
        auto s2 = httpupgrade::Profile::server("cover.example", "/tunnel", {}, true);
        require(c2 && s2 && c2->max_early_data() == 2048 && c2->path() == "/tunnel", "ws ?ed= profile");
        run_ws_early_case("ws ?ed=2048 round-trip", *c2, *s2, med, "Sec-WebSocket-Protocol: ");
        auto c3 = httpupgrade::Profile::client("cover.example", "/max", {}, true, 8192, "X-Early-Data");
        auto s3 = httpupgrade::Profile::server("cover.example", "/max", {}, true, 8192, "X-Early-Data");
        require(c3 && s3, "ws 8192 profile");
        run_ws_early_case("ws 8192-byte custom header", *c3, *s3, max8k, "X-Early-Data: ");
        auto ctx = io::make_io_context(false);
        io::local_stream_socket cs(ctx), ss(ctx);
        require(!io::connect_pair(cs, ss), "ws bad b64 pair");
        WsTestLower slower(ss); websocket::GenericStream<WsTestLower> server(slower);
        bool rejected = false;
        capy::run_async(ctx.get_executor())(ws_reject_server(server, *s3, rejected));
        capy::run_async(ctx.get_executor())(ws_send_bad_b64(cs));
        ctx.run_for(2s);
        require(rejected, "ws server rejects invalid early-data base64url");
    }

    template<class Chan> auto run_chan(Chan& ch, bool* done = nullptr) -> capy::task<> {
        (void)co_await ch.run();
        if (done) *done = true;
    }
    template<class Chan> auto grpc_idle_then_rpc(Chan& client, Chan& server, bool& rpc_ok) -> capy::task<> {
        (void)co_await io::delay(130ms);
        auto ticket = client.open();
        require(ticket.has_value(), "grpc open after idle pings");
        typename Chan::Stream cstream(client, *ticket);
        std::array<std::uint8_t, 5> msg{'p', 'i', 'n', 'g', '!'};
        require(co_await cstream.send(msg, grpc::Clock::now() + 2s), "grpc send");
        require(co_await cstream.close_output(grpc::Clock::now() + 2s), "grpc close");
        std::array<std::uint8_t, 16> out{};
        auto r = co_await cstream.read(out, grpc::Clock::now() + 2s);
        rpc_ok = r && *r == 5 && std::ranges::equal(std::span(out).first(5), msg);
        client.cancel(); server.cancel();
    }
    template<class Chan> auto grpc_echo_once(Chan& server) -> capy::task<> {
        while (!server.finished() && !server.failure()) {
            if (auto t = server.accept()) {
                typename Chan::Stream st(server, *t);
                std::array<std::uint8_t, 16> buf{};
                auto r = co_await st.read(buf, grpc::Clock::now() + 2s);
                if (r && *r > 0) {
                    (void)co_await st.send(std::span(buf).first(*r), grpc::Clock::now() + 2s);
                    (void)co_await st.close_output(grpc::Clock::now() + 2s);
                }
                break;
            }
            if (!co_await server.wait_change(grpc::Clock::now() + 2s)) break;
        }
    }
    template<class Chan> auto cancel_after(Chan& a, Chan& b, std::chrono::milliseconds d) -> capy::task<> {
        (void)co_await io::delay(d);
        a.cancel(); b.cancel();
    }

    void test_grpc_keepalive_ping() {
        using Lower = net::SocketByteStream<io::local_stream_socket>;
        using MChan = grpc::MultiplexChannel<Lower, 8>;

        {
            auto ctx = io::make_io_context(false);
            io::local_stream_socket cs(ctx), ss(ctx);
            require(!io::connect_pair(cs, ss), "grpc ka pair");
            auto prof = grpc::RequestProfile::create("nexus.Service", "cover.example", false);
            grpc::Limits clim{}; clim.idle_timeout_ms = 35; clim.ping_timeout_ms = 250; clim.permit_without_stream = true;
            auto csess = grpc::MultiplexSession<8>::create(grpc::Role::client, *prof, grpc::ResponsePolicy::standard, clim);
            auto ssess = grpc::MultiplexSession<8>::create(grpc::Role::server, *prof, grpc::ResponsePolicy::standard, {});
            Lower cl(cs), sl(ss);
            MChan client(cl, std::move(*csess)), server(sl, std::move(*ssess));
            bool rpc_ok = false;
            capy::run_async(ctx.get_executor())(run_chan(client));
            capy::run_async(ctx.get_executor())(run_chan(server));
            capy::run_async(ctx.get_executor())(grpc_idle_then_rpc(client, server, rpc_ok));
            capy::run_async(ctx.get_executor())(grpc_echo_once(server));
            ctx.run_for(3s);
            require(rpc_ok && client.pings_sent() >= 2 && client.ping_acks_received() >= 2,
                    "grpc keepalive sends PINGs and gets ACKs on idle connection");
        }
        {
            auto ctx = io::make_io_context(false);
            io::local_stream_socket cs(ctx), ss(ctx);
            require(!io::connect_pair(cs, ss), "grpc ka no-stream pair");
            auto prof = grpc::RequestProfile::create("nexus.Service", "cover.example", false);
            grpc::Limits clim{}; clim.idle_timeout_ms = 30; clim.ping_timeout_ms = 200; clim.permit_without_stream = false;
            auto csess = grpc::MultiplexSession<8>::create(grpc::Role::client, *prof, grpc::ResponsePolicy::standard, clim);
            auto ssess = grpc::MultiplexSession<8>::create(grpc::Role::server, *prof, grpc::ResponsePolicy::standard, {});
            Lower cl(cs), sl(ss);
            MChan client(cl, std::move(*csess)), server(sl, std::move(*ssess));
            capy::run_async(ctx.get_executor())(run_chan(client));
            capy::run_async(ctx.get_executor())(run_chan(server));
            capy::run_async(ctx.get_executor())(cancel_after(client, server, 110ms));
            ctx.run_for(2s);
            require(client.pings_sent() == 0, "permit-without-stream=#false suppresses PING with 0 streams");
        }
        for (bool test_server : {false, true}) {
            auto ctx = io::make_io_context(false);
            io::local_stream_socket active_sock(ctx), blackhole(ctx);
            require(!io::connect_pair(active_sock, blackhole), "grpc blackhole pair");
            auto prof = grpc::RequestProfile::create("nexus.Service", "cover.example", false);
            grpc::Limits lim{}; lim.idle_timeout_ms = 35; lim.ping_timeout_ms = 60; lim.permit_without_stream = true;
            auto sess = grpc::MultiplexSession<8>::create(
                test_server ? grpc::Role::server : grpc::Role::client, *prof, grpc::ResponsePolicy::standard, lim);
            Lower lower(active_sock);
            MChan chan(lower, std::move(*sess));
            bool done = false;
            capy::run_async(ctx.get_executor())(run_chan(chan, &done));
            ctx.run_for(1s);
            require(done && chan.pings_sent() >= 1 && chan.ping_acks_received() == 0 &&
                    chan.failure() && chan.failure()->error == grpc::Error::timeout,
                    test_server ? "grpc server keepalive PING timeout teardown" : "grpc client keepalive PING timeout teardown");
        }
    }

    struct RawSockStream {
        io::local_stream_socket& sock;
        auto read(std::span<std::uint8_t> out) -> capy::task<std::expected<std::size_t, std::string>> {
            auto [ec, n] = co_await sock.read_some(capy::mutable_buffer(out.data(), out.size()));
            if (capy::is_eof(ec)) co_return std::size_t{0};
            if (ec) co_return std::unexpected(ec.message());
            co_return n;
        }
        auto send(std::span<std::uint8_t const> in) -> capy::task<bool> {
            while (!in.empty()) {
                auto [ec, n] = co_await sock.write_some(capy::const_buffer(in.data(), in.size()));
                if (ec || n == 0) co_return false;
                in = in.subspan(n);
            }
            co_return true;
        }
        auto close_output() -> capy::task<bool> { co_return !sock.shutdown(io::shutdown_send); }
        auto cancel() noexcept -> void { sock.cancel(); }
    };

    template<class MuxSess>
    auto echo_child(MuxSess& srv, std::uint32_t id, std::atomic<int>& served) -> capy::task<> {
        typename MuxSess::StreamHandle st(srv, id);
        std::array<std::uint8_t, 512> hdr{};
        auto n0 = co_await st.read(hdr);
        if (!n0 || *n0 == 0) co_return;
        auto dec = mux::sing::decode_stream_request(std::span(hdr).first(*n0));
        if (!dec || !*dec) co_return;
        auto const consumed = (*dec)->second;
        std::vector<std::uint8_t> ok_resp = mux::sing::encode_stream_response({mux::sing::status_success, {}});
        if (consumed < *n0) ok_resp.insert(ok_resp.end(), hdr.begin() + static_cast<std::ptrdiff_t>(consumed), hdr.begin() + static_cast<std::ptrdiff_t>(*n0));
        if (!co_await st.send(ok_resp)) co_return;
        std::array<std::uint8_t, 4096> buf{};
        for (;;) {
            auto r = co_await st.read(buf);
            if (!r) co_return;
            if (*r == 0) break;
            if (!co_await st.send(std::span(buf).first(*r))) co_return;
        }
        (void)co_await st.close_output();
        served.fetch_add(1);
    }

    template<class MuxSess>
    auto run_echo_server(MuxSess& srv, io::io_context& ctx, std::atomic<int>& served) -> capy::task<> {
        auto run_p = [&]() -> capy::task<capy::results<>> { co_return co_await srv.run(); };
        auto acc = [&]() -> capy::task<capy::results<>> {
            for (;;) {
                auto sid = co_await srv.accept_stream();
                if (!sid) break;
                capy::run_async(ctx.get_executor())(echo_child(srv, *sid, served));
            }
            co_return capy::results<>{};
        };
        (void)co_await capy::when_all(run_p(), acc());
    }

    template<class MuxSess>
    auto run_client_stream(MuxSess& sess, int i, std::size_t bytes_per_stream, bool udp, std::atomic<int>& client_ok)
        -> capy::task<capy::results<>> {
        auto sid = co_await sess.open_stream();
        if (!sid) co_return capy::results<>{};
        typename MuxSess::StreamHandle st(sess, *sid);
        net::ProxyAddress dest{net::ProxyAddressFamily::ipv4, {127, 0, 0, 1}, 4, static_cast<std::uint16_t>(8000 + i)};
        auto req_bytes = mux::sing::encode_stream_request({udp, udp, udp ? mux::sing::magic_proxy_address() : dest});
        if (!req_bytes || !co_await st.send(*req_bytes)) co_return capy::results<>{};
        std::vector<std::uint8_t> payload(bytes_per_stream);
        for (std::size_t j = 0; j < payload.size(); ++j)
            payload[j] = static_cast<std::uint8_t>((j * 17 + static_cast<std::size_t>(i) * 31) & 0xffu);
        bool send_ok = false;
        std::vector<std::uint8_t> rx;
        auto do_send = [&]() -> capy::task<capy::results<>> {
            std::size_t off = 0;
            while (off < payload.size()) {
                auto take = std::min<std::size_t>(payload.size() - off, 3000);
                if (!co_await st.send(std::span(payload).subspan(off, take))) co_return capy::results<>{};
                off += take;
            }
            send_ok = co_await st.close_output();
            co_return capy::results<>{};
        };
        auto do_recv = [&]() -> capy::task<capy::results<>> {
            std::array<std::uint8_t, 2048> buf{};
            for (;;) {
                auto r = co_await st.read(buf, std::chrono::steady_clock::now() + 5s);
                if (!r) co_return capy::results<>{};
                if (*r == 0) break;
                rx.insert(rx.end(), buf.begin(), buf.begin() + *r);
            }
            co_return capy::results<>{};
        };
        (void)co_await capy::when_all(do_send(), do_recv());
        auto resp = mux::sing::decode_stream_response(rx);
        if (send_ok && resp && *resp && (*resp)->first.status == mux::sing::status_success &&
            rx.size() == (*resp)->second + payload.size() &&
            std::equal(payload.begin(), payload.end(), rx.begin() + static_cast<std::ptrdiff_t>((*resp)->second)))
            client_ok.fetch_add(1);
        co_return capy::results<>{};
    }

    auto mux_server_entry(RawSockStream& sraw, io::io_context& ctx, std::atomic<int>& served) -> capy::task<> {
        std::array<std::uint8_t, 2> head{};
        if (!co_await mux::sing::read_exact(sraw, head)) co_return;
        require(head[0] == mux::sing::version_1 && (head[1] == mux::sing::proto_smux || head[1] == mux::sing::proto_h2mux),
                "inbound auto-detect session header");
        std::array<std::uint8_t, 1> pf{};
        if (!co_await mux::sing::read_exact(sraw, pf)) co_return;
        bool is_pad = pf[0] != 0;
        if (is_pad) {
            std::array<std::uint8_t, 2> pl{};
            if (!co_await mux::sing::read_exact(sraw, pl)) co_return;
            std::vector<std::uint8_t> skip((std::size_t(pl[0]) << 8) | pl[1]);
            if (!co_await mux::sing::read_exact(sraw, skip)) co_return;
        }
        auto dispatch = [&](auto& lower) -> capy::task<> {
            using L = std::remove_reference_t<decltype(lower)>;
            if (head[1] == mux::sing::proto_h2mux) {
                mux::h2mux::Session<L> sess(lower, false);
                co_await run_echo_server(sess, ctx, served);
            } else {
                mux::smux::Session<L> sess(lower, false, mux::smux::version_2);
                co_await run_echo_server(sess, ctx, served);
            }
        };
        if (is_pad) { mux::sing::PaddingStream<RawSockStream> ps(sraw); co_await dispatch(ps); }
        else co_await dispatch(sraw);
    }

    auto mux_client_entry(RawSockStream& craw, std::uint8_t proto, bool padded, int num_streams,
                          std::size_t bytes_per_stream, bool udp, std::atomic<int>& client_ok) -> capy::task<> {
        auto sreq = mux::sing::encode_session_request({mux::sing::version_1, proto, padded});
        require(co_await craw.send(sreq), "send mux session request");
        auto run_client = [&](auto& sess) -> capy::task<> {
            auto run_p = [&]() -> capy::task<capy::results<>> { co_return co_await sess.run(); };
            auto drive = [&]() -> capy::task<capy::results<>> {
                std::vector<capy::task<capy::results<>>> tasks;
                tasks.reserve(static_cast<std::size_t>(num_streams));
                for (int i = 0; i < num_streams; ++i)
                    tasks.push_back(run_client_stream(sess, i, bytes_per_stream, udp, client_ok));
                (void)co_await capy::when_all(std::move(tasks));
                sess.cancel();
                co_return capy::results<>{};
            };
            (void)co_await capy::when_all(run_p(), drive());
        };
        auto pick_proto = [&](auto& lower) -> capy::task<> {
            using L = std::remove_reference_t<decltype(lower)>;
            if (proto == mux::sing::proto_h2mux) { mux::h2mux::Session<L> sess(lower, true); co_await run_client(sess); }
            else { mux::smux::Session<L> sess(lower, true, mux::smux::version_2); co_await run_client(sess); }
        };
        if (padded) { mux::sing::PaddingStream<RawSockStream> ps(craw); co_await pick_proto(ps); }
        else co_await pick_proto(craw);
        craw.sock.close();
    }

    void test_h2mux_and_autodetect(std::uint8_t proto, bool padded, int num_streams, std::size_t bytes_per_stream, bool udp) {
        auto ctx = io::make_io_context(false);
        io::local_stream_socket cs(ctx), ss(ctx);
        require(!io::connect_pair(cs, ss), "mux pair");
        RawSockStream craw{cs}, sraw{ss};
        std::atomic<int> served{0}, client_ok{0};
        capy::run_async(ctx.get_executor())(mux_server_entry(sraw, ctx, served));
        capy::run_async(ctx.get_executor())(mux_client_entry(craw, proto, padded, num_streams, bytes_per_stream, udp, client_ok));
        ctx.run_for(6s);
        require(client_ok.load() == num_streams && served.load() == num_streams,
                proto == mux::sing::proto_h2mux ? "h2mux round-trip failed" : "smux auto-detect round-trip failed");
    }

    auto h2mux_dos_server(RawSockStream& sraw, io::io_context& ctx, std::size_t max_streams, std::atomic<int>& served) -> capy::task<> {
        mux::h2mux::Session<RawSockStream> srv(sraw, false, mux::h2mux::Limits{.max_streams = max_streams});
        co_await run_echo_server(srv, ctx, served);
    }
    auto h2mux_dos_client(RawSockStream& craw, std::size_t max_streams, bool& valid_ok) -> capy::task<> {
        using Core = http2::detail::SessionCore<mux::h2mux::detail::Policy>;
        capy::async_event rx, tx, acc, wr;
        http2::detail::CoreLimits clim{262144, 65535, 32, 4096, 16, 4096, 4096, 64, 5000, 16384};
        Core client(clim, http2::detail::LocalAccounting(4 * 1024 * 1024), true, mux::h2mux::Limits{}, &rx, &tx, &acc, &wr);
        require(client.start(http2::detail::Role::client, clim).has_value(), "raw h2 client start");
        auto flush_out = [&]() -> capy::task<> {
            std::array<std::uint8_t, 16384> buf{};
            for (;;) { auto n = client.output(buf); if (!n || *n == 0) break; require(co_await craw.send(std::span(buf).first(*n)), "raw h2 send"); }
        };
        auto pump_rx = [&]() -> capy::task<> {
            std::array<std::uint8_t, 4096> buf{};
            if (auto r = co_await craw.read(buf); r && *r > 0) (void)client.receive(std::span(buf).first(*r));
        };
        std::array<nghttp2::nghttp2_nv, 4> bad{{Core::nv(":method", "GET"), Core::nv(":scheme", "https"), Core::nv(":authority", "localhost"), Core::nv(":path", "/")}};
        for (std::size_t i = 0; i < max_streams + 2; ++i) {
            require(nghttp2::nghttp2_submit_request2(client.native(), nullptr, bad.data(), bad.size(), nullptr, nullptr) > 0, "submit invalid GET");
            co_await flush_out(); co_await pump_rx();
        }
        auto st = std::make_unique<mux::h2mux::detail::StreamState>(); auto* raw = st.get();
        std::array<nghttp2::nghttp2_nv, 2> good{{Core::nv(":method", "CONNECT"), Core::nv(":authority", "localhost")}};
        auto prov = client.provider(raw);
        auto id = nghttp2::nghttp2_submit_request2(client.native(), nullptr, good.data(), good.size(), &prov, raw);
        require(id > 0, "submit valid CONNECT after invalid GET flood");
        raw->id = id;
        auto req = mux::sing::encode_stream_request({false, false, net::ProxyAddress{net::ProxyAddressFamily::ipv4, {127, 0, 0, 1}, 4, 9000}});
        require(req.has_value(), "encode req");
        req->insert(req->end(), {'o', 'k'});
        raw->tx.push_back(std::move(*req)); raw->tx_bytes = raw->tx.front().size(); raw->local_end_req = true;
        client.policy().streams.emplace(id, std::move(st));
        co_await flush_out();
        while (!raw->remote_end && !raw->failed) { co_await pump_rx(); co_await flush_out(); }
        valid_ok = !raw->failed && raw->rx.size() == 3 && raw->rx[0] == 0 && raw->rx[1] == 'o' && raw->rx[2] == 'k';
        craw.sock.close();
    }
    void test_h2mux_invalid_requests_no_dos() {
        constexpr std::size_t kMaxStreams = 4;
        auto ctx = io::make_io_context(false);
        io::local_stream_socket cs(ctx), ss(ctx);
        require(!io::connect_pair(cs, ss), "h2mux dos pair");
        RawSockStream craw{cs}, sraw{ss};
        std::atomic<int> served{0}; bool valid_ok = false;
        capy::run_async(ctx.get_executor())(h2mux_dos_server(sraw, ctx, kMaxStreams, served));
        capy::run_async(ctx.get_executor())(h2mux_dos_client(craw, kMaxStreams, valid_ok));
        ctx.run_for(4s);
        require(valid_ok && served.load() == 1, "h2mux server survived max_streams+2 invalid requests without wedging");
    }
}

auto main() -> int {
    test_websocket_early_data();
    test_grpc_keepalive_ping();
    test_h2mux_and_autodetect(mux::sing::proto_h2mux, false, 1, 256 * 1024, false);
    test_h2mux_and_autodetect(mux::sing::proto_h2mux, false, 16, 12000, false);
    test_h2mux_and_autodetect(mux::sing::proto_h2mux, true, 4, 65000, false);
    test_h2mux_and_autodetect(mux::sing::proto_h2mux, false, 4, 9000, true);
    test_h2mux_and_autodetect(mux::sing::proto_smux, true, 4, 16000, false);
    test_h2mux_invalid_requests_no_dos();
    std::println("WAVE 31B TRANSPORT & H2MUX UNIT TESTS PASSED");
    return 0;
}
