#include <boost/capy/ex/run_async.hpp>
import std;
import capy;
import corosio;
import config;
import net.datagram_frame;
import mux.smux_wire;
import mux.sing_wire;
import mux.smux_streams;
import mux.smux_session;

namespace {
    namespace io = ::corosio;
    using namespace std::chrono_literals;

    auto require(bool ok, std::string_view msg) -> void {
        if (!ok) {
            std::cerr << "FAIL: " << msg << '\n';
            std::exit(1);
        }
    }

    auto make_addr(net::ProxyAddressFamily fam, std::initializer_list<std::uint8_t> raw, std::uint16_t port) -> net::ProxyAddress {
        net::ProxyAddress a{.family = fam, .length = static_cast<std::uint8_t>(raw.size()), .port = port};
        std::ranges::copy(raw, a.bytes.begin());
        return a;
    }

    auto make_domain(std::string_view host, std::uint16_t port) -> net::ProxyAddress {
        net::ProxyAddress a{.family = net::ProxyAddressFamily::domain, .length = static_cast<std::uint8_t>(host.size()), .port = port};
        std::ranges::copy(host, a.bytes.begin());
        return a;
    }

    struct MemoryPipe {
        std::vector<std::vector<std::uint8_t>> writes;
        std::vector<std::uint8_t> flat;
        std::size_t pos = 0;

        auto read(std::span<std::uint8_t> dst) -> capy::task<std::expected<std::size_t, std::string>> {
            if (pos >= flat.size()) co_return std::size_t{0};
            auto take = std::min({dst.size(), flat.size() - pos, std::size_t{7}});
            std::copy_n(flat.data() + pos, take, dst.begin());
            pos += take;
            co_return take;
        }
        auto send(std::span<std::uint8_t const> src) -> capy::task<bool> {
            writes.emplace_back(src.begin(), src.end());
            flat.insert(flat.end(), src.begin(), src.end());
            co_return true;
        }
        auto close_output() -> capy::task<bool> { co_return true; }
        auto cancel() noexcept -> void {}
    };

    struct TcpLower {
        io::tcp_socket& sock;
        auto read(std::span<std::uint8_t> dst) -> capy::task<std::expected<std::size_t, std::string>> {
            auto [ec, n] = co_await sock.read_some(capy::mutable_buffer(dst.data(), dst.size()));
            if (capy::is_eof(ec) || (!ec && n == 0)) co_return std::size_t{0};
            if (ec) co_return std::unexpected(std::string("tcp read error"));
            co_return n;
        }
        auto send(std::span<std::uint8_t const> src) -> capy::task<bool> {
            while (!src.empty()) {
                auto [ec, n] = co_await sock.write_some(capy::const_buffer(src.data(), src.size()));
                if (ec || n == 0 || n > src.size()) co_return false;
                src = src.subspan(n);
            }
            co_return true;
        }
        auto close_output() -> capy::task<bool> { co_return !sock.shutdown(io::shutdown_send); }
        auto cancel() noexcept -> void { sock.cancel(); }
    };

    auto test_smux_wire() -> void {
        using namespace mux::smux;
        FrameHeader psh{version_2, Command::psh, 0x1234, 0x05060708};
        auto raw = encode_header(psh);
        require(raw == std::array<std::uint8_t, 8>{2, 2, 0x34, 0x12, 0x08, 0x07, 0x06, 0x05}, "smux LE header");
        auto dec = decode_header(raw);
        require(dec && *dec == psh, "smux decode psh");

        for (auto cmd : {Command::syn, Command::fin, Command::nop}) {
            FrameHeader h1{version_1, cmd, 0, 7};
            require(decode_header(encode_header(h1)).value() == h1, "smux v1 control roundtrip");
            require(!decode_header(encode_header(FrameHeader{version_2, cmd, 1, 7})).has_value(), "control nonzero len rejected");
        }
        FrameHeader upd_hdr{version_2, Command::upd, upd_payload_size, 9};
        require(decode_header(encode_header(upd_hdr)).value() == upd_hdr, "smux upd header");
        require(!decode_header(encode_header(FrameHeader{0, Command::nop, 0, 0})).has_value(), "ver 0 rejected");
        require(!decode_header(encode_header(FrameHeader{3, Command::nop, 0, 0})).has_value(), "ver 3 rejected");
        require(!decode_header(std::array<std::uint8_t, 8>{2, 5, 0, 0, 1, 0, 0, 0}).has_value(), "unknown cmd rejected");
        require(!decode_header(encode_header(FrameHeader{version_1, Command::upd, 8, 1})).has_value(), "v1 upd rejected");
        require(!decode_header(encode_header(FrameHeader{version_2, Command::upd, 7, 1})).has_value(), "bad upd len rejected");

        UpdPayload upd{0x11223344u, 0x00040000u};
        auto uwire = encode_upd(upd);
        require(uwire == std::array<std::uint8_t, 8>{0x44, 0x33, 0x22, 0x11, 0x00, 0x00, 0x04, 0x00}, "upd LE wire");
        require(decode_upd(uwire) == upd, "upd roundtrip");
    }

    auto test_sing_wire_and_padding() -> void {
        using namespace mux::sing;
        require(is_mux_destination("sp.mux.sing-box.arpa", 444) && is_mux_destination("SP.MUX.SING-BOX.ARPA", 444), "magic dest");
        require(!is_mux_destination("sp.mux.sing-box.arpa", 443) && !is_mux_destination("example.com", 444), "non-magic dest");

        for (auto const& [req, pad] : {std::pair{SessionRequest{version_0, proto_smux, false}, std::optional<std::uint16_t>{}},
                                        std::pair{SessionRequest{version_1, proto_smux, false}, std::optional<std::uint16_t>{}},
                                        std::pair{SessionRequest{version_1, proto_smux, true}, std::optional<std::uint16_t>{12}}}) {
            auto wire = encode_session_request(req, pad);
            auto dec = decode_session_request(wire);
            require(dec && *dec && (*dec)->first == req && (*dec)->second == wire.size(), "session request roundtrip");
            auto part = decode_session_request(std::span(wire).first(wire.size() - 1));
            require(part && !*part, "session request partial returns nullopt");
        }
        require(!decode_session_request(std::array<std::uint8_t, 2>{2, 0}).has_value(), "bad sing version");
        require(!decode_session_request(std::array<std::uint8_t, 2>{1, 9}).has_value(), "bad sing proto");
        require(!decode_session_request(std::array<std::uint8_t, 3>{1, 0, 2}).has_value(), "bad sing padding flag");

        std::vector<StreamRequest> reqs{
            {false, false, make_addr(net::ProxyAddressFamily::ipv4, {203, 0, 113, 5}, 443)},
            {true, false, make_addr(net::ProxyAddressFamily::ipv6, {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 5353)},
            {true, false, make_domain("dns.google", 53)},
            {true, true, net::ProxyAddress{}},
        };
        for (auto const& r : reqs) {
            auto enc = encode_stream_request(r);
            require(enc.has_value(), "encode stream request");
            auto dec = decode_stream_request(*enc);
            auto exp = r;
            if (exp.packet_addr) exp.destination = magic_proxy_address();
            require(dec && *dec && (*dec)->second == enc->size() && (*dec)->first == exp, "stream request match");
            auto part = decode_stream_request(std::span(*enc).first(enc->size() - 1));
            require(part && !*part, "stream request partial");
        }
        for (auto const& resp : {StreamResponse{status_success, {}}, StreamResponse{status_error, "denied"},
                                 StreamResponse{status_error, std::string(200, 'E')}}) {
            auto wire = encode_stream_response(resp);
            auto dec = decode_stream_response(wire);
            require(dec && *dec && (*dec)->first == resp && (*dec)->second == wire.size(), "stream response roundtrip");
        }
        auto pvar = decode_stream_response(std::array<std::uint8_t, 2>{1, 0x80});
        require(pvar && !*pvar && !decode_stream_response(std::array<std::uint8_t, 1>{2}).has_value(), "response validation");

        io::io_context ctx;
        MemoryPipe pipe;
        PaddingStream<MemoryPipe> writer(pipe), reader(pipe);
        std::vector<std::uint8_t> expected, actual;
        bool io_ok = false;
        capy::run_async(ctx.get_executor())([&]() -> capy::task<> {
            for (std::size_t i = 0; i < 20; ++i) {
                std::vector<std::uint8_t> msg(32 + i * 3, static_cast<std::uint8_t>(0x20 + i));
                if (!co_await writer.send(msg)) co_return;
                expected.insert(expected.end(), msg.begin(), msg.end());
            }
            for (;;) {
                std::array<std::uint8_t, 19> buf{};
                auto r = co_await reader.read(buf);
                if (!r) co_return;
                if (*r == 0) break;
                actual.insert(actual.end(), buf.begin(), buf.begin() + *r);
            }
            io_ok = (pipe.writes.size() == 20 && expected == actual);
            for (std::size_t i = 0; i < first_paddings; ++i) io_ok = io_ok && pipe.writes[i].size() > 4 + (32 + i * 3);
            for (std::size_t i = first_paddings; i < 20; ++i) io_ok = io_ok && pipe.writes[i].size() == 32 + i * 3;
        }());
        ctx.run_for(2s);
        require(io_ok, "20-chunk PaddingStream roundtrip");
    }

    auto test_smux_streams() -> void {
        using namespace mux::smux;
        StreamTable client(true, version_2), server(false, version_2);
        auto s1 = client.open(), s3 = client.open();
        require(s1 && *s1 == 1 && s3 && *s3 == 3, "client odd stream IDs");
        require(server.accept(1).has_value() && server.accept(3).has_value(), "server accept IDs");
        require(server.accept(0).error() == StreamError::invalid && server.accept(1).error() == StreamError::duplicate, "reject bad/dup ID");

        for (std::size_t i = 0; i < 8; ++i) {
            require(client.tx_window_available(1) == default_max_frame_size, "tx window step");
            client.record_tx(1, default_max_frame_size);
        }
        require(client.tx_window_available(1) == 0 && client.on_upd(1, UpdPayload{131072, initial_peer_window}) &&
                client.tx_window_available(1) == default_max_frame_size, "tx window exhausted & upd restore");

        auto s5 = client.open();
        require(s5 && *s5 == 5, "open stream 5");
        client.record_tx(*s5, 0xFFFF'FF00u);
        require(client.on_upd(*s5, UpdPayload{0xFFFF'FF00u, initial_peer_window}) &&
                client.tx_window_available(*s5) == default_max_frame_size, "wraparound align");
        client.record_tx(*s5, 300);
        client.record_tx(*s5, initial_peer_window - 300);
        require(client.tx_window_available(*s5) == 0 && client.on_upd(*s5, UpdPayload{44u, initial_peer_window}) &&
                client.tx_window_available(*s5) == 300u, "uint32 wraparound arithmetic");

        std::vector<std::uint8_t> chunk(32768, 0xAB);
        for (int i = 0; i < 4; ++i) require(server.push(1, chunk) == PushResult::queued, "push rx chunk");
        require(server.push(1, std::vector<std::uint8_t>(100, 0xCD)) == PushResult::queued, "push over half window");
        std::array<std::uint8_t, 65536> out{};
        auto r1 = server.read(1, out);
        require(r1 && r1->bytes_read == 32768 && !r1->upd.has_value(), "read before upd threshold");
        for (int i = 0; i < 3; ++i) {
            auto rn = server.read(1, out);
            require(rn && rn->bytes_read == 32768, "middle read");
            if (i == 2) require(rn->upd && rn->upd->consumed == 131072 && rn->upd->window == initial_peer_window, "upd at 131072");
        }
    }

    auto make_tcp_loopback(io::io_context& ctx, io::tcp_socket& client, io::tcp_socket& server) -> bool {
        io::tcp_acceptor acc{ctx};
        if (acc.open() || acc.bind(io::endpoint(io::ipv4_address::loopback(), 0)) || acc.listen()) return false;
        auto port = acc.local_endpoint().port();
        if (!port || client.open()) return false;
        bool done = false, aok = false, cok = false;
        auto accept_fn = [&]() -> capy::task<capy::results<>> {
            auto [ec, s] = co_await acc.accept();
            if (!ec) server = std::move(s);
            aok = !ec;
            co_return capy::results<>{};
        };
        auto connect_fn = [&]() -> capy::task<capy::results<>> {
            auto [ec] = co_await client.connect(io::endpoint(io::ipv4_address::loopback(), port));
            cok = !ec;
            co_return capy::results<>{};
        };
        capy::run_async(ctx.get_executor())([&]() -> capy::task<> {
            auto [err, a, c] = co_await capy::when_all(accept_fn(), connect_fn());
            (void)a; (void)c;
            done = !err;
        }());
        ctx.restart();
        (void)ctx.run_for(3s);
        acc.close();
        return done && aok && cok;
    }

    auto test_tcp_loopback_v2_large() -> void {
        io::io_context ctx;
        io::tcp_socket csock{ctx}, ssock{ctx};
        require(make_tcp_loopback(ctx, csock, ssock), "tcp loopback v2 large setup");
        TcpLower cl{csock}, sl{ssock};
        mux::smux::Session<TcpLower> csess(cl, true, mux::smux::version_2), ssess(sl, false, mux::smux::version_2);
        constexpr std::size_t total = 320 * 1024;
        bool c_ok = false, s_ok = false;
        auto server_job = [&]() -> capy::task<capy::results<>> {
            auto sid = co_await ssess.accept_stream();
            if (!sid) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
            std::size_t seen = 0;
            bool match = true;
            std::array<std::uint8_t, 8192> buf{};
            for (;;) {
                auto r = co_await ssess.read_stream(*sid, buf, std::chrono::steady_clock::now() + 4s);
                if (!r) { match = false; break; }
                if (*r == 0) break;
                for (std::size_t i = 0; i < *r; ++i, ++seen)
                    if (buf[i] != static_cast<std::uint8_t>(((seen * 131u) + 7u) & 0xffu)) match = false;
            }
            std::array<std::uint8_t, 4> ack{'O', 'K', 'v', '2'};
            s_ok = match && seen == total && co_await ssess.write_stream(*sid, ack) && co_await ssess.close_stream_output(*sid);
            ssess.release_stream(*sid);
            co_return capy::results<>{};
        };
        auto client_job = [&]() -> capy::task<capy::results<>> {
            auto sid = co_await csess.open_stream();
            if (!sid) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
            std::vector<std::uint8_t> payload(total);
            for (std::size_t i = 0; i < total; ++i) payload[i] = static_cast<std::uint8_t>(((i * 131u) + 7u) & 0xffu);
            bool sent = co_await csess.write_stream(*sid, payload) && co_await csess.close_stream_output(*sid);
            std::array<std::uint8_t, 4> ack{}, tail{};
            std::size_t got = 0;
            while (got < ack.size()) {
                auto r = co_await csess.read_stream(*sid, std::span(ack).subspan(got), std::chrono::steady_clock::now() + 4s);
                if (!r || *r == 0) break;
                got += *r;
            }
            auto rtail = co_await csess.read_stream(*sid, tail, std::chrono::steady_clock::now() + 4s);
            c_ok = sent && got == 4 && rtail && *rtail == 0 && ack == std::array<std::uint8_t, 4>{'O', 'K', 'v', '2'};
            csess.release_stream(*sid);
            (void)co_await cl.close_output();
            csess.cancel();
            co_return capy::results<>{};
        };
        capy::run_async(ctx.get_executor())([&]() -> capy::task<> {
            (void)co_await capy::when_all(csess.run(), ssess.run(), client_job(), server_job());
        }());
        ctx.restart();
        (void)ctx.run_for(5s);
        require(c_ok && s_ok && csess.drained() && ssess.drained(), "v2 >300KiB cmdUPD + drained");
    }

    auto test_tcp_loopback_padded_20() -> void {
        io::io_context ctx;
        io::tcp_socket csock{ctx}, ssock{ctx};
        require(make_tcp_loopback(ctx, csock, ssock), "tcp loopback padded setup");
        TcpLower cl_raw{csock}, sl_raw{ssock};
        mux::sing::PaddingStream<TcpLower> cp(cl_raw), sp(sl_raw);
        mux::smux::Session<mux::sing::PaddingStream<TcpLower>> csess(cp, true), ssess(sp, false);
        bool c_ok = false, s_ok = false;
        auto server_job = [&]() -> capy::task<capy::results<>> {
            auto sid = co_await ssess.accept_stream();
            if (!sid) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
            bool ok = true;
            for (int m = 0; m < 20 && ok; ++m) {
                std::array<std::uint8_t, 32> buf{};
                for (std::size_t got = 0; got < buf.size();) {
                    auto r = co_await ssess.read_stream(*sid, std::span(buf).subspan(got), std::chrono::steady_clock::now() + 4s);
                    if (!r || *r == 0) { ok = false; break; }
                    got += *r;
                }
                for (auto& b : buf) b ^= 0x5A;
                if (ok && !co_await ssess.write_stream(*sid, buf)) ok = false;
            }
            s_ok = ok && co_await ssess.close_stream_output(*sid);
            ssess.release_stream(*sid);
            co_return capy::results<>{};
        };
        auto client_job = [&]() -> capy::task<capy::results<>> {
            auto sid = co_await csess.open_stream();
            if (!sid) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
            bool ok = true;
            for (int m = 0; m < 20 && ok; ++m) {
                std::array<std::uint8_t, 32> req{}, resp{};
                req.fill(static_cast<std::uint8_t>(m + 1));
                if (!co_await csess.write_stream(*sid, req)) { ok = false; break; }
                for (std::size_t got = 0; got < resp.size();) {
                    auto r = co_await csess.read_stream(*sid, std::span(resp).subspan(got), std::chrono::steady_clock::now() + 4s);
                    if (!r || *r == 0) { ok = false; break; }
                    got += *r;
                }
                for (auto b : resp) ok = ok && (b == static_cast<std::uint8_t>((m + 1) ^ 0x5A));
            }
            std::array<std::uint8_t, 4> eof_buf{};
            auto tail = co_await csess.read_stream(*sid, eof_buf, std::chrono::steady_clock::now() + 4s);
            c_ok = ok && co_await csess.close_stream_output(*sid) && tail && *tail == 0;
            csess.release_stream(*sid);
            (void)co_await cp.close_output();
            csess.cancel();
            co_return capy::results<>{};
        };
        capy::run_async(ctx.get_executor())([&]() -> capy::task<> {
            (void)co_await capy::when_all(csess.run(), ssess.run(), client_job(), server_job());
        }());
        ctx.restart();
        (void)ctx.run_for(5s);
        require(c_ok && s_ok && csess.drained() && ssess.drained(), "v2 PaddingStream 20 msgs + drained");
    }

    auto test_tcp_loopback_v1_concurrent() -> void {
        io::io_context ctx;
        io::tcp_socket csock{ctx}, ssock{ctx};
        require(make_tcp_loopback(ctx, csock, ssock), "tcp loopback v1 setup");
        TcpLower cl{csock}, sl{ssock};
        mux::smux::Session<TcpLower> csess(cl, true, mux::smux::version_1), ssess(sl, false, mux::smux::version_2);
        std::atomic<int> s_done{0}, c_done{0};
        auto server_worker = [&]() -> capy::task<capy::results<>> {
            for (;;) {
                auto sid = co_await ssess.accept_stream();
                if (!sid) break;
                std::vector<std::uint8_t> data;
                std::array<std::uint8_t, 1024> buf{};
                for (;;) {
                    auto r = co_await ssess.read_stream(*sid, buf, std::chrono::steady_clock::now() + 4s);
                    if (!r) { ssess.release_stream(*sid); co_return capy::results<>{}; }
                    if (*r == 0) break;
                    data.insert(data.end(), buf.begin(), buf.begin() + *r);
                }
                if (ssess.protocol_version() == mux::smux::version_1 && co_await ssess.write_stream(*sid, data) &&
                    co_await ssess.close_stream_output(*sid)) s_done.fetch_add(1, std::memory_order_relaxed);
                ssess.release_stream(*sid);
            }
            co_return capy::results<>{};
        };
        auto client_worker = [&](int k) -> capy::task<capy::results<>> {
            auto sid = co_await csess.open_stream();
            if (!sid) co_return capy::results<>{};
            std::vector<std::uint8_t> msg(4096, static_cast<std::uint8_t>(0x30 + k)), got;
            if (co_await csess.write_stream(*sid, msg) && co_await csess.close_stream_output(*sid)) {
                std::array<std::uint8_t, 1024> buf{};
                for (;;) {
                    auto r = co_await csess.read_stream(*sid, buf, std::chrono::steady_clock::now() + 4s);
                    if (!r) break;
                    if (*r == 0) { if (got == msg) c_done.fetch_add(1, std::memory_order_relaxed); break; }
                    got.insert(got.end(), buf.begin(), buf.begin() + *r);
                }
            }
            csess.release_stream(*sid);
            co_return capy::results<>{};
        };
        capy::run_async(ctx.get_executor())([&]() -> capy::task<> {
            auto run_clients = [&]() -> capy::task<capy::results<>> {
                (void)co_await capy::when_all(client_worker(0), client_worker(1), client_worker(2), client_worker(3));
                (void)co_await cl.close_output();
                csess.cancel();
                co_return capy::results<>{};
            };
            (void)co_await capy::when_all(csess.run(), ssess.run(), run_clients(),
                server_worker(), server_worker(), server_worker(), server_worker());
        }());
        ctx.restart();
        (void)ctx.run_for(5s);
        require(c_done == 4 && s_done == 4 && ssess.protocol_version() == mux::smux::version_1 &&
                csess.drained() && ssess.drained(), "v1 auto-adopt concurrent streams + drained");
    }

    auto test_config_kdl_multiplex() -> void {
        constexpr std::string_view valid_kdl = R"kdl(
schema-version 1
role "client"
inbounds {
    vless "vless-in" { listen host="127.0.0.1" port=4443; authentication { user "u1" uuid-file="/tmp/edge.uuid"; }; tls { certificate-file "/tmp/cert.pem"; private-key-file "/tmp/key.pem"; }; multiplex { enabled #true; padding #true; max-streams 32; }; }
    trojan "trojan-in" { listen host="127.0.0.1" port=5443; authentication { user "u1" password-file="/tmp/pw"; }; tls { certificate-file "/tmp/cert.pem"; private-key-file "/tmp/key.pem"; }; multiplex { padding #false; max-streams 16; }; }
    shadowsocks "ss-in" { listen host="127.0.0.1" port=6443; method "2022-blake3-aes-128-gcm"; key-file "/tmp/ss.key"; multiplex { padding #true; max-streams 8; }; }
}
outbounds {
    direct
    vless "vless-out" { server host="edge.example.test" port=443; authentication { uuid-file "/tmp/edge.uuid"; }; tls { server-name "edge.example.test"; ca-file "/tmp/ca.pem"; verify #true; }; multiplex { protocol "smux"; max-connections 4; min-streams 2; max-streams 16; padding #true; only-tcp #true; }; }
    shadowsocks "ss-out" { server host="ss.example.test" port=8388; method "2022-blake3-aes-128-gcm"; key-file "/tmp/ss.key"; multiplex { protocol "smux-v1"; max-connections 2; min-streams 1; max-streams 8; }; }
    trojan "trojan-out" { server host="tj.example.test" port=443; authentication { password-file "/tmp/pw"; }; tls { server-name "tj.example.test"; ca-file "/tmp/ca.pem"; verify #true; }; multiplex { enabled #false; }; }
    snell "snell-out" { server host="snell.example.test" port=6160; version 5; psk-file "/tmp/snell.psk"; multiplex { protocol "smux-v2"; max-connections 1; }; }
    selector "grp" { members "vless-out" "ss-out" "trojan-out" "snell-out"; }
}
routing { final "grp"; }
)kdl";
        auto cfg = config::parse_kdl(valid_kdl);
        require(cfg.has_value(), cfg ? "" : "valid multiplex KDL: " + cfg.error());
        require(cfg->inbounds.size() == 3 && cfg->inbounds[0].vless && cfg->inbounds[0].vless->multiplex &&
                cfg->inbounds[0].vless->multiplex->enabled && cfg->inbounds[0].vless->multiplex->padding &&
                cfg->inbounds[0].vless->multiplex->max_streams == 32, "vless inbound multiplex");
        require(cfg->inbounds[1].trojan && cfg->inbounds[1].trojan->multiplex &&
                !cfg->inbounds[1].trojan->multiplex->padding && cfg->inbounds[1].trojan->multiplex->max_streams == 16, "trojan inbound mux");
        require(cfg->inbounds[2].shadowsocks && cfg->inbounds[2].shadowsocks->multiplex &&
                cfg->inbounds[2].shadowsocks->multiplex->padding && cfg->inbounds[2].shadowsocks->multiplex->max_streams == 8, "ss inbound mux");
        require(cfg->vless_outbounds.size() == 1 && cfg->vless_outbounds[0].config.multiplex &&
                cfg->vless_outbounds[0].config.multiplex->protocol == config::MultiplexProtocol::smux_v2 &&
                cfg->vless_outbounds[0].config.multiplex->max_connections == 4 && cfg->vless_outbounds[0].config.multiplex->min_streams == 2 &&
                cfg->vless_outbounds[0].config.multiplex->max_streams == 16 && cfg->vless_outbounds[0].config.multiplex->padding &&
                cfg->vless_outbounds[0].config.multiplex->only_tcp, "vless outbound multiplex");
        require(cfg->shadowsocks_outbounds.size() == 1 && cfg->shadowsocks_outbounds[0].config.multiplex &&
                cfg->shadowsocks_outbounds[0].config.multiplex->protocol == config::MultiplexProtocol::smux_v1, "ss mux v1");
        require(cfg->trojan_outbounds.size() == 1 && cfg->trojan_outbounds[0].config.multiplex &&
                !cfg->trojan_outbounds[0].config.multiplex->enabled, "trojan mux disabled");
        require(cfg->snell_outbounds.size() == 1 && cfg->snell_outbounds[0].config.multiplex &&
                cfg->snell_outbounds[0].config.multiplex->protocol == config::MultiplexProtocol::smux_v2, "snell mux");

        auto wrap_out = [](std::string_view body) {
            return std::string(R"kdl(schema-version 1
role "client"
inbounds { socks5 "s" { listen "127.0.0.1:1080"; authentication "none"; }; }
outbounds { direct; vless "v" { server "edge.test:443"; authentication { uuid-file "/tmp/u"; }; tls { server-name "edge.test"; ca-file "/tmp/c"; verify #true; }; multiplex { )kdl")
                + std::string(body) + R"kdl( }; }; }
routing { final "v"; })kdl";
        };
        auto min_only = config::parse_kdl(wrap_out(R"(min-streams 32;)"));
        require(min_only.has_value() && min_only->vless_outbounds.size() == 1 &&
                min_only->vless_outbounds[0].config.multiplex &&
                min_only->vless_outbounds[0].config.multiplex->min_streams == 32 &&
                min_only->vless_outbounds[0].config.multiplex->max_streams == 0,
                "min-streams without max-streams leaves max-streams unbounded");
        auto h2_cfg = config::parse_kdl(wrap_out(R"(protocol "h2mux"; padding #true; max-connections 2; max-streams 32;)"));
        require(h2_cfg.has_value() && h2_cfg->vless_outbounds.size() == 1 &&
                h2_cfg->vless_outbounds[0].config.multiplex &&
                h2_cfg->vless_outbounds[0].config.multiplex->protocol == config::MultiplexProtocol::h2mux &&
                h2_cfg->vless_outbounds[0].config.multiplex->padding &&
                h2_cfg->vless_outbounds[0].config.multiplex->max_connections == 2 &&
                h2_cfg->vless_outbounds[0].config.multiplex->max_streams == 32,
                "h2mux outbound multiplex KDL");
        for (std::string_view bad : {R"(protocol "yamux";)", R"(min-streams 8; max-streams 4;)", R"(min-streams 32; max-streams 16;)", R"(max-connections 0;)", R"(unknown-key #true;)"})
            require(!config::parse_kdl(wrap_out(bad)).has_value(), "invalid outbound mux rejected");
        constexpr std::string_view bad_in = R"kdl(schema-version 1
role "server"
inbounds { trojan "t" { listen "127.0.0.1:443"; authentication { user "u" password-file="/tmp/p"; }; tls { certificate-file "/tmp/c"; private-key-file "/tmp/k"; }; multiplex { protocol "smux"; }; }; }
outbounds { direct; }
routing { final "direct"; })kdl";
        require(!config::parse_kdl(bad_in).has_value(), "invalid inbound mux protocol field rejected");
    }
}

int main() {
    test_smux_wire();
    test_sing_wire_and_padding();
    test_smux_streams();
    test_tcp_loopback_v2_large();
    test_tcp_loopback_padded_20();
    test_tcp_loopback_v1_concurrent();
    test_config_kdl_multiplex();
    std::cout << "MUX UNIT TESTS PASSED\n";
    return 0;
}
