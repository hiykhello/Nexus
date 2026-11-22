#pragma once

namespace proxy::http_modern_detail {
    struct HttpModernProfile {
        tls::ServerCredential credential;
        std::optional<Credentials> creds;
        bool http2 = true;
        std::uint32_t handshake_timeout_ms = 10000;
    };

    inline auto write_upstream(Session& child, std::span<std::uint8_t const> bytes) -> nex::capy::task<bool> {
        if (child.tunnel) {
            bool ok = co_await child.tunnel->send(bytes);
            if (ok) child.count_traffic(true, bytes.size());
            co_return ok;
        }
        while (!bytes.empty()) {
            auto [ec, n] = co_await child.target.write_some(nex::capy::const_buffer(bytes.data(), bytes.size()));
            if (ec || !n) co_return false;
            child.count_traffic(true, n);
            bytes = bytes.subspan(n);
        }
        co_return true;
    }

    inline auto read_upstream(Session& child, std::span<std::uint8_t> buf) -> nex::capy::task<std::expected<std::size_t, std::string>> {
        if (child.tunnel) co_return co_await child.tunnel->read(buf);
        auto [ec, n] = co_await child.target.read_some(nex::capy::mutable_buffer(buf.data(), buf.size()));
        if (nex::capy::is_eof(ec) || (!ec && !n)) co_return std::size_t{0};
        if (ec) co_return std::unexpected(ec.message());
        co_return n;
    }

    inline auto forward_h2_request(Session& child, naive::H2ServerStream<tls::detail::ByteStream<nex::corosio::tcp_socket>>& stream,
                                   std::span<http2::Header const> req_headers, std::string_view method,
                                   std::string_view authority, std::string_view path, Clock::time_point until) -> nex::capy::task<> {
        std::string wire = std::format("{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
                                       method, path.empty() ? "/" : path, authority);
        for (auto const& h : req_headers) {
            if (h.name.starts_with(':') || naive::header_ci_equal(h.name, "host") ||
                naive::header_ci_equal(h.name, "connection") || naive::header_ci_equal(h.name, "proxy-connection") ||
                naive::header_ci_equal(h.name, "proxy-authorization") || naive::header_ci_equal(h.name, "keep-alive") ||
                naive::header_ci_equal(h.name, "transfer-encoding") || naive::header_ci_equal(h.name, "upgrade"))
                continue;
            wire.append(h.name).append(": ").append(h.value).append("\r\n");
        }
        wire.append("\r\n");
        if (!co_await write_upstream(child, {reinterpret_cast<std::uint8_t const*>(wire.data()), wire.size()})) co_return;
        std::array<std::uint8_t, 8192> req_buf{};
        for (;;) {
            auto n = co_await stream.read(req_buf, Clock::now() + std::chrono::seconds(60));
            if (!n || !*n) break;
            if (!co_await write_upstream(child, std::span(req_buf).first(*n))) co_return;
        }
        if (child.tunnel) (void)co_await child.tunnel->close_output();
        else (void)child.target.shutdown(nex::corosio::shutdown_send);

        std::string resp_buf;
        std::array<std::uint8_t, 16384> rx{};
        std::size_t header_end = std::string::npos;
        while (resp_buf.size() < 32768) {
            auto got = co_await read_upstream(child, rx);
            if (!got || !*got) break;
            child.count_traffic(false, *got);
            resp_buf.append(reinterpret_cast<char const*>(rx.data()), *got);
            header_end = resp_buf.find("\r\n\r\n");
            if (header_end != std::string::npos) break;
        }
        if (header_end == std::string::npos) {
            std::array<http2::FieldView, 1> err{http2::FieldView{":status", "502"}};
            if (stream.respond(err, true)) (void)co_await stream.send_raw_chunk({}, true, until);
            co_return;
        }
        auto parsed = http::parse_forward_response(std::string_view(resp_buf).substr(0, header_end + 4), method == "HEAD");
        if (!parsed.status_code) {
            std::array<http2::FieldView, 1> err{http2::FieldView{":status", "502"}};
            if (stream.respond(err, true)) (void)co_await stream.send_raw_chunk({}, true, until);
            co_return;
        }
        std::string status_str = std::to_string(parsed.status_code);
        std::vector<std::string> lower_names, values;
        if (auto nl = std::string_view(resp_buf).find("\r\n"); nl != std::string::npos) {
            http::HeaderFieldCursor hf(std::string_view(resp_buf).substr(nl + 2, header_end - nl));
            for (auto step = hf.next(); step.status == http::HeaderFieldStatus::field; step = hf.next()) {
                std::string ln(step.field.name);
                for (char& c : ln) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
                if (ln.starts_with(':') || ln == "connection" || ln == "keep-alive" ||
                    ln == "transfer-encoding" || ln == "upgrade" || ln == "proxy-connection")
                    continue;
                lower_names.push_back(std::move(ln));
                values.emplace_back(http::trim_header_ows(step.field.value));
            }
        }
        std::vector<http2::FieldView> h2_hdrs;
        h2_hdrs.push_back({":status", status_str});
        for (std::size_t i = 0; i < lower_names.size() && h2_hdrs.size() < 96; ++i)
            h2_hdrs.push_back({lower_names[i], values[i]});
        std::string tail = resp_buf.substr(header_end + 4);
        http::ChunkDecoder chunk_dec(http::ChunkOutput::payload);
        auto emit_chunk = [&](std::string_view data, bool fin) -> nex::capy::task<bool> {
            if (parsed.chunked) {
                std::string decoded;
                auto r = chunk_dec.consume_some(data, decoded);
                if (r.status == http::ChunkStatus::malformed) co_return false;
                co_return co_await stream.send_raw_chunk(
                    {reinterpret_cast<std::uint8_t const*>(decoded.data()), decoded.size()},
                    fin || r.status == http::ChunkStatus::complete, Clock::now() + std::chrono::seconds(60));
            }
            co_return co_await stream.send_raw_chunk(
                {reinterpret_cast<std::uint8_t const*>(data.data()), data.size()}, fin, Clock::now() + std::chrono::seconds(60));
        };
        if (!stream.respond(h2_hdrs, false)) co_return;
        if (!tail.empty()) if (!co_await emit_chunk(tail, false)) co_return;
        for (;;) {
            auto got = co_await read_upstream(child, rx);
            if (!got || !*got) { (void)co_await emit_chunk({}, true); co_return; }
            child.count_traffic(false, *got);
            if (!co_await emit_chunk(std::string_view(reinterpret_cast<char const*>(rx.data()), *got), false)) co_return;
        }
    }

    struct H1StreamIncoming {
        tls::detail::ByteStream<nex::corosio::tcp_socket>& stream;
        std::string& pre;
        std::size_t off = 0;

        auto read(std::span<std::uint8_t> out, Clock::time_point dl = Clock::now() + std::chrono::seconds(300))
            -> nex::capy::task<std::expected<std::size_t, tls::detail::ByteStreamError>> {
            if (off < pre.size()) {
                auto n = std::min(out.size(), pre.size() - off);
                std::copy_n(pre.data() + off, n, reinterpret_cast<char*>(out.data()));
                off += n;
                if (off == pre.size()) { std::string{}.swap(pre); off = 0; }
                co_return n;
            }
            co_return co_await stream.read(out, dl);
        }
        auto send(std::span<std::uint8_t const> in) -> nex::capy::task<bool> {
            co_return co_await stream.send(in, Clock::now() + std::chrono::seconds(300));
        }
        auto close_output() -> nex::capy::task<bool> {
            co_return co_await stream.close_output(Clock::now() + std::chrono::seconds(30));
        }
    };

    inline auto make_dst_request(http::ConnectRequest const& cr) -> socks5::Request {
        socks5::Request dst{};
        dst.status = socks5::Status::accepted;
        dst.port = cr.port;
        if (cr.kind == http::HostKind::domain) {
            dst.address_type = 3;
            dst.address_length = static_cast<std::uint8_t>(cr.host.size());
            std::copy(cr.host.begin(), cr.host.end(), dst.address.begin());
        } else {
            dst.address_type = cr.kind == http::HostKind::ipv4 ? 1 : 4;
            dst.address_length = cr.kind == http::HostKind::ipv4 ? 4 : 16;
            std::copy(cr.address.begin(), cr.address.end(), dst.address.begin());
        }
        return dst;
    }

    inline auto serve_h1_tls(Session& session, nex::corosio::io_context& context, rules::RouteMatcher const& policy,
                             HttpModernProfile const& profile, tls::detail::ByteStream<nex::corosio::tcp_socket>& tls_stream) -> nex::capy::task<> {
        auto until = Clock::now() + std::chrono::seconds(10);
        std::string buf;
        std::array<std::uint8_t, 4096> rx{};
        std::size_t header_end = std::string::npos;
        while (buf.size() < 8192) {
            auto got = co_await tls_stream.read(rx, until);
            if (!got || !*got) co_return;
            buf.append(reinterpret_cast<char const*>(rx.data()), *got);
            header_end = buf.find("\r\n\r\n");
            if (header_end != std::string::npos) break;
        }
        auto send_txt = [&](std::string_view msg) -> nex::capy::task<bool> {
            co_return co_await tls_stream.send({reinterpret_cast<std::uint8_t const*>(msg.data()), msg.size()}, until);
        };
        if (header_end == std::string::npos) {
            (void)co_await send_txt("HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
            co_return;
        }
        if (profile.creds) {
            std::string auth_val;
            auto hdr_block = std::string_view(buf).substr(0, header_end + 4);
            if (auto nl = hdr_block.find("\r\n"); nl != std::string::npos) {
                http::HeaderFieldCursor hf(hdr_block.substr(nl + 2));
                for (auto step = hf.next(); step.status == http::HeaderFieldStatus::field; step = hf.next()) {
                    if (naive::header_ci_equal(step.field.name, "proxy-authorization")) {
                        auth_val.assign(http::trim_header_ows(step.field.value));
                        break;
                    }
                }
            }
            if (!naive_in_detail::match_basic_single(auth_val, *profile.creds)) {
                (void)co_await send_txt("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Nexus\"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
                co_return;
            }
            session.auth_user = std::string_view(reinterpret_cast<char const*>(profile.creds->username.data()), profile.creds->username_size);
            if (!session.admit_principal(*session.auth_user)) {
                (void)co_await send_txt("HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
                co_return;
            }
        }
        auto parsed = http::parse_connect(buf);
        if (parsed.status == http::ConnectStatus::accepted) {
            auto dst = make_dst_request(parsed);
            session.begin_traffic(TrafficProtocol::http_connect, dst.port);
            std::string tail = buf.substr(parsed.consumed);
            H1StreamIncoming incoming{tls_stream, tail};
            auto code = co_await naive_in_detail::dial_naive_target(session, context, policy, dst, incoming);
            if (code != 0 || session.closed) {
                (void)co_await send_txt(code == 2 ? "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                                                  : "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
                co_return;
            }
            if (!co_await send_txt("HTTP/1.1 200 Connection Established\r\n\r\n")) co_return;
            session.relaying = true;
            (void)co_await nex::capy::when_all(
                stream_relay::direction(session, stream_relay::upload(session, incoming)),
                stream_relay::direction(session, stream_relay::download(session, incoming)));
            co_return;
        }
        auto fwd = http::parse_forward_request(buf);
        if (fwd.status != http::ConnectStatus::accepted) {
            (void)co_await send_txt("HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
            co_return;
        }
        auto dst = make_dst_request(fwd.destination);
        session.begin_traffic(TrafficProtocol::http_forward, dst.port);
        std::string pre_up = fwd.wire + buf.substr(fwd.consumed);
        H1StreamIncoming incoming{tls_stream, pre_up};
        auto code = co_await naive_in_detail::dial_naive_target(session, context, policy, dst, incoming);
        if (code != 0 || session.closed) {
            (void)co_await send_txt(code == 2 ? "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                                              : "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
            co_return;
        }
        session.relaying = true;
        (void)co_await nex::capy::when_all(
            stream_relay::direction(session, stream_relay::upload(session, incoming)),
            stream_relay::direction(session, stream_relay::download(session, incoming)));
    }
}
