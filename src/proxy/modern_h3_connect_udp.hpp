#pragma once

namespace proxy::naive_in_detail {
    template<class H3H>
    auto send_h3_status(H3H& h, std::string_view code, std::string_view auth_challenge, Clock::time_point until) -> nex::capy::task<> {
        if (auth_challenge.empty()) {
            std::array<nex::nghttp3::nghttp3_nv, 2> hdrs{naive::h3_nv(":status", code), naive::h3_nv("content-length", "0")};
            if (h.respond(hdrs, true)) (void)co_await h.send_raw({}, true, until);
        } else {
            std::array<nex::nghttp3::nghttp3_nv, 3> hdrs{
                naive::h3_nv(":status", code), naive::h3_nv("proxy-authenticate", auth_challenge), naive::h3_nv("content-length", "0")};
            if (h.respond(hdrs, true)) (void)co_await h.send_raw({}, true, until);
        }
    }

    template<class H3H>
    auto run_connect_udp_direct(Session& child, Session& parent, nex::corosio::io_context& context,
                                H3H& h, masque::UdpTarget const& target, Clock::time_point until) -> nex::capy::task<> {
        nex::corosio::endpoint peer;
        if (auto ip = platform::parse_ip_address(target.host)) {
            if (ip->size == 4) {
                std::array<unsigned char, 4> b{};
                std::copy_n(ip->bytes.begin(), 4, b.begin());
                peer = {nex::corosio::ipv4_address(b), target.port};
            } else {
                peer = {nex::corosio::ipv6_address(ip->bytes), target.port};
            }
        } else {
            auto eps = co_await resolve_udp_domain(child, context, target.host, target.port, until,
                                                   child.datagram_source ? &*child.datagram_source : nullptr);
            if (!eps || eps->empty()) { co_await send_h3_status(h, "502", {}, until); co_return; }
            peer = eps->front();
        }
        nex::corosio::udp_socket udp(context);
        if (net::prepare_udp_socket(udp, peer, child.direct_tcp_options ? &child.direct_tcp_options->binding : nullptr, until)) {
            co_await send_h3_status(h, "502", {}, until);
            co_return;
        }
        auto* st_raw = h.state();
        if (!st_raw) co_return;
        st_raw->is_datagram = true;
        std::array<nex::nghttp3::nghttp3_nv, 2> ok_hdrs{naive::h3_nv(":status", "200"), naive::h3_nv("capsule-protocol", "?1")};
        if (!h.respond(ok_hdrs, true)) co_return;
        child.relaying = true;
        auto up = [&]() -> nex::capy::task<nex::capy::results<>> {
            while (!child.closed && !parent.closed) {
                auto pkt = co_await h.recv_datagram(Clock::now() + std::chrono::seconds(120));
                if (!pkt) break;
                auto [ec, n] = co_await udp.send_to(nex::capy::const_buffer(pkt->data(), pkt->size()), peer);
                if (ec) break;
                child.touched = parent.touched = Clock::now();
                child.count_traffic(true, n);
            }
            child.close();
            co_return nex::capy::results<>{};
        };
        auto dn = [&]() -> nex::capy::task<nex::capy::results<>> {
            std::array<std::uint8_t, 2048> buf{};
            while (!child.closed && !parent.closed) {
                nex::corosio::endpoint from;
                auto [ec, n] = co_await udp.recv_from(nex::capy::mutable_buffer(buf.data(), buf.size()), from);
                if (ec || !n) break;
                if (from != peer) continue;
                if (!h.send_datagram(std::span(buf).first(n))) break;
                child.touched = parent.touched = Clock::now();
                child.count_traffic(false, n);
            }
            child.close();
            co_return nex::capy::results<>{};
        };
        std::stop_callback sc(parent.stop.get_token(), [&]() noexcept { child.close(); udp.close(); });
        (void)co_await nex::capy::when_all(up(), dn());
    }

    template<class H3H>
    auto run_connect_udp_tunnel(Session& child, Session& parent, nex::corosio::io_context& context, std::size_t outbound,
                                H3H& h, masque::UdpTarget const& target, Clock::time_point until) -> nex::capy::task<> {
        if (!child.tunnel_factories || outbound < 2 || outbound - 2 >= child.tunnel_factories->size()) {
            co_await send_h3_status(h, "502", {}, until); co_return;
        }
        child.tunnel = (*child.tunnel_factories)[outbound - 2](child, context, false);
        if (!child.tunnel) { co_await send_h3_status(h, "502", {}, until); co_return; }
        auto pt = child.tunnel->packet_transport();
        net::ProxyAddress pa{};
        pa.port = target.port;
        if (auto ip = platform::parse_ip_address(target.host)) {
            pa.family = ip->size == 4 ? net::ProxyAddressFamily::ipv4 : net::ProxyAddressFamily::ipv6;
            pa.length = static_cast<std::uint8_t>(ip->size);
            std::copy_n(ip->bytes.begin(), pa.length, pa.bytes.begin());
        } else {
            pa.family = net::ProxyAddressFamily::domain;
            pa.length = static_cast<std::uint8_t>(std::min<std::size_t>(255, target.host.size()));
            std::copy_n(target.host.begin(), pa.length, pa.bytes.begin());
        }
        net::DatagramFraming framing{};
        if (pt.kind == net::PacketTransportKind::framed) {
            framing = pt.framing;
            if (co_await child.tunnel->connect_packets(pa, until) != TunnelConnectResult::connected) {
                co_await send_h3_status(h, "502", {}, until); co_return;
            }
        } else if (child.tunnel->has_uot()) {
            framing = {net::AddressWire::uot, false, false};
            if (co_await child.tunnel->connect_uot_until(until) != TunnelConnectResult::connected) {
                co_await send_h3_status(h, "502", {}, until); co_return;
            }
            auto req = uot::encode_request({false, pa});
            if (!req || !co_await child.tunnel->send(*req)) { co_await send_h3_status(h, "502", {}, until); co_return; }
        } else {
            co_await send_h3_status(h, "502", {}, until); co_return;
        }
        auto* st_raw = h.state();
        if (!st_raw) co_return;
        st_raw->is_datagram = true;
        std::array<nex::nghttp3::nghttp3_nv, 2> ok_hdrs{naive::h3_nv(":status", "200"), naive::h3_nv("capsule-protocol", "?1")};
        if (!h.respond(ok_hdrs, true)) co_return;
        child.select_traffic_path(ConnectPath::tunnel);
        child.relaying = true;
        auto up = [&]() -> nex::capy::task<nex::capy::results<>> {
            while (!child.closed && !parent.closed) {
                auto pkt = co_await h.recv_datagram(Clock::now() + std::chrono::seconds(120));
                if (!pkt) break;
                auto wire = net::encode_datagram(framing, pa, *pkt);
                if (!wire || !co_await child.tunnel->send(*wire)) break;
                child.touched = parent.touched = Clock::now();
                child.count_traffic(true, pkt->size());
            }
            child.close();
            co_return nex::capy::results<>{};
        };
        auto dn = [&]() -> nex::capy::task<nex::capy::results<>> {
            std::array<std::uint8_t, 65536> buf{};
            net::DatagramDecoder dec(framing, pa);
            while (!child.closed && !parent.closed) {
                auto n = co_await child.tunnel->read(buf);
                if (!n || !*n) break;
                auto span = std::span(buf).first(*n);
                while (!span.empty()) {
                    auto step = dec.feed(span);
                    span = span.subspan(step.consumed);
                    if (step.status == net::DatagramStatus::accepted) {
                        if (auto dg = dec.packet()) {
                            if (!h.send_datagram(dg->payload)) break;
                            child.count_traffic(false, dg->payload.size());
                        }
                        (void)dec.consume();
                    } else if (step.status != net::DatagramStatus::incomplete) break;
                }
                child.touched = parent.touched = Clock::now();
            }
            child.close();
            co_return nex::capy::results<>{};
        };
        std::stop_callback sc(parent.stop.get_token(), [&]() noexcept { child.close(); });
        (void)co_await nex::capy::when_all(up(), dn());
    }

    template<class H3H>
    auto serve_connect_udp_stream(Server& server, Session& parent, nex::corosio::io_context& context,
                                  H3H& h, std::string_view path,
                                  std::optional<std::string_view> auth_user, Clock::time_point until) -> nex::capy::task<> {
        auto target = masque::parse_well_known_udp_target(path);
        if (!target) { co_await send_h3_status(h, "400", {}, until); co_return; }
        auto lease = parent.quota ? parent.quota->try_acquire() : std::nullopt;
        if (parent.quota && !lease) { co_await send_h3_status(h, "503", {}, until); co_return; }
        Session child(context);
        child.quota = std::move(lease);
        if (auth_user) child.auth_user = *auth_user;
        init_naive_child(child, parent, until);
        if (!child.admit_principal_child(parent)) { co_await send_h3_status(h, "403", {}, until); co_return; }
        child.begin_traffic(TrafficProtocol::http3_udp, target->port);
        child.select_traffic_path(ConnectPath::datagrams);
        auto const& policy = parent.route_snapshot ? parent.route_snapshot->matcher : server.routing_policy();
        rules::MatchInput mi{.port = target->port, .network = rules::Network::udp, .auth_user = child.auth_user};
        if (platform::parse_ip_address(target->host)) mi.ip = target->host;
        else mi.domain = target->host;
        if (child.inbound) mi.inbound = *child.inbound;
        auto matched = policy.match(child.ingress.apply(mi));
        if (!matched || *matched == 1) { co_await send_h3_status(h, "403", {}, until); co_return; }
        if (*matched == 0) co_await run_connect_udp_direct(child, parent, context, h, *target, until);
        else co_await run_connect_udp_tunnel(child, parent, context, *matched, h, *target, until);
    }
}
