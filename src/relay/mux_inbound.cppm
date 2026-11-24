// Generic inbound sing-mux/smux handler shared by VLESS, Trojan, and Shadowsocks-2022.
module;
#include <boost/capy/ex/run_async.hpp>

export module relay:mux_inbound;
import std;
import capy;
import corosio;
import config;
import rules;
import socks5;
import sniff.tcp;
import sniff.tcp_io;
import sniff.route_tcp;
import net.datagram_frame;
import net.stream_datagrams;
import platform.stream_peer;
import mux.smux_wire;
import mux.sing_wire;
import mux.smux_streams;
import mux.smux_session;
import relay.stream_relay;
import :types;
import :route_interface;
import :traffic_interface;
import :session_interface;
import :internal_decls;

namespace relay::mux_in {
    template<class Stream>
    auto read_session_request(Stream& s) -> capy::task<std::optional<mux::sing::SessionRequest>> {
        std::array<std::uint8_t, 2> head{};
        if (!co_await mux::sing::read_exact(s, head)) co_return std::nullopt;
        if (head[0] > mux::sing::version_1 || head[1] != mux::sing::proto_smux) co_return std::nullopt;
        bool padded = false;
        if (head[0] == mux::sing::version_1) {
            std::array<std::uint8_t, 1> pflag{};
            if (!co_await mux::sing::read_exact(s, pflag) || pflag[0] > 1) co_return std::nullopt;
            padded = pflag[0] != 0;
            if (padded) {
                std::array<std::uint8_t, 2> plen_bytes{};
                if (!co_await mux::sing::read_exact(s, plen_bytes)) co_return std::nullopt;
                std::size_t plen = (static_cast<std::size_t>(plen_bytes[0]) << 8) | plen_bytes[1];
                std::array<std::uint8_t, 512> scratch{};
                while (plen > 0) {
                    auto take = std::min(plen, scratch.size());
                    if (!co_await mux::sing::read_exact(s, std::span(scratch).first(take))) co_return std::nullopt;
                    plen -= take;
                }
            }
        }
        co_return mux::sing::SessionRequest{head[0], head[1], padded};
    }

    template<class Stream>
    auto read_exact_deadline(Stream& s, std::span<std::uint8_t> dst, Clock::time_point deadline) -> capy::task<bool> {
        while (!dst.empty()) {
            if (Clock::now() >= deadline) co_return false;
            auto r = co_await s.read(dst, deadline);
            if (!r || *r == 0 || *r > dst.size()) co_return false;
            dst = dst.subspan(*r);
        }
        co_return true;
    }

    template<class Stream>
    auto read_stream_request(Stream& s, Clock::time_point deadline) -> capy::task<std::optional<mux::sing::StreamRequest>> {
        std::array<std::uint8_t, 3> head{};
        if (!co_await read_exact_deadline(s, head, deadline)) co_return std::nullopt;
        std::array<std::uint8_t, 264> buf{};
        std::ranges::copy(head, buf.begin());
        std::size_t rest_len = 0, pos = 3;
        if (head[2] == 1) rest_len = 6;
        else if (head[2] == 4) rest_len = 18;
        else if (head[2] == 3) {
            std::array<std::uint8_t, 1> dlen{};
            if (!co_await read_exact_deadline(s, dlen, deadline) || dlen[0] == 0) co_return std::nullopt;
            buf[pos++] = dlen[0];
            rest_len = static_cast<std::size_t>(dlen[0]) + 2;
        } else {
            co_return std::nullopt;
        }
        if (!co_await read_exact_deadline(s, std::span(buf).subspan(pos, rest_len), deadline)) co_return std::nullopt;
        auto parsed = mux::sing::decode_stream_request(std::span(buf).first(pos + rest_len));
        if (!parsed || !*parsed) co_return std::nullopt;
        co_return (*parsed)->first;
    }

    template<class SessionT>
    struct SingMuxServerStream {
        using SmuxStream = mux::smux::Stream<SessionT>;
        SmuxStream stream;
        Session& parent;
        bool response_written = false;

        SingMuxServerStream(SessionT& owner, std::uint32_t sid, Session& p)
            : stream(owner, sid), parent(p) {}

        auto read(std::span<std::uint8_t> out, std::optional<Clock::time_point> dl = {}) {
            parent.touched = Clock::now();
            return stream.read(out, dl);
        }
        auto send(std::span<std::uint8_t const> bytes, std::optional<Clock::time_point> = {}) -> capy::task<bool> {
            parent.touched = Clock::now();
            if (response_written) co_return co_await stream.send(bytes);
            std::vector<std::uint8_t> prefixed;
            prefixed.reserve(1 + bytes.size());
            prefixed.push_back(mux::sing::status_success);
            prefixed.insert(prefixed.end(), bytes.begin(), bytes.end());
            if (!co_await stream.send(prefixed)) co_return false;
            response_written = true;
            co_return true;
        }
        auto send_error(std::string_view msg) -> capy::task<bool> {
            if (response_written) co_return false;
            response_written = true;
            auto wire = mux::sing::encode_stream_response({mux::sing::status_error, std::string(msg)});
            co_return co_await stream.send(wire);
        }
        auto close_output() -> capy::task<bool> {
            if (!response_written) {
                std::array<std::uint8_t, 1> ok{mux::sing::status_success};
                if (!co_await stream.send(ok)) co_return false;
                response_written = true;
            }
            co_return co_await stream.close_output();
        }
        auto cancel() noexcept -> void { stream.cancel(); }
        auto peer_closed() const noexcept -> bool {
            return parent.closed || platform::stream_peer_closed(parent.client.native_handle());
        }
    };

    template<class In>
    auto sniff_mux_stream(void* stream, sniff::TcpSniffer& sniffer, Clock::time_point deadline)
        -> capy::task<sniff::TcpReadResult> {
        auto& incoming = *static_cast<In*>(stream);
        std::array<std::uint8_t, 4096> bytes{};
        for (;;) {
            auto state = sniffer.limit();
            if (state.status != sniff::TcpStatus::need_more) co_return {sniff::TcpReadStop::classified, state, {}};
            if (Clock::now() >= deadline) co_return {sniff::TcpReadStop::deadline, state, {}};
            auto n = co_await incoming.read(std::span(bytes).first(std::min(bytes.size(), sniffer.remaining())), deadline);
            if (!n) {
                if (Clock::now() >= deadline) co_return {sniff::TcpReadStop::deadline, sniffer.current(), {}};
                co_return {sniff::TcpReadStop::io_error, sniffer.current(), std::make_error_code(std::errc::io_error)};
            }
            if (!*n) co_return {sniff::TcpReadStop::eof, sniffer.finish(), {}};
            auto step = sniffer.feed(std::span(bytes).first(*n));
            if (step.consumed != *n)
                co_return {sniff::TcpReadStop::io_error, step, std::make_error_code(std::errc::protocol_error)};
        }
    }

    template<class SessionT>
    auto serve_mux_child(Session& parent, corosio::io_context& context, rules::RouteMatcher const& policy,
        SessionT& mux, std::uint32_t sid) -> capy::task<> {
        auto lease = parent.quota ? parent.quota->try_acquire() : std::nullopt;
        if (parent.quota && !lease) {
            mux.release_stream(sid);
            co_return;
        }
        Session child(context);
        child.quota = std::move(lease);
        init_multiplexed_child(child, parent, Clock::now() + std::chrono::seconds(10));
        if (!child.admit_principal_child(parent)) {
            mux.release_stream(sid);
            co_return;
        }

        SingMuxServerStream<SessionT> incoming(mux, sid, parent);
        std::stop_callback stop_parent(parent.stop.get_token(), [&]() noexcept { child.close(); });
        std::stop_callback stop_child(child.stop.get_token(), [&]() noexcept { incoming.cancel(); });
        if (child.closed) co_return;

        auto req = co_await read_stream_request(incoming, child.handshake_deadline);
        if (!req || child.closed) co_return;

        if (req->udp) {
            if (child.ordered_tcp && !child.ordered_tcp->udp) {
                (void)co_await incoming.send_error("UDP disabled");
                co_return;
            }
            child.begin_traffic(TrafficProtocol::xudp, req->packet_addr ? 0 : req->destination.port);
            child.select_traffic_path(ConnectPath::datagrams);
            child.relaying = true;
            child.touched = Clock::now();
            auto resolver = [&](std::string name, std::uint16_t port, Clock::time_point limit) {
                return resolve_udp_domain(child, context, std::move(name), port, limit);
            };
            auto source = source_endpoint(child, child.ordered_tcp || policy.needs_source() || child.dns_requirements().source);
            auto router = child.ordered_tcp ? ordered_datagram_router(child, context, source)
                                            : net::stream_datagrams::OrderedRouter{};
            net::DatagramFraming framing{net::AddressWire::socks, !req->packet_addr, false};
            net::stream_datagrams::Server state(child, context, incoming, policy, resolver, framing,
                req->packet_addr ? net::ProxyAddress{} : req->destination, source, std::move(router));
            try { (void)co_await capy::when_all(net::stream_datagrams::tasks(state)); }
            catch (...) { child.close(); state.cancel(); throw; }
            co_return;
        }

        socks5::Request target;
        target.status = socks5::Status::accepted;
        target.address_type = req->destination.family == net::ProxyAddressFamily::ipv4 ? 1
            : req->destination.family == net::ProxyAddressFamily::ipv6 ? 4 : 3;
        target.address_length = req->destination.length;
        target.port = req->destination.port;
        std::copy_n(req->destination.bytes.begin(), req->destination.length, target.address.begin());
        child.begin_traffic(TrafficProtocol::vless, target.port);

        if (child.ordered_tcp) {
            auto connected = co_await route_ordered_stream_tcp(child, context, target, &incoming, &sniff_mux_stream<decltype(incoming)>);
            if (!connected || child.closed) {
                (void)co_await incoming.send_error("route or dial failed");
                co_return;
            }
        } else {
            auto code = co_await dial_destination(child, context, policy, target);
            if (code != 0 || child.closed) {
                (void)co_await incoming.send_error("dial failed");
                co_return;
            }
        }
        child.relaying = true;
        child.touched = Clock::now();
        (void)co_await capy::when_all(
            stream_relay::direction(child, stream_relay::upload(child, incoming)),
            stream_relay::direction(child, stream_relay::download(child, incoming)));
    }

    struct YieldOnce {
        capy::continuation cont{};
        auto await_ready() const noexcept -> bool { return false; }
        template<class Ctx>
        auto await_suspend(std::coroutine_handle<> h, Ctx const* ctx) noexcept -> std::coroutine_handle<> {
            cont.h = h;
            ctx->executor.post(cont);
            return std::noop_coroutine();
        }
        auto await_resume() const noexcept -> void {}
    };

    template<class Lower>
    auto run_mux_server(Session& parent, corosio::io_context& context, rules::RouteMatcher const& policy,
        Lower& lower, std::uint32_t max_streams) -> capy::task<> {
        mux::smux::Limits limits{.max_streams = std::clamp<std::size_t>(max_streams, 1, 1024)};
        mux::smux::Session<Lower> mux(lower, false, mux::smux::version_2, limits);
        std::stop_callback stop_cb(parent.stop.get_token(), [&]() noexcept { mux.cancel(); });
        if (parent.closed) co_return;
        std::size_t active_children = 0;
        capy::async_event child_done;
        auto run_proto = [&]() -> capy::task<capy::results<>> {
            auto res = co_await mux.run();
            parent.close();
            co_return res;
        };
        auto accept_loop = [&]() -> capy::task<capy::results<>> {
            auto on_child_done = [&]() noexcept {
                if (active_children > 0) --active_children;
                child_done.set();
            };
            while (!parent.closed) {
                auto sid = co_await mux.accept_stream();
                if (!sid) break;
                ++active_children;
                try {
                    capy::run_async(context.get_executor(),
                        [on_child_done]() noexcept { on_child_done(); },
                        [on_child_done](std::exception_ptr) noexcept { on_child_done(); })(
                        serve_mux_child(parent, context, policy, mux, *sid));
                } catch (...) {
                    on_child_done();
                    mux.release_stream(*sid);
                }
            }
            co_return capy::results<>{};
        };
        try {
            (void)co_await capy::when_all(run_proto(), accept_loop());
        } catch (...) {
            mux.cancel();
        }
        parent.close();
        mux.cancel();
        while (active_children > 0) {
            child_done.clear();
            if (active_children == 0) break;
            auto [ec] = co_await child_done.wait();
            if (ec && active_children > 0) co_await YieldOnce{};
        }
    }
}

namespace relay {
    template<class Stream>
    auto serve_mux_session(Session& session, corosio::io_context& context, rules::RouteMatcher const& policy,
        Stream& underlying, config::InboundMultiplexConfig const& cfg) -> capy::task<> {
        auto req = co_await mux_in::read_session_request(underlying);
        if (!req || session.closed || (cfg.padding && !req->padding)) co_return;
        session.relaying = true;
        session.touched = Clock::now();
        if (req->padding) {
            mux::sing::PaddingStream<Stream> padded(underlying);
            co_await mux_in::run_mux_server(session, context, policy, padded, cfg.max_streams);
        } else {
            co_await mux_in::run_mux_server(session, context, policy, underlying, cfg.max_streams);
        }
    }
}
