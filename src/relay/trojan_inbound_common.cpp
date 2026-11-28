module relay;
import std;
import capy;
import corosio;
import rules;
import socks5;
import sniff.tcp;
import sniff.tcp_io;
import sniff.route_tcp;
import tls.byte_stream;
import trojan;
import trojan.stream;
import net.stream_datagrams;
import mux.sing_wire;
import relay.stream_relay;
import :types;
import :route_interface;
import :session_interface;
import :traffic_interface;
import :internal_decls;
import :mux_inbound;
import :trojan_inbound_common;

namespace relay::trojan_in {
    namespace {
        auto sniff_trojan_plaintext(void* context, sniff::TcpSniffer& sniffer, Clock::time_point deadline)
            -> capy::task<sniff::TcpReadResult> {
            auto& incoming = *static_cast<TrojanInboundRef*>(context);
            std::array<std::uint8_t, 4096> buffer{};
            for (;;) {
                auto state = sniffer.limit();
                if (state.status != sniff::TcpStatus::need_more) co_return {sniff::TcpReadStop::classified, state, {}};
                if (Clock::now() >= deadline) co_return {sniff::TcpReadStop::deadline, state, {}};
                auto result = co_await incoming.read_sniff(
                    std::span(buffer).first(std::min(buffer.size(), sniffer.remaining())), deadline);
                if (!result) {
                    if (result.error() == tls::detail::ByteStreamError::timeout)
                        co_return {sniff::TcpReadStop::deadline, sniffer.current(), {}};
                    co_return {sniff::TcpReadStop::io_error, sniffer.current(), std::make_error_code(std::errc::io_error)};
                }
                if (!*result) co_return {sniff::TcpReadStop::eof, sniffer.finish(), {}};
                auto accepted = sniffer.feed(std::span(buffer).first(*result));
                if (accepted.consumed != *result)
                    co_return {sniff::TcpReadStop::io_error, accepted, std::make_error_code(std::errc::protocol_error)};
            }
        }
        [[gnu::noinline]] auto serve_ordered_tcp(Session& session, corosio::io_context& context,
            socks5::Request const& target, TrojanInboundRef& incoming, Clock::time_point deadline) -> capy::task<bool> {
            OrderedTcpRequest request;
            if (!request.prepare(session, target)) co_return false;
            std::array<std::uint8_t, 16640> wire{}, scratch{};
            sniff::TcpSniffer sniffer(wire, scratch); rules::ProgramCursor cursor;
            auto const& ordered = *session.ordered_tcp;
            OrderedTcpResult result;
            if (session.transport_owner) {
                result = co_await execute_ordered_tcp(session, context, ordered.program, cursor, request.input, sniffer,
                    request.candidates, request.endpoints, ordered.fallback,
                    std::min(deadline, Clock::now() + ordered.sniff_timeout),
                    deadline, ordered.unknown_policy, &incoming, &sniff_trojan_plaintext);
            } else {
                auto branch = [&]() -> capy::task<capy::results<OrderedTcpResult>> {
                    auto r = co_await execute_ordered_tcp(session, context, ordered.program, cursor, request.input, sniffer,
                        request.candidates, request.endpoints, ordered.fallback,
                        std::min(deadline, Clock::now() + ordered.sniff_timeout),
                        deadline, ordered.unknown_policy, &incoming, &sniff_trojan_plaintext);
                    co_return capy::results<OrderedTcpResult>{std::make_error_code(std::errc::operation_canceled), std::move(r)};
                };
                auto [signal, r, watch] = co_await capy::when_all(branch(), watch_client_error(session));
                (void)signal; (void)watch;
                result = std::move(r);
            }
            if (session.closed || result.stop != sniff::RouteTcpStop::terminal || result.code) co_return false;
            sniff::TcpReplay replay(result.first_sent ? std::span<std::uint8_t const>{} : sniffer.wire());
            co_return co_await replay_ordered_tcp(session, replay, deadline);
        }
    }

    auto serve_trojan_stream(Session& session, corosio::io_context& context, rules::RouteProgram const& policy,
        TrojanInboundProfile const& profile, TrojanInboundRef& incoming, Clock::time_point deadline,
        std::optional<trojan::detail::AcceptedRequest> pre_accepted)
        -> capy::task<> {
        auto accepted = pre_accepted ? std::move(pre_accepted) : co_await incoming.read_request(deadline);
        if (!accepted || session.closed || accepted->user >= profile.users.size()) co_return;
        if (!profile.names.empty() && !session.admit_principal(profile.names[accepted->user])) co_return;
        if (accepted->request.command == trojan::Command::udp) {
            if (session.ordered_tcp && !session.ordered_tcp->udp) co_return;
            session.begin_traffic(TrafficProtocol::trojan_udp, 0);
            session.select_traffic_path(ConnectPath::datagrams);
            session.relaying = true; session.touched = Clock::now();
            auto resolver = [&](std::string name, std::uint16_t port, Clock::time_point limit) {
                return resolve_udp_domain(session, context, std::move(name), port, limit);
            };
            auto source = source_endpoint(session, session.ordered_tcp || policy.needs_source() || session.dns_requirements().source);
            auto router = session.ordered_tcp ? ordered_datagram_router(session, context, source)
                                              : net::stream_datagrams::OrderedRouter{};
            net::stream_datagrams::Server state(session, context, incoming, policy, resolver,
                trojan::datagram_framing, net::ProxyAddress{}, source, std::move(router));
            try { (void)co_await capy::when_all(net::stream_datagrams::tasks(state)); }
            catch (...) { session.close(); state.cancel(); throw; }
            co_return;
        }
        auto const& destination = accepted->request.destination;
        if (profile.multiplex && profile.multiplex->enabled && destination.family == trojan::Family::domain &&
            mux::sing::is_mux_destination(
                std::string_view(reinterpret_cast<char const*>(destination.bytes.data()), destination.length),
                destination.port)) {
            co_await serve_mux_session(session, context, policy, incoming, *profile.multiplex);
            co_return;
        }
        socks5::Request target; target.status = socks5::Status::accepted;
        target.address_type = destination.family == trojan::Family::ipv4 ? 1
                            : destination.family == trojan::Family::ipv6 ? 4 : 3;
        target.address_length = destination.length; target.port = destination.port;
        std::copy_n(destination.bytes.begin(), destination.length, target.address.begin());
        session.begin_traffic(TrafficProtocol::trojan, target.port);
        if (session.ordered_tcp) {
            if (!co_await serve_ordered_tcp(session, context, target, incoming, deadline)) co_return;
        } else {
            auto dialed = session.transport_owner
                ? co_await dial_destination(session, context, policy, target, deadline)
                : co_await dial(session, context, policy, target);
            if (dialed || session.closed) co_return;
        }
        session.relaying = true; session.touched = Clock::now();
        try {
            (void)co_await capy::when_all(
                stream_relay::direction(session, stream_relay::upload(session, incoming)),
                stream_relay::direction(session, stream_relay::download(session, incoming)));
        } catch (...) { session.close(); throw; }
    }
}
