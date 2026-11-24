// Non-TLS outbound HTTP/2 PING and HTTPS probe entry points.
module relay;
import :probe_h2_wire;
import std;
import capy;

namespace relay {
    auto Server::probe_https(Session& session, OutboundProbe& probe) -> capy::task<bool> {
        (void)session;
        (void)probe;
        co_return false;
    }

    auto Server::probe_h2_ping(Session& session, OutboundProbe& probe)
        -> capy::task<std::optional<std::uint32_t>> {
        if (probe.use_tls) co_return std::nullopt;
        if (co_await dial_destination(session, context, probe.route, probe.target, probe.deadline)) {
            co_return std::nullopt;
        }
        session.handshake_deadline = probe.deadline;
        co_return co_await probe_h2_detail::exchange_plain_h2_ping(session, probe);
    }
}
