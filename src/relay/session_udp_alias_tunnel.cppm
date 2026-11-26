// Private SOCKS5 UDP alias tunnel state, UotState, and UDP helper declarations.
module relay:session_udp_alias_tunnel;
import std;
import capy;
import corosio;
import net.datagram_frame;
import net.lazy_readers;
import relay.request_backend;
import proxy.v4;
import rules;
import socks5;
import socks5.udp_ingress;
import socks5.udp_tunnel_authorization;
import uot;
import xudp;
import xudp.client_io;
import xudp.client_sessions;
import :types;
import :tunnel_facade;
import :session_interface;
import :session_udp_types;

namespace relay::session_udp_detail {
#ifdef NEXUS_ENABLE_SOCKS_UDP
#ifdef NEXUS_ENABLE_FAKEIP
    struct UotAliasTunnels {
        static constexpr std::size_t limit = 16;
        using Readers = net::LazyReaders<ordinary_udp_slots + limit>;
        enum class Send { dropped, forwarded, retry };

        struct Relay {
            socks5::UdpPeer alias, target;
            std::size_t outbound;
            std::shared_ptr<void> lease;
            pro::proxy<TunnelFacade> tunnel;
            socks5::UdpTunnelAuthorization authorization;
            net::DatagramFraming framing;
#ifdef NEXUS_ENABLE_VLESS
            XudpStream xudp_stream;
            std::unique_ptr<xudp::ClientIo<XudpStream>> xudp_client;
            std::uint16_t xudp_session = 0, ended_session = 0;
#endif
            Clock::time_point touched = Clock::now();
            std::optional<Clock::time_point> deadline;
            bool reader_requested = false, reader_finished = false, closing = false;

            auto cancel() noexcept -> void {
                if (closing) return;
                closing = true;
#ifdef NEXUS_ENABLE_VLESS
                if (xudp_client) {
                    xudp_client->cancel();
                    return;
                }
#endif
                if (tunnel) tunnel->cancel();
            }
        };

        struct Entry {
            std::unique_ptr<Relay> relay;
            capy::async_event ready;
        };
        std::array<Entry, limit> entries;

        auto cancel() noexcept -> void {
            for (auto& entry : entries) {
                if (entry.relay) entry.relay->cancel();
                entry.ready.set();
            }
        }

        auto expire(Clock::time_point now) noexcept -> void {
            using namespace std::chrono_literals;
            for (auto& entry : entries) {
                if (!entry.relay) continue;
                auto& relay = *entry.relay;
                if (relay.deadline ? now >= *relay.deadline : now - relay.touched >= 60s)
                    relay.cancel();
            }
        }

        auto send(Session& session, io::io_context& context, Readers& readers,
            socks5::UdpTunnelPacket const& packet, TunnelFactory const& factory) -> capy::task<Send> {
            auto const& alias = *packet.alias;
            auto entry = std::ranges::find_if(entries, [&](Entry const& candidate) {
                return candidate.relay && !candidate.relay->closing && candidate.relay->alias == alias.endpoint &&
                    candidate.relay->target == packet.target && candidate.relay->outbound == packet.outbound;
            });
            if (entry == entries.end()) {
                entry = std::ranges::find_if(entries, [](Entry const& candidate) { return !candidate.relay; });
                if (entry == entries.end()) co_return Send::dropped;
                entry->relay = std::make_unique<Relay>();
                entry->relay->alias = alias.endpoint;
                entry->relay->target = packet.target;
                entry->relay->outbound = packet.outbound;
                entry->relay->lease = alias.lease;
            }
            auto& relay = *entry->relay;
            auto until = packet.deadline;
            if (!relay.tunnel)
                until = std::min(until, Clock::now() + std::chrono::milliseconds(factory.timeout_ms));
            relay.deadline = until;
            struct Finish {
                Entry& entry;
                ~Finish() {
                    auto& relay = *entry.relay;
                    relay.deadline.reset();
                    if (!relay.reader_requested || relay.reader_finished) {
                        relay.cancel();
                        entry.relay.reset();
                    }
                }
            } finish{*entry};
            auto active = [&] { return !session.closed && !relay.closing && Clock::now() < until; };
            if (!relay.tunnel) {
                relay.tunnel = factory(session, context);
                if (!relay.tunnel) co_return Send::dropped;
                auto transport = relay.tunnel->packet_transport();
                if (transport.kind == net::PacketTransportKind::none || !active()) co_return Send::dropped;
                auto connected = co_await relay.tunnel->connect_packets(uot_address(relay.target), until);
                if (connected != TunnelConnectResult::connected || !active()) co_return Send::dropped;
                if (transport.kind == net::PacketTransportKind::framed) {
                    relay.framing = transport.framing;
                    if (transport.needs_uot_request) {
                        auto request = uot::encode_request({false, uot_address(relay.target)});
                        if (!request || !co_await relay.tunnel->send(*request) || !active()) co_return Send::dropped;
                    }
                } else {
#ifdef NEXUS_ENABLE_VLESS
                    relay.xudp_stream = {&relay.tunnel, &relay.deadline, &session.closed};
                    relay.xudp_client = std::make_unique<xudp::ClientIo<XudpStream>>(relay.xudp_stream, 1);
#else
                    co_return Send::dropped;
#endif
                }
                auto index = static_cast<std::size_t>(entry - entries.begin()) + ordinary_udp_slots;
                if (!readers.request(index)) co_return Send::dropped;
                relay.reader_requested = true;
                entry->ready.set();
            }
            if (!active()) co_return Send::dropped;
            auto credit = session.reserve_principal_datagram(true, packet.packet.data.size());
            if (!credit) co_return Send::dropped;
#ifdef NEXUS_ENABLE_VLESS
            if (relay.xudp_client) {
                credit->submit();
                auto sent = co_await send_xudp(relay, packet.packet.data);
                if (sent == Send::forwarded) credit->complete(packet.packet.data.size());
                else if (sent == Send::retry) credit->complete(0);
                if (sent == Send::forwarded && active()) {
                    session.count_traffic(true, packet.packet.data.size());
                    relay.touched = Clock::now();
                    co_return sent;
                }
                relay.cancel();
                co_return sent == Send::retry ? sent : Send::dropped;
            }
#endif
            auto frame = net::encode_datagram(relay.framing, uot_address(relay.target), packet.packet.data);
            if (!frame) co_return Send::dropped;
            auto token = relay.authorization.begin(relay.target);
            if (!token) co_return Send::dropped;
            credit->submit();
            auto sent = co_await relay.tunnel->send(*frame);
            if (sent) {
                credit->complete(packet.packet.data.size());
                session.count_traffic(true, packet.packet.data.size());
            }
            sent = sent && active();
            (void)relay.authorization.finish(*token, sent);
            if (!sent) {
                relay.cancel();
                co_return Send::dropped;
            }
            relay.touched = Clock::now();
            co_return Send::forwarded;
        }

#ifdef NEXUS_ENABLE_VLESS
        static auto send_xudp(Relay& relay, std::span<std::uint8_t const> payload) -> capy::task<Send> {
            auto target = xudp_address(relay.target);
            if (relay.xudp_session) {
                auto sent = co_await relay.xudp_client->send(relay.xudp_session, target, payload);
                if (sent) co_return Send::forwarded;
                if (sent.error() != xudp::ClientIoError::session || relay.xudp_session)
                    co_return Send::dropped;
            }
            auto opened = co_await relay.xudp_client->open(target, payload);
            if (!opened)
                co_return opened.error() == xudp::ClientIoError::exhausted ? Send::retry : Send::dropped;
            if (*opened != relay.ended_session) relay.xudp_session = *opened;
            co_return Send::forwarded;
        }

        static auto read_xudp(Session& session, socks5::UdpIngress& ingress, Relay& relay) -> capy::task<> {
            using namespace std::chrono_literals;
            while (!session.closed && !relay.closing) {
                auto event = co_await relay.xudp_client->read();
                if (!event) co_return;
                if (event->action == xudp::Incoming::ended) {
                    relay.ended_session = event->session;
                    if (event->session == relay.xudp_session) relay.xudp_session = 0;
                    continue;
                }
                while (!session.closed && !relay.closing) {
                    auto queued = ingress.queue_tunnel_reply(relay.alias, event->payload);
                    if (!queued) co_return;
                    if (*queued != socks5::UdpReplyStatus::busy) {
                        if (*queued == socks5::UdpReplyStatus::queued) relay.touched = Clock::now();
                        break;
                    }
                    auto [error] = co_await io::delay(1ms);
                    if (error) co_return;
                }
            }
        }
#endif

        auto read(Session& session, socks5::UdpIngress& ingress, Readers& readers, std::size_t index)
            -> capy::task<capy::results<>> {
            auto& entry = entries[index];
            while (!session.closed && !readers.stopped()) {
                if (!entry.relay || entry.relay->reader_finished) {
                    entry.ready.clear();
                    auto [error] = co_await entry.ready.wait();
                    if (error) session.close();
                    continue;
                }
                auto& relay = *entry.relay;
#ifdef NEXUS_ENABLE_VLESS
                if (relay.xudp_client) co_await read_xudp(session, ingress, relay);
                else
#endif
                    co_await uot_read_framed(session, ingress, relay.tunnel, relay.authorization, relay.framing,
                        uot_address(relay.target), &relay.alias, &relay.closing, &relay.touched);
                relay.cancel();
                relay.reader_finished = true;
                if (!relay.deadline) entry.relay.reset();
            }
            co_return capy::results<>{};
        }
    };

    struct UdpFakeIpLease {
        std::unique_ptr<dns::FakeIpShared::Target> target;
        ~UdpFakeIpLease() {
            if (target) try { (void)target->release(); } catch (...) {}
        }
    };

    auto udp_fakeip_target(Session& session, socks5::UdpDatagram const& packet)
        -> std::expected<dns::SharedFakeIpRequest, dns::FakeIpRegistryError>;
    auto udp_fakeip_domain(socks5::UdpDatagram packet, socks5::Request const& request) -> socks5::UdpDatagram;
    auto udp_send_alias(Session& session, socks5::UdpIngress& ingress, UdpResolution& resolution,
        socks5::UdpDatagram const& domain, std::span<io::endpoint const> endpoints,
        std::shared_ptr<UdpFakeIpLease> const& lease, rules::RouteMatcher const* policy, socks5::UdpPeer const& source,
        std::optional<std::size_t> rule = {}, std::size_t outbound = 0) -> capy::task<void>;
    auto udp_resolve_alias(Session& session, io::io_context& context, socks5::UdpIngress& ingress,
        UdpResolution& resolution, rules::RouteMatcher const& policy) -> capy::task<void>;
#endif

    struct UotState {
        std::array<std::unique_ptr<UotSlot>, routed_udp_slots> slots;
        net::FixedDatagramSlots<UotSlot, socks5::UdpPeer, fixed_udp_slots> fixed;
        auto slot_at(std::size_t index) -> UotSlot& {
            if (index < routed_udp_slots) {
                if (!slots[index]) slots[index] = std::make_unique<UotSlot>();
                return *slots[index];
            }
            return fixed.slot(index - routed_udp_slots);
        }
#ifdef NEXUS_ENABLE_FAKEIP
        std::unique_ptr<UotAliasTunnels> aliases;
        UotAliasTunnels::Readers readers;
#else
        net::LazyReaders<ordinary_udp_slots> readers;
#endif
        std::optional<Clock::time_point> active_deadline;
        auto cancel() noexcept -> void {
            readers.stop();
#ifdef NEXUS_ENABLE_FAKEIP
            if (aliases) aliases->cancel();
#endif
            auto close = [](UotSlot& slot) noexcept {
#ifdef NEXUS_ENABLE_VLESS
                if (slot.xudp_client) slot.xudp_client->cancel();
                else
#endif
                if (slot.tunnel) slot.tunnel->cancel();
                slot.readiness.set();
            };
            for (auto const& slot : slots) if (slot) close(*slot);
            fixed.for_each(close);
        }
    };

    auto uot_sender(Session& session, io::io_context& context, socks5::UdpIngress& ingress, UotState& state)
        -> capy::task<capy::results<>>;
    auto uot_reader(Session& session, socks5::UdpIngress& ingress, UotState& state, std::size_t index)
        -> capy::task<capy::results<>>;
#endif
}
