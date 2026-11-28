// Private SOCKS5 UDP alias tunnel state, UotState, and UDP helper declarations.
module relay:session_udp_alias_tunnel;
import std;
import capy;
import corosio;
import containers.lru_slab;
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
        static constexpr std::size_t limit = alias_udp_slots;
        using Readers = net::LazyReaders<0>;
        enum class Send { dropped, forwarded, retry };

        struct AliasKey {
            socks5::UdpPeer alias, target;
            std::size_t outbound = 0;
            auto operator==(AliasKey const&) const noexcept -> bool = default;
        };

        struct AliasKeyHash {
            auto operator()(AliasKey const& k) const noexcept -> std::size_t {
                std::uint64_t h = 14695981039346656037ull;
                auto mix = [&](std::uint64_t v) noexcept { h = (h ^ v) * 1099511628211ull; };
                auto mix_peer = [&](socks5::UdpPeer const& p) noexcept {
                    mix((static_cast<std::uint64_t>(p.address_type) << 16) | p.port);
                    std::uint64_t a = 0, b = 0;
                    std::memcpy(&a, p.address.data(), 8); mix(a);
                    if (p.address_type == 4) { std::memcpy(&b, p.address.data() + 8, 8); mix(b); }
                };
                mix(static_cast<std::uint64_t>(k.outbound));
                mix_peer(k.alias);
                mix_peer(k.target);
                return static_cast<std::size_t>(h ^ (h >> 32));
            }
        };

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
            std::shared_ptr<Relay> relay;
            capy::async_event ready;
        };

        containers::LruSlab<AliasKey, Entry, AliasKeyHash> slab_;
        std::size_t reader_base_ = ordinary_udp_slots;

        explicit UotAliasTunnels(std::size_t soft_cap = limit, std::size_t reader_base = ordinary_udp_slots) noexcept
            : slab_(soft_cap), reader_base_(reader_base) {}

        [[nodiscard]] auto size() const noexcept -> std::size_t { return slab_.size(); }
        [[nodiscard]] auto soft_cap() const noexcept -> std::size_t { return slab_.soft_cap(); }

        auto cancel() noexcept -> void {
            slab_.for_each([](std::uint32_t, AliasKey const&, Entry& entry) noexcept {
                if (entry.relay) entry.relay->cancel();
                entry.ready.set();
            });
        }

        auto expire(Clock::time_point now) noexcept -> void {
            using namespace std::chrono_literals;
            slab_.for_each_lru_to_mru([&](std::uint32_t, AliasKey const&, Entry& entry) noexcept {
                if (!entry.relay) return;
                auto& relay = *entry.relay;
                if (relay.deadline ? now >= *relay.deadline : now - relay.touched >= 60s)
                    relay.cancel();
            });
        }

        auto send(Session& session, io::io_context& context, Readers& readers,
            socks5::UdpTunnelPacket const& packet, TunnelFactory const& factory) -> capy::task<Send> {
            auto const& alias = *packet.alias;
            AliasKey key{alias.endpoint, packet.target, packet.outbound};
            std::uint32_t slot_idx = 0;
            if (auto hit = slab_.find_index_and_touch(key)) {
                slot_idx = *hit;
                auto& entry = slab_.slot_value(slot_idx);
                if (!entry.relay || entry.relay->closing) {
                    if (entry.relay && !entry.relay->deadline) entry.relay.reset();
                    if (!entry.relay) {
                        auto r = std::make_shared<Relay>();
                        r->alias = alias.endpoint; r->target = packet.target;
                        r->outbound = packet.outbound; r->lease = alias.lease;
                        entry.relay = std::move(r);
                    }
                }
            } else if (auto fresh = slab_.emplace(key)) {
                slot_idx = *fresh;
                auto r = std::make_shared<Relay>();
                r->alias = alias.endpoint; r->target = packet.target;
                r->outbound = packet.outbound; r->lease = alias.lease;
                slab_.slot_value(slot_idx).relay = std::move(r);
            } else {
                auto recycled = slab_.rekey_lru(key, [](std::uint32_t, AliasKey const&, Entry& victim) noexcept {
                    if (victim.relay) victim.relay->cancel();
                    victim.relay.reset();
                    victim.ready.clear();
                });
                if (!recycled) co_return Send::dropped;
                slot_idx = *recycled;
                auto r = std::make_shared<Relay>();
                r->alias = alias.endpoint; r->target = packet.target;
                r->outbound = packet.outbound; r->lease = alias.lease;
                slab_.slot_value(slot_idx).relay = std::move(r);
            }
            auto& entry = slab_.slot_value(slot_idx);
            auto relay_ptr = entry.relay;
            if (!relay_ptr) co_return Send::dropped;
            auto& relay = *relay_ptr;
            auto until = packet.deadline;
            if (!relay.tunnel)
                until = std::min(until, Clock::now() + std::chrono::milliseconds(factory.timeout_ms));
            relay.deadline = until;
            struct Finish {
                Entry& entry;
                std::shared_ptr<Relay> relay;
                ~Finish() {
                    relay->deadline.reset();
                    if (!relay->reader_requested || relay->reader_finished) {
                        relay->cancel();
                        if (entry.relay == relay) entry.relay.reset();
                    }
                }
            } finish{entry, relay_ptr};
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
                if (!readers.request(reader_base_ + slot_idx)) co_return Send::dropped;
                relay.reader_requested = true;
                entry.ready.set();
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
            auto& entry = slab_.slot_value(static_cast<std::uint32_t>(index));
            while (!session.closed && !readers.stopped()) {
                auto relay = entry.relay;
                if (!relay || !relay->reader_requested || relay->reader_finished) {
                    entry.ready.clear();
                    if (entry.relay && entry.relay->reader_requested && !entry.relay->reader_finished) continue;
                    auto [error] = co_await entry.ready.wait();
                    if (error) session.close();
                    continue;
                }
#ifdef NEXUS_ENABLE_VLESS
                if (relay->xudp_client) co_await read_xudp(session, ingress, *relay);
                else
#endif
                    co_await uot_read_framed(session, ingress, relay->tunnel, relay->authorization, relay->framing,
                        uot_address(relay->target), &relay->alias, &relay->closing, &relay->touched);
                relay->cancel();
                relay->reader_finished = true;
                if (!relay->deadline && entry.relay == relay) entry.relay.reset();
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
        std::shared_ptr<UdpFakeIpLease> const& lease, rules::RouteProgram const* policy, socks5::UdpPeer const& source,
        std::optional<std::size_t> rule = {}, std::size_t outbound = 0) -> capy::task<void>;
    auto udp_resolve_alias(Session& session, io::io_context& context, socks5::UdpIngress& ingress,
        UdpResolution& resolution, rules::RouteProgram const& policy) -> capy::task<void>;
#endif

    struct UotState {
        net::RoutedDatagramSlots<UotSlot, routed_udp_slots> routed;
        net::FixedDatagramSlots<UotSlot, socks5::UdpPeer, fixed_udp_slots> fixed;
        net::LazyReaders<0> readers;
#ifdef NEXUS_ENABLE_FAKEIP
        std::unique_ptr<UotAliasTunnels> aliases;
        std::size_t alias_cap = alias_udp_slots;
#endif
        std::optional<Clock::time_point> active_deadline;

        explicit UotState(std::size_t routed_cap = routed_udp_slots, std::size_t fixed_cap = fixed_udp_slots,
            [[maybe_unused]] std::size_t aliases_cap = alias_udp_slots) noexcept
            : routed(routed_cap), fixed(fixed_cap),
#ifdef NEXUS_ENABLE_FAKEIP
              readers(routed_cap + fixed_cap + aliases_cap), alias_cap(aliases_cap)
#else
              readers(routed_cap + fixed_cap)
#endif
        {}

        [[nodiscard]] auto ordinary_limit() const noexcept -> std::size_t { return routed.soft_cap() + fixed.soft_cap(); }

        auto slot_at(std::size_t index) -> UotSlot& {
            return index < routed.soft_cap() ? routed.slot(index) : fixed.slot(index - routed.soft_cap());
        }

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
                slot.reader_done.set();
            };
            routed.for_each(close);
            fixed.for_each(close);
        }
    };

    auto uot_sender(Session& session, io::io_context& context, socks5::UdpIngress& ingress, UotState& state)
        -> capy::task<capy::results<>>;
    auto uot_reader(Session& session, socks5::UdpIngress& ingress, UotState& state, std::size_t index)
        -> capy::task<capy::results<>>;
#endif
}
