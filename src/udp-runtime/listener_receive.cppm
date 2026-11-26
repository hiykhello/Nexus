// Receive ownership, authentication dispatch, and staged socket binding.
module;
#include <unistd.h>

export module ss_udp.listener_receive;
import std;
import capy;
import corosio;
import shadowsocks.udp_dispatch;
import platform.udp_batch;
import ss_udp.listener_ingress;
import ss_udp.listener_route;
import ss_udp.ordered_route;

#ifdef NEXUS_TEST_UDP_PENDING
extern "C" void nexus_test_udp_pending();
#endif

export namespace shadowsocks::detail {
    struct ListenerReceiveOps {
        // A false result permits a retired policy on the same binding to
        // try authentication with its own key or accept a known old session.
        template<class Listener>
        static auto handle_datagram(Listener& owner, std::size_t index, std::span<std::uint8_t const> wire,
            UdpPeer remote, bool allow_new, std::optional<UdpRequestIdentity> identity = {}) -> bool {
            using Clock = std::chrono::steady_clock;
            if (owner.stopped_) return false;
            auto now = Clock::now();
            auto timestamp = Listener::wall();
            if (!timestamp) return true;
            auto seconds = *timestamp;
            remote.ingress = index;
            auto deadline = now + std::chrono::seconds(10);
            auto policy = owner.policies_.empty() ? nullptr : &owner.policies_[index];
            auto rejected = UdpSessionError::invalid_state;
            UdpListenerAdmission admission{allow_new, &rejected, identity};
            auto pending = owner.sniff_owner_ ?
                owner.state_.dispatcher().begin_ordered(owner.state_.key(), wire, remote, now, seconds, deadline, admission) :
                owner.state_.dispatcher().begin(owner.state_.key(), wire, remote, now, seconds, deadline, policy, admission, bool(owner.ordered_));
            if (!pending) return rejected != UdpSessionError::packet && rejected != UdpSessionError::other_listener_generation;
            struct PendingGuard {
                UdpDispatcher& dispatcher;
                std::uint64_t token;
                bool transferred = false;
                ~PendingGuard() { if (!transferred) (void)dispatcher.cancel(token); }
            } guard{owner.state_.dispatcher(), pending->token};
#ifdef NEXUS_TEST_UDP_PENDING
            nexus_test_udp_pending();
#endif
            if (owner.sniff_owner_) {
                auto packet = owner.state_.dispatcher().pending_packet(pending->token);
                if (!packet) return true;
                auto decision = std::make_shared<OrderedUdpDecision>(*packet, *owner.ordered_->program,
                    policy ? policy->inbound() : std::nullopt, owner.ordered_->skip_unknown, owner.ordered_->fallback, now);
                if (!owner.sniff_owner_->submit(pending->token, std::move(decision), deadline, now)) return true;
                guard.transferred = true;
                ListenerRouteOps::drain_ordered(owner);
                return true;
            }
            auto const& a = pending->address;
            if (a.empty()) return true;
            if (a[0] == 3) {
                guard.transferred = ListenerRouteOps::start_resolution(owner, std::move(*pending), remote,
                    policy ? policy->inbound() : std::nullopt, deadline);
            } else {
                if (a[0] != 1 && a[0] != 4) return true;
                UdpPeer target{};
                target.family = a[0] == 1 ? 4 : 6;
                auto size = target.family == 4 ? 4u : 16u;
                if (a.size() != size + 3) return true;
                std::copy_n(a.begin() + 1, size, target.address.begin());
                target.port = static_cast<std::uint16_t>((static_cast<unsigned>(a[size + 1]) << 8) | a[size + 2]);
                std::array candidates{target};
                if (owner.ordered_)
                    guard.transferred = ListenerRouteOps::send_legacy(owner, pending->token, candidates,
                        policy ? policy->inbound() : std::nullopt, deadline).has_value();
                else
                    (void)owner.state_.dispatcher().complete(pending->token, candidates, now);
            }
            return true;
        }

        template<class Listener>
        static auto receive(Listener& owner, std::size_t index) -> udp_capy::task<> {
            std::array<std::uint8_t, 65536> buffer{};
#if defined(__linux__)
            std::vector<std::uint8_t> batch_slab;
            if (owner.ingress_) batch_slab.resize(8 * 65536);
#endif
            auto const& cancellation = owner.receive_stops_[index];
            while (!cancellation.stop_requested() && owner.ingress_ && owner.ingress_->generation() < owner.generation_) {
                auto [error] = co_await udp_io::delay(std::chrono::milliseconds(2));
                if (error && !cancellation.stop_requested()) { owner.stop(); co_return; }
            }
            while (!cancellation.stop_requested()) {
                if (owner.ingress_) {
                    auto [error] = co_await owner.sockets_[index]->wait(udp_io::wait_type::read);
                    if (cancellation.stop_requested()) break;
                    if (error) { owner.stop(); break; }
#if defined(__linux__)
                    std::array<platform::UdpRecvSlot, 8> slots{};
                    std::array<std::optional<UdpListenerIngress::Datagram>, 8> dgs{};
                    for (std::size_t i = 0; i < 8; ++i) {
                        slots[i].data = batch_slab.data() + i * 65536;
                        slots[i].capacity = 65536;
                    }
                    for (unsigned round = 0; round < 2 && !cancellation.stop_requested(); ++round) {
                        auto got = UdpListenerIngress::read_batch(owner.sockets_[index]->native_handle(), slots, dgs);
                        if (!got) { owner.stop(); co_return; }
                        if (*got == 0) break;
                        for (std::size_t i = 0; i < *got && !cancellation.stop_requested(); ++i) {
                            if (!dgs[i]) continue;
                            owner.ingress_->route(owner.endpoints_[index], owner.generation_,
                                std::span(slots[i].data, dgs[i]->size), dgs[i]->source);
                        }
                        if (*got < slots.size()) break;
                    }
#else
                    // Ready-only burst drain (up to 16 already-queued datagrams per wakeup).
                    for (unsigned burst = 0; burst < 16 && !cancellation.stop_requested(); ++burst) {
                        auto packet = UdpListenerIngress::read(owner.sockets_[index]->native_handle(), buffer);
                        if (!packet) { owner.stop(); co_return; }
                        if (!*packet) break;
                        auto const& datagram = **packet;
                        owner.ingress_->route(owner.endpoints_[index], owner.generation_,
                            std::span(buffer).first(datagram.size), datagram.source);
                    }
#endif
                    continue;
                }
                udp_io::endpoint source;
                auto [error, n] = co_await owner.sockets_[index]->recv_from(
                    udp_capy::mutable_buffer(buffer.data(), buffer.size()), source);
                if (cancellation.stop_requested()) break;
                if (error) { owner.stop(); break; }
                auto remote = Listener::peer(source);
                if (remote && n <= 65535)
                    (void)handle_datagram(owner, index, std::span(buffer).first(n), *remote, true);
            }
        }

        template<class Listener>
        [[nodiscard]] static auto identity_route(Listener const& owner, std::size_t index) noexcept -> UdpIdentityRoute const* {
            return owner.identities_.empty() || !owner.identities_[index] ? nullptr : &*owner.identities_[index];
        }

        template<class Listener>
        static auto bind_socket(Listener& owner, udp_io::udp_socket& socket, udp_io::endpoint endpoint, bool share)
            -> std::expected<bool, std::error_code> {
            if (owner.ingress_) {
                auto duplicate = owner.ingress_->duplicate(endpoint, owner.generation_, share);
                if (!duplicate) return std::unexpected(duplicate.error());
                if (duplicate->fd >= 0) {
                    if (auto error = socket.assign(duplicate->fd)) {
                        ::close(duplicate->fd);
                        return std::unexpected(error);
                    }
                    return duplicate->receive;
                }
            }
            if (auto error = socket.open(endpoint.address().family())) return std::unexpected(error);
            if (auto error = socket.bind(endpoint)) return std::unexpected(error);
            return true;
        }

        template<class Listener>
        static auto register_ingress(Listener& owner) -> void {
            if (!owner.ingress_) return;
            for (std::size_t index = 0; index < owner.sockets_.size(); ++index)
                owner.ingress_->add(owner.endpoints_[index], owner.generation_, owner.sockets_[index]->native_handle(),
                    &owner, index, identity_route(owner, index),
                    [](void* ptr, std::size_t slot, std::span<std::uint8_t const> wire, UdpPeer source, bool allow_new,
                       std::optional<UdpRequestIdentity> identity) {
                        return handle_datagram(*static_cast<Listener*>(ptr), slot, wire, source, allow_new, identity);
                    },
                    [](void* ptr, std::size_t slot) noexcept {
                        static_cast<Listener*>(ptr)->receive_stops_[slot].request_stop();
                    });
        }
    };
}
