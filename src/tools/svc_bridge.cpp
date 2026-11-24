module;
#ifdef __linux__
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_tun.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#elif !defined(_WIN32)
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

module cli.proxy_services;
import std;
import config;
import logging;
import logging.cli;
import packet;
import packet.bridge;

namespace cli {
    namespace {
        auto make_bridge_cfg(config::BridgeServiceConfig const& cfg) -> packet::bridge::BridgeConfig {
            return {
                .tun_interface = cfg.tun_interface,
                .physical_interface = cfg.physical_interface,
                .mtu = cfg.mtu,
                .allow_ipv4 = cfg.allow_ipv4,
                .allow_ipv6 = cfg.allow_ipv6,
                .drop_link_local = cfg.drop_link_local,
            };
        }

#ifndef _WIN32
        auto set_nonblock(int fd) noexcept -> bool {
            int flags = ::fcntl(fd, F_GETFL, 0);
            return flags >= 0 && ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
        }

        struct BridgeState {
            packet::bridge::Layer3Bridge bridge;
            int tun_fd = -1;
            int phys_fd = -1;
            bool phys_is_af_packet = false;
            int phys_ifindex = 0;
            int wake_pipe[2]{-1, -1};
            std::atomic_bool stopping{false};
            std::atomic<std::uint64_t> forwarded_v4{0};
            std::atomic<std::uint64_t> forwarded_v6{0};
            std::atomic<std::uint64_t> dropped_ttl{0};
            std::atomic<std::uint64_t> dropped_mtu{0};
            std::atomic<std::uint64_t> dropped_loop{0};
            std::atomic<std::uint64_t> dropped_filtered{0};
            std::jthread worker;

            BridgeState(packet::bridge::BridgeConfig cfg, int tfd, int pfd, bool af_pkt, int ifidx)
                : bridge(std::move(cfg)), tun_fd(tfd), phys_fd(pfd), phys_is_af_packet(af_pkt), phys_ifindex(ifidx) {}

            ~BridgeState() { stop(); }

            auto sync_stats() noexcept -> void {
                auto const& s = bridge.stats();
                forwarded_v4.store(s.forwarded_v4, std::memory_order_relaxed);
                forwarded_v6.store(s.forwarded_v6, std::memory_order_relaxed);
                dropped_ttl.store(s.dropped_ttl, std::memory_order_relaxed);
                dropped_mtu.store(s.dropped_mtu, std::memory_order_relaxed);
                dropped_loop.store(s.dropped_loop, std::memory_order_relaxed);
                dropped_filtered.store(s.dropped_filtered, std::memory_order_relaxed);
            }

            auto stop() noexcept -> void {
                if (!stopping.exchange(true, std::memory_order_acq_rel)) {
                    if (wake_pipe[1] >= 0) {
                        std::uint8_t b = 1;
                        (void)::write(wake_pipe[1], &b, 1);
                    }
                }
                if (worker.joinable()) worker.join();
                if (wake_pipe[0] >= 0) { ::close(wake_pipe[0]); wake_pipe[0] = -1; }
                if (wake_pipe[1] >= 0) { ::close(wake_pipe[1]); wake_pipe[1] = -1; }
                if (tun_fd >= 0) { ::close(tun_fd); tun_fd = -1; }
                if (phys_fd >= 0) { ::close(phys_fd); phys_fd = -1; }
            }

            auto send_to_phys(std::span<std::uint8_t const> pkt) noexcept -> void {
                if (pkt.empty()) return;
#ifdef __linux__
                if (phys_is_af_packet) {
                    sockaddr_ll sll{};
                    sll.sll_family = AF_PACKET;
                    sll.sll_ifindex = phys_ifindex;
                    auto ver = static_cast<std::uint8_t>((pkt[0] >> 4) & 0x0f);
                    sll.sll_protocol = htons(ver == 6 ? ETH_P_IPV6 : ETH_P_IP);
                    (void)::sendto(phys_fd, pkt.data(), pkt.size(), MSG_DONTWAIT,
                        reinterpret_cast<sockaddr*>(&sll), sizeof(sll));
                    return;
                }
#endif
                (void)::write(phys_fd, pkt.data(), pkt.size());
            }

            auto pump_loop() -> void {
                std::vector<std::uint8_t> buf(std::max<std::size_t>(bridge.config().mtu + 64u, 2048u));
                pollfd pfds[3]{
                    {tun_fd, POLLIN, 0},
                    {phys_fd, POLLIN, 0},
                    {wake_pipe[0], POLLIN, 0},
                };
                while (!stopping.load(std::memory_order_acquire)) {
                    int r = ::poll(pfds, 3, -1);
                    if (r < 0) {
                        if (errno == EINTR) continue;
                        break;
                    }
                    if (pfds[2].revents & (POLLIN | POLLHUP | POLLERR)) break;
                    if (pfds[0].revents & POLLIN) {
                        for (int i = 0; i < 64 && !stopping.load(std::memory_order_relaxed); ++i) {
                            auto n = ::read(tun_fd, buf.data(), buf.size());
                            if (n <= 0) break;
                            auto fwd = bridge.forward(packet::bridge::Direction::tun_to_phys,
                                bridge.config().tun_interface, std::span(buf.data(), static_cast<std::size_t>(n)));
                            if (fwd) send_to_phys(*fwd);
                            sync_stats();
                        }
                    }
                    if (pfds[1].revents & POLLIN) {
                        for (int i = 0; i < 64 && !stopping.load(std::memory_order_relaxed); ++i) {
                            std::optional<std::array<std::uint8_t, 6>> src_mac;
                            ssize_t n = 0;
#ifdef __linux__
                            if (phys_is_af_packet) {
                                sockaddr_ll sll{}; socklen_t sl = sizeof(sll);
                                n = ::recvfrom(phys_fd, buf.data(), buf.size(), MSG_DONTWAIT,
                                    reinterpret_cast<sockaddr*>(&sll), &sl);
                                if (n <= 0) break;
                                if (sll.sll_pkttype == PACKET_OUTGOING) continue;
                                if (sll.sll_halen == 6) {
                                    std::array<std::uint8_t, 6> mac{};
                                    std::copy_n(sll.sll_addr, 6, mac.begin());
                                    src_mac = mac;
                                }
                            } else
#endif
                            {
                                n = ::read(phys_fd, buf.data(), buf.size());
                                if (n <= 0) break;
                            }
                            auto fwd = bridge.forward(packet::bridge::Direction::phys_to_tun,
                                bridge.config().physical_interface,
                                std::span(buf.data(), static_cast<std::size_t>(n)), src_mac);
                            if (fwd) (void)::write(tun_fd, fwd->data(), fwd->size());
                            sync_stats();
                        }
                    }
                    if ((pfds[0].revents | pfds[1].revents) & (POLLERR | POLLNVAL)) break;
                }
            }
        };

        auto start_pump(config::BridgeServiceConfig const& cfg, int tun_fd, int phys_fd,
            bool af_packet, int ifindex, logging::Runtime& logs) -> std::expected<ServiceHandle, std::string> {
            if (tun_fd < 0 || phys_fd < 0) return std::unexpected("bridge: invalid packet file descriptors");
            if (!set_nonblock(tun_fd) || !set_nonblock(phys_fd)) {
                ::close(tun_fd); ::close(phys_fd);
                return std::unexpected("bridge: failed to configure nonblocking FDs");
            }
            auto st = std::make_unique<BridgeState>(make_bridge_cfg(cfg), tun_fd, phys_fd, af_packet, ifindex);
            if (::pipe(st->wake_pipe) != 0)
                return std::unexpected(std::string("bridge: wake pipe failed: ") + std::strerror(errno));
            (void)set_nonblock(st->wake_pipe[0]);
            (void)set_nonblock(st->wake_pipe[1]);
            st->worker = std::jthread([ptr = st.get()] { ptr->pump_loop(); });
            logs.emit(logging::Level::info, logging::Domain::core, 101, {},
                "bridge active: {} <-> {} (mtu={})", cfg.tun_interface, cfg.physical_interface, cfg.mtu);
            return ServiceHandle::create(std::move(st));
        }
#endif
    }

    auto init_bridge_service(config::BridgeServiceConfig const& cfg, logging::Runtime& logs)
        -> std::expected<ServiceHandle, std::string> {
#ifdef __linux__
        if (cfg.tun_interface.empty() || cfg.physical_interface.empty() || cfg.tun_interface.size() >= IFNAMSIZ)
            return std::unexpected("bridge: valid tun-interface and physical-interface are required");
        unsigned ifidx = ::if_nametoindex(cfg.physical_interface.c_str());
        if (ifidx == 0)
            return std::unexpected("bridge: physical interface not found: " + cfg.physical_interface);
        int tun_fd = ::open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
        if (tun_fd < 0)
            return std::unexpected(std::string("bridge: cannot open /dev/net/tun: ") + std::strerror(errno));
        ifreq ifr{};
        std::copy(cfg.tun_interface.begin(), cfg.tun_interface.end(), ifr.ifr_name);
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL;
        if (::ioctl(tun_fd, TUNSETIFF, &ifr) < 0) {
            auto err = std::strerror(errno);
            ::close(tun_fd);
            return std::unexpected("bridge: TUNSETIFF failed for " + cfg.tun_interface + ": " + err);
        }
        int raw = ::socket(AF_PACKET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
        if (raw < 0) {
            auto err = std::strerror(errno);
            ::close(tun_fd);
            return std::unexpected(std::string("bridge: AF_PACKET socket failed: ") + err);
        }
        sockaddr_ll sll{};
        sll.sll_family = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_ALL);
        sll.sll_ifindex = static_cast<int>(ifidx);
        if (::bind(raw, reinterpret_cast<sockaddr*>(&sll), sizeof(sll)) != 0) {
            auto err = std::strerror(errno);
            ::close(tun_fd);
            ::close(raw);
            return std::unexpected(std::string("bridge: AF_PACKET bind failed: ") + err);
        }
        return start_pump(cfg, tun_fd, raw, true, static_cast<int>(ifidx), logs);
#else
        (void)cfg; (void)logs;
        return std::unexpected("bridge: L3 AF_PACKET/TUN bridging is supported on Linux");
#endif
    }

    auto init_bridge_service_with_fds(config::BridgeServiceConfig const& cfg, int tun_fd, int phys_fd, logging::Runtime& logs)
        -> std::expected<ServiceHandle, std::string> {
#ifndef _WIN32
        return start_pump(cfg, tun_fd, phys_fd, false, 0, logs);
#else
        (void)cfg; (void)tun_fd; (void)phys_fd; (void)logs;
        return std::unexpected("bridge: FD pump is not supported on Windows");
#endif
    }

    auto bridge_stats(ServiceHandle const& h) noexcept -> BridgeStatsSnapshot {
#ifndef _WIN32
        if (!h.state) return {};
        auto const* st = static_cast<BridgeState const*>(h.state.get());
        return {
            st->forwarded_v4.load(std::memory_order_relaxed),
            st->forwarded_v6.load(std::memory_order_relaxed),
            st->dropped_ttl.load(std::memory_order_relaxed),
            st->dropped_mtu.load(std::memory_order_relaxed),
            st->dropped_loop.load(std::memory_order_relaxed),
            st->dropped_filtered.load(std::memory_order_relaxed),
        };
#else
        (void)h;
        return {};
#endif
    }
}
