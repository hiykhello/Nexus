module;
#if defined(__linux__)
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
#endif

module cli.tun_enabled;
import std;
import config;
import relay;
import cli.tun_host;
import cli.masque_tun;
import packet.tun_network_types;

namespace cli::tun_enabled {
    namespace {
        auto receive_tun_fd_from_env_socket() -> std::expected<std::optional<int>, std::string> {
#if defined(__linux__)
            char const* env = std::getenv("NEXUS_TUN_FD_SOCK");
            if (!env || env[0] == '\0') return std::optional<int>{};
            std::string_view path(env);
            sockaddr_un addr{};
            if (path.size() >= sizeof(addr.sun_path)) return std::unexpected("NEXUS_TUN_FD_SOCK path exceeds sun_path");
            addr.sun_family = AF_UNIX;
            std::ranges::copy(path, addr.sun_path);
            int sock = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
            if (sock < 0) return std::unexpected(std::string("NEXUS_TUN_FD_SOCK socket failed: ") + std::strerror(errno));
            struct CloseSock { int fd; ~CloseSock() { if (fd >= 0) ::close(fd); } } guard{sock};
            timeval tv{.tv_sec = 2, .tv_usec = 0};
            (void)::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            (void)::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            if (::connect(sock, reinterpret_cast<sockaddr const*>(&addr), sizeof(addr)) != 0)
                return std::unexpected(std::string("NEXUS_TUN_FD_SOCK connect failed: ") + std::strerror(errno));
            char req = 1;
            if (::send(sock, &req, 1, MSG_NOSIGNAL) != 1)
                return std::unexpected(std::string("NEXUS_TUN_FD_SOCK send failed: ") + std::strerror(errno));
            char resp = 0;
            iovec iov{&resp, 1};
            alignas(cmsghdr) std::array<char, CMSG_SPACE(sizeof(int) * 4)> cbuf{};
            msghdr msg{};
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cbuf.data();
            msg.msg_controllen = cbuf.size();
            auto n = ::recvmsg(sock, &msg, MSG_CMSG_CLOEXEC);
            if (n <= 0) return std::unexpected("NEXUS_TUN_FD_SOCK recvmsg failed");
            int received_fd = -1;
            for (cmsghdr* cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
                if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS &&
                    cm->cmsg_len >= CMSG_LEN(sizeof(int))) {
                    std::size_t count = (cm->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                    for (std::size_t i = 0; i < count; ++i) {
                        int fd = -1;
                        std::memcpy(&fd, CMSG_DATA(cm) + i * sizeof(int), sizeof(int));
                        if (received_fd < 0 && fd >= 0) received_fd = fd;
                        else if (fd >= 0) ::close(fd);
                    }
                }
            }
            if (received_fd < 0) return std::unexpected("NEXUS_TUN_FD_SOCK yielded no TUN descriptor");
            return std::optional<int>{received_fd};
#else
            return std::optional<int>{};
#endif
        }
    }
    Runtime::~Runtime() { stop(); }
    auto Runtime::resize(std::size_t count) -> void { entries_.resize(count); }

    auto Runtime::configure(std::size_t index, config::InboundConfig const& entry, config::Config const& config)
        -> std::expected<void, std::string> {
        if (!entry.tun) return {};
        if (index >= entries_.size() || entries_[index]) return std::unexpected("invalid TUN slot");
        entries_[index].emplace(Entry{*entry.tun, nullptr});
        auto& redirect=entries_[index]->redirect;
        auto const& extra = entry.tun->extra;
        redirect.input_mark = extra.auto_redirect_input_mark.value_or(0);
        redirect.output_mark = extra.auto_redirect_output_mark.value_or(0);
        redirect.reset_mark = extra.auto_redirect_reset_mark.value_or(0);
        for (auto const& r : extra.include_uids)
            if (redirect.include_uid_count < redirect.include_uids.size())
                redirect.include_uids[redirect.include_uid_count++] = {r.min, r.max};
        for (auto user_id : extra.include_android_users) {
            if (redirect.include_uid_count < redirect.include_uids.size()) {
                std::uint32_t base = user_id * 100000u;
                redirect.include_uids[redirect.include_uid_count++] = {base, base + 99999u};
            }
        }
        for (auto const& r : extra.exclude_uids)
            if (redirect.exclude_uid_count < redirect.exclude_uids.size())
                redirect.exclude_uids[redirect.exclude_uid_count++] = {r.min, r.max};
        for (auto const& ifn : extra.include_interfaces) {
            if (redirect.include_if_count < redirect.include_interfaces.size())
                std::ranges::copy_n(ifn.data(), std::min<std::size_t>(ifn.size(), 15),
                    redirect.include_interfaces[redirect.include_if_count++].begin());
        }
        for (auto const& ifn : extra.exclude_interfaces) {
            if (redirect.exclude_if_count < redirect.exclude_interfaces.size())
                std::ranges::copy_n(ifn.data(), std::min<std::size_t>(ifn.size(), 15),
                    redirect.exclude_interfaces[redirect.exclude_if_count++].begin());
        }
        bool has_hijack_dns=config.ordered_tcp &&
            std::ranges::any_of(config.ordered_tcp->rules,[](auto const& rule) {
                return rule.action==config::OrderedTcpAction::hijack_dns;
            });
        if (entry.tun->strict_route && has_hijack_dns && config.dns)
            entries_[index]->config.dns_hijack_tcp=true;
        if (entry.tun->strict_route) {
            redirect.tcp_dns=entries_[index]->config.dns_hijack_tcp;
            redirect.udp_dns=config.ordered_tcp && config.ordered_tcp->udp && has_hijack_dns;
            if (config.dns && config.dns->fakeip) {
                auto const& fake=*config.dns->fakeip;
                if (entry.tun->inet4_address) {
                    auto& prefix=redirect.protected_destinations[redirect.protected_count++];
                    prefix.family=4;
                    prefix.prefix=static_cast<std::uint8_t>(std::countl_zero(fake.last^fake.first));
                    for (unsigned i=0;i<4;++i) prefix.bytes[i]=static_cast<std::uint8_t>(fake.first>>(24-8*i));
                }
                if (entry.tun->inet6_address && fake.ipv6) {
                    auto& prefix=redirect.protected_destinations[redirect.protected_count++];
                    prefix.family=6;
                    prefix.prefix=fake.ipv6->second;
                    std::ranges::copy(fake.ipv6->first,prefix.bytes.begin());
                }
            }
        }
        if (auto const& name = entry.tun->connect_ip_outbound) {
            auto group=std::ranges::find(config.selectors,*name,&config::OutboundSelector::name);
            if (group!=config.selectors.end() && (group->uses_probe || group->uses_balance))
                return std::unexpected("CONNECT-IP TUN requires a manual outbound group");
            auto found = std::ranges::find(config.masque_outbounds,config::selected_outbound(config,*name),&config::NamedMasqueOutbound::name);
            if (found == config.masque_outbounds.end() || !found->config.connect_ip)
                return std::unexpected("TUN requires a named MASQUE CONNECT-IP outbound");
            auto outbound = found->config;
            std::optional<std::string> lower_host;
            if (outbound.detour_index) {
                if (*outbound.detour_index == 0) outbound.tcp_options.binding = config.direct_tcp_options.binding;
                else {
                    auto next=config::selected_outbound(config,*outbound.detour);
                    auto tunnel=[&](auto const& nodes,auto&& inspect) -> bool {
                        using Node=std::ranges::range_value_t<decltype(nodes)>;
                        auto found=std::ranges::find(nodes,next,&Node::name);
                        if (found==nodes.end() || !inspect(found->config)) return false;
                        auto const& hop=found->config;
                        if (hop.detour_index.value_or(0)) next=config::selected_outbound(config,*hop.detour);
                        else lower_host=hop.host;
                        return true;
                    };
                    bool requires_packets=true;
                    for (std::size_t step=0;!lower_host && step<config.tunnel_count();++step) {
                        if (!tunnel(config.trojan_outbounds,[](auto const&) {return true;}) &&
                            !tunnel(config.shadowsocks_outbounds,[&](auto const& hop) {return !requires_packets || hop.udp_over_tcp;}))
                            break;
                        requires_packets=false;
                    }
                    if (!lower_host) return std::unexpected("CONNECT-IP TUN detour requires a Trojan or Shadowsocks chain with a datagram-capable final hop");
                    if (entry.tun->socket_mark)
                        return std::unexpected("CONNECT-IP TUN socket-mark belongs to the physical detour outbound");
                    if (std::ranges::count_if(config.inbounds, [](auto const& in) {return in.tun.has_value();}) != 1)
                        return std::unexpected("CONNECT-IP TUN detour requires a single TUN inbound");
                }
            }
            entries_[index]->masque = std::make_unique<MasqueTunHost>(*entry.tun, std::move(outbound), std::move(lower_host));
        }
        return {};
    }

    auto Runtime::start(std::size_t index, relay::Server& server) -> std::expected<std::string, std::string> {
        if (index >= entries_.size() || !entries_[index]) return std::unexpected("TUN inbound not configured");
        auto& e = *entries_[index];
        if (e.masque) return e.masque->start(server);
        if (e.device_adopted) return std::unexpected("TUN device-fd has already been adopted");
        auto tun_cfg = e.config;
        auto tun_redirect = e.redirect;
        auto global_bridge = platform::global_tun_bridge();
        auto fd_override = (!tun_cfg.extra.bridge_mode && !global_bridge && !tun_cfg.device_fd)
            ? platform::consume_external_tun_fd() : std::optional<platform::ExternalTunFdOverride>{};
        std::optional<int> env_tun_fd;
        if (!tun_cfg.extra.bridge_mode && !global_bridge && !fd_override) {
            auto env_res = receive_tun_fd_from_env_socket();
            if (!env_res) { failure_ = env_res.error(); return std::unexpected(env_res.error()); }
            if (*env_res) {
                env_tun_fd = *env_res;
                tun_cfg.device_fd.reset();
                fd_override = platform::ExternalTunFdOverride{*env_tun_fd, true, true};
            }
        }
        if (tun_cfg.extra.bridge_mode || global_bridge || fd_override) {
            tun_cfg.interface_name.clear();
            tun_cfg.inet4_address.reset();
            tun_cfg.inet6_address.reset();
            tun_cfg.auto_route = false;
            tun_cfg.strict_route = false;
            tun_cfg.auto_redirect = false;
        }
        auto cfg_device_fd = tun_cfg.device_fd;
        e.host = std::make_unique<TunHost>(server, std::move(tun_cfg), true, tun_redirect);
        auto started = [&]() -> std::expected<std::string, std::string> {
            if (e.config.extra.bridge_mode || global_bridge) {
                auto bridge = global_bridge ? std::move(global_bridge)
                    : std::make_shared<platform::ExternalTunBridge>(e.config.mtu);
                return e.host->start(std::move(bridge));
            }
            bool has_cfg_fd = cfg_device_fd.has_value();
            if (!has_cfg_fd && !fd_override) return e.host->start();
            int fd_num = has_cfg_fd ? cfg_device_fd->number : fd_override->fd;
            bool adopt = has_cfg_fd ? cfg_device_fd->adopt : fd_override->adopt;
            bool skip_ioctl = e.config.extra.device_fd_skip_ioctl || (fd_override && fd_override->skip_ioctl);
            auto device = packet::attach_platform_tun(fd_num, adopt, skip_ioctl);
            if (!device) {
#if defined(__linux__)
                if (adopt && fd_override && fd_num >= 0) ::close(fd_num);
#endif
                if (auto* system = std::get_if<std::error_code>(&device.error()))
                    return std::unexpected("failed attaching TUN device-fd: " + system->message());
                return std::unexpected("TUN device-fd must be a valid nonblocking read/write TUN");
            }
            e.device_adopted = adopt;
            return e.host->start(std::move(*device));
        }();
        if (!started) { failure_ = started.error(); e.host.reset(); return std::unexpected(started.error()); }
        return *started;
    }

    auto Runtime::begin_drain() noexcept -> void {
        for (auto& e : entries_) if (e && e->host) e->host->begin_drain();
    }

    auto Runtime::drained() const noexcept -> bool {
        return std::ranges::all_of(entries_, [](auto const& e) {
            return !e || !e->host || e->host->drained();
        });
    }

    auto Runtime::queue_outbound_probe(std::size_t index,std::shared_ptr<relay::OutboundProbe> probe) -> bool {
        return index<entries_.size() && entries_[index] && entries_[index]->host &&
            entries_[index]->host->queue_outbound_probe(std::move(probe));
    }

    auto Runtime::healthy() const noexcept -> bool {
        return std::ranges::all_of(entries_, [](auto const& e) {
            if (!e) return true;
            if (e->masque) return e->masque->healthy();
            return !e->host || e->host->healthy();
        });
    }

    auto Runtime::failure() const -> std::optional<std::string> {
        for (auto const& e : entries_) if (e) {
            if (e->masque) if (auto err = e->masque->failure()) return err;
            if (e->host) if (auto err = e->host->failure()) return err;
        }
        return failure_;
    }

    auto Runtime::stop() noexcept -> void {
        for (auto& e : entries_) if (e) {
            if (e->masque) e->masque->stop();
            if (e->host) e->host->stop();
        }
    }
}
