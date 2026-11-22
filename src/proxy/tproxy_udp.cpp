module;
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <proxy/proxy_macros.h>

module proxy;
import proxy.v4;
import std;
import net.udp_socket;
import net.stream_datagrams;
import proxy.request_backend;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

namespace proxy {
    using namespace std::chrono_literals;
#include "tproxy_reply_cache.hpp"

    namespace {
        auto decode(void const* data,std::size_t size,bool ipv6) noexcept -> std::optional<net::UdpEndpoint> {
            net::UdpEndpoint endpoint{};
            if (ipv6) {
                sockaddr_in6 address{};
                if(size!=sizeof(address)) return {};
                std::memcpy(&address,data,size);
                if(address.sin6_family!=AF_INET6 || address.sin6_scope_id) return {};
                endpoint.family=6;
                endpoint.port=ntohs(address.sin6_port);
                std::memcpy(endpoint.address.data(),&address.sin6_addr,16);
            } else {
                sockaddr_in address{};
                if(size!=sizeof(address)) return {};
                std::memcpy(&address,data,size);
                if(address.sin_family!=AF_INET) return {};
                endpoint.family=4;
                endpoint.port=ntohs(address.sin_port);
                std::memcpy(endpoint.address.data(),&address.sin_addr,4);
            }
            if (!endpoint.port) return {};
            return endpoint;
        }

        struct Incoming {
            static constexpr bool native_packets=true;
            TproxyReplySocketCache* reply_cache=nullptr;
            std::optional<std::uint32_t> mark;
            net::UdpEndpoint client,target;
#ifdef NEXUS_ENABLE_FAKEIP
            dns::FakeIpShared* fakeip=nullptr;
            bool alias=false;
            auto allows_target(net::UdpEndpoint const& endpoint) const -> bool {
                return !fakeip || bool(dns::validate_fakeip_resolution(*fakeip,
                    std::span(endpoint.address).first(endpoint.family==4 ? 4 : 16)));
            }
#endif
            auto send_packet(net::ProxyAddress const& source,std::span<std::uint8_t const> data) -> nex::capy::task<bool> {
                if (!reply_cache) co_return false;
#ifdef NEXUS_ENABLE_FAKEIP
                // The relay validates the real reply source on its own socket or stream.
                if (alias) co_return reply_cache->send(target,mark,client,data);
#endif
                auto expected=net::stream_datagrams::peer_address(target);
                if(source.family!=expected.family || source.port!=expected.port || source.length!=expected.length ||
                    !std::ranges::equal(std::span(source.bytes).first(source.length),std::span(expected.bytes).first(expected.length)))
                    co_return false;
                co_return reply_cache->send(target,mark,client,data);
            }
        };
        struct Resolve {
            Session& session;
            nex::corosio::io_context& context;
            net::UdpEndpoint source;
            auto operator()(std::string name,std::uint16_t port,Clock::time_point deadline) {
                return resolve_udp_domain(session,context,std::move(name),port,deadline,&source);
            }
        };
        struct Flow {
            Session session;
            Incoming incoming;
            net::ProxyAddress route_target;
            using Relays=net::stream_datagrams::Server<Session,Incoming,Resolve>;
            std::optional<Relays> relays;
            std::uint32_t ingress_ifindex=0;
            std::array<char,IF_NAMESIZE> ingress_name{};
            bool active=true;
            explicit Flow(nex::corosio::io_context& context) : session(context) {}
        };
    }

    class TransparentUdp {
        Server& server_;
        Socket socket_;
        TproxyReplySocketCache reply_cache_;
        net::UdpEndpoint listen_;
        std::optional<std::uint32_t> mark_;
        std::vector<std::unique_ptr<Flow>> flows_;
        static constexpr std::size_t flow_limit=128;

        auto accept(net::UdpEndpoint const& client,TransparentDatagram const& incoming) -> Flow* {
            auto const& target=incoming.original_destination;
            auto entry=std::ranges::find_if(flows_,[&](auto const& flow) {
                return !flow->session.closed && flow->incoming.client==client && flow->incoming.target==target &&
                    flow->ingress_ifindex==incoming.ingress_ifindex;
            });
            if (entry!=flows_.end()) return entry->get();
            if (flows_.size()==flow_limit) return nullptr;
            auto lease=server_.acquire_session();
            if (!lease) return nullptr;
            auto& context=server_.executor_context();
            auto flow=std::make_unique<Flow>(context);
            server_.attach_session(flow->session,std::move(*lease));
            flow->route_target=net::stream_datagrams::peer_address(target);
            std::optional<bool> fakeip_alias;
#ifdef NEXUS_ENABLE_FAKEIP
            if (auto* owner=flow->session.fakeip) {
                flow->incoming.fakeip=owner;
                socks5::Request request{.status=socks5::Status::accepted,
                    .address_type=target.family==4 ? std::uint8_t{1} : std::uint8_t{4},
                    .address_length=target.family==4 ? std::uint8_t{4} : std::uint8_t{16},.port=target.port};
                std::ranges::copy(std::span(target.address).first(request.address_length),request.address.begin());
                auto translated=dns::translate_fakeip_request(*owner,request,flow->session.fakeip_view);
                if (!translated) return nullptr;
                fakeip_alias=bool(translated->target);
                if (translated->target) {
                    flow->session.fakeip_target=std::move(translated->target);
                    flow->incoming.alias=true;
                    flow->route_target.family=net::ProxyAddressFamily::domain;
                    flow->route_target.length=translated->request.address_length;
                    std::copy_n(translated->request.address.begin(),flow->route_target.length,flow->route_target.bytes.begin());
                }
            }
#endif
            if (reply_cache_.ensure_bound(target,mark_)) return nullptr;
            flow->incoming.reply_cache=&reply_cache_;
            flow->incoming.mark=mark_;
            flow->incoming.client=client;
            flow->incoming.target=target;
            flow->ingress_ifindex=incoming.ingress_ifindex;
            if (flow->ingress_ifindex && ::if_indextoname(flow->ingress_ifindex,flow->ingress_name.data()))
                flow->session.source_interface=flow->ingress_name.data();
            // UDP carries no sender credentials.
            flow->session.datagram_source=client;
            flow->session.relaying=true;
            flow->session.begin_traffic(TrafficProtocol::tproxy_udp,target.port,incoming);
            flow->session.select_traffic_path(ConnectPath::datagrams);
            auto const& policy=flow->session.route_snapshot ? flow->session.route_snapshot->matcher : server_.routing_policy();
            auto router=flow->session.ordered_tcp && flow->session.ordered_tcp->udp ?
                ordered_datagram_router(flow->session,context,client,fakeip_alias) : net::stream_datagrams::OrderedRouter{};
            flow->relays.emplace(flow->session,context,flow->incoming,policy,
                Resolve{flow->session,context,client},net::DatagramFraming{},net::ProxyAddress{},client,std::move(router));
            auto* current=flow.get();
            flows_.push_back(std::move(flow));
            try {
                nex::capy::run_async(context.get_executor(),[current] {
                    current->session.close();
                    current->active=false;
                },[current](std::exception_ptr) noexcept {
                    current->session.close();
                    current->active=false;
                })(relay(*current));
            } catch (...) {
                flows_.pop_back();
                throw;
            }
            return current;
        }

        static auto relay(Flow& flow) -> nex::capy::task<> {
            (void)co_await nex::capy::when_all(net::stream_datagrams::tasks(*flow.relays));
        }

    public:
        TransparentUdp(Server& server,std::optional<std::uint32_t> mark)
            : server_(server),mark_(mark) {
            flows_.reserve(flow_limit);
        }
        auto start(nex::corosio::endpoint endpoint,bool reuse) -> std::error_code {
            listen_.family=endpoint.is_v6() ? 6 : 4;
            listen_.port=endpoint.port();
            if (endpoint.is_v6()) std::ranges::copy(endpoint.address().to_v6().to_bytes(),listen_.address.begin());
            else std::ranges::copy(endpoint.address().to_v4().to_bytes(),listen_.address.begin());
            reply_cache_.refresh_netns();
            return socket_.bind(listen_,true,reuse);
        }
        auto poll() -> std::error_code {
            std::erase_if(flows_,[](auto const& flow) {return !flow->active;});
            reply_cache_.reap_idle(Clock::now());
            std::array<std::uint8_t,65536> payload{};
            bool ipv6=listen_.family==6;
            for (unsigned count=0;count<32;++count) {
                sockaddr_storage address{};
                alignas(cmsghdr) std::array<unsigned char,
                    CMSG_SPACE(sizeof(sockaddr_in6))+CMSG_SPACE(sizeof(in6_pktinfo))+CMSG_SPACE(sizeof(int))> control{};
                iovec data{payload.data(),payload.size()};
                msghdr header{.msg_name=&address,.msg_namelen=sizeof(address),.msg_iov=&data,.msg_iovlen=1,
                    .msg_control=control.data(),.msg_controllen=control.size()};
                auto size=::recvmsg(socket_.fd,&header,MSG_DONTWAIT);
                if (size<0) {
                    if (errno==EAGAIN || errno==EWOULDBLOCK) break;
                    if (errno==EINTR) continue;
                    return {errno,std::generic_category()};
                }
                if (header.msg_flags&(MSG_TRUNC|MSG_CTRUNC)) continue;
                auto client=decode(&address,header.msg_namelen,ipv6);
                std::optional<net::UdpEndpoint> target;
                std::uint32_t ingress_ifindex=0;
                std::optional<std::uint8_t> dscp;
                for (auto* item=CMSG_FIRSTHDR(&header);item;item=CMSG_NXTHDR(&header,item)) {
                    if (item->cmsg_level!=(ipv6 ? IPPROTO_IPV6 : IPPROTO_IP)) continue;
                    auto native_size=ipv6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
                    if (item->cmsg_type==(ipv6 ? IPV6_ORIGDSTADDR : IP_ORIGDSTADDR) &&
                        item->cmsg_len==CMSG_LEN(native_size)) {
                        target=decode(CMSG_DATA(item),native_size,ipv6);
                    } else if (ipv6 && item->cmsg_type==IPV6_TCLASS && item->cmsg_len==CMSG_LEN(sizeof(int))) {
                        int traffic_class;
                        std::memcpy(&traffic_class,CMSG_DATA(item),sizeof(traffic_class));
                        if (traffic_class>=0 && traffic_class<=255) dscp=static_cast<std::uint8_t>(traffic_class >> 2);
                    } else if (!ipv6 && item->cmsg_type==IP_TOS && item->cmsg_len==CMSG_LEN(sizeof(std::uint8_t))) {
                        dscp=static_cast<std::uint8_t>(*CMSG_DATA(item) >> 2);
                    } else if (ipv6 && item->cmsg_type==IPV6_PKTINFO && item->cmsg_len==CMSG_LEN(sizeof(in6_pktinfo))) {
                        in6_pktinfo info;
                        std::memcpy(&info,CMSG_DATA(item),sizeof(info));
                        ingress_ifindex=info.ipi6_ifindex;
                    } else if (!ipv6 && item->cmsg_type==IP_PKTINFO && item->cmsg_len==CMSG_LEN(sizeof(in_pktinfo))) {
                        in_pktinfo info;
                        std::memcpy(&info,CMSG_DATA(item),sizeof(info));
                        ingress_ifindex=static_cast<std::uint32_t>(info.ipi_ifindex);
                    }
                }
                if (!client || !target || (target->port==listen_.port &&
                    (target->address==listen_.address || std::ranges::all_of(listen_.address,[](auto byte) {return byte==0;}))))
                    continue;
                auto* flow=accept(*client,{*target,ingress_ifindex});
                if (!flow) continue;
                auto& state=*flow->relays;
                auto length=static_cast<std::size_t>(size);
                if (state.pending.size()>=64 || state.pending_bytes+length>1024*1024) continue;
                state.pending.emplace_back(flow->route_target,
                    std::vector(payload.begin(),payload.begin()+size),Clock::now(),
                    server_.transparent_metadata(*client,dscp,ingress_ifindex));
                state.pending_bytes+=length;
            }
            return {};
        }
        auto stop() noexcept -> void {
            socket_.close();
            for (auto& flow : flows_) {
                flow->session.close();
                flow->relays->cancel();
            }
            reply_cache_.clear();
        }
    };

    auto Server::start_transparent_udp(nex::corosio::endpoint listen,bool reuse) -> std::error_code {
        auto owner=std::make_shared<TransparentUdp>(*this,direct_tcp_options.binding.routing_mark);
        if(auto error=owner->start(listen,reuse)) return error;
        transparent_udp=std::move(owner);
        return {};
    }
    auto Server::poll_transparent_udp() -> void {
        if (auto error=transparent_udp->poll()) {
            record_failure({FailureKind::transparent_udp,error});
            running=false;
        }
    }
    auto Server::stop_transparent_udp() noexcept -> void {if(transparent_udp)transparent_udp->stop();}
}
