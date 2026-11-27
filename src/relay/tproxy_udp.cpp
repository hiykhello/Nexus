module;
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <proxy/proxy_macros.h>

module relay;
import proxy.v4;
import std;
import containers.lru_slab;
import net.udp_socket;
import net.stream_datagrams;
import relay.request_backend;
import capy;
import corosio;
import :tproxy_reply_cache;

namespace relay {
    using namespace std::chrono_literals;
    using namespace tproxy_detail;

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
            auto send_packet(net::ProxyAddress const& source,std::span<std::uint8_t const> data)
                -> capy::task<net::stream_datagrams::ReplySendStatus> {
                using Status = net::stream_datagrams::ReplySendStatus;
                using CacheResult = TproxyReplySocketCache::SendResult;
                auto to_status = [](CacheResult r) noexcept -> Status {
                    if (r == CacheResult::sent) return Status::sent;
                    if (r == CacheResult::dropped) return Status::dropped;
                    return Status::failed;
                };
                if (!reply_cache) co_return Status::failed;
#ifdef NEXUS_ENABLE_FAKEIP
                // The relay validates the real reply source on its own socket or stream.
                if (alias) co_return to_status(reply_cache->send(target,mark,client,data));
#endif
                auto expected=net::stream_datagrams::peer_address(target);
                if(source.family!=expected.family || source.port!=expected.port || source.length!=expected.length ||
                    !std::ranges::equal(std::span(source.bytes).first(source.length),std::span(expected.bytes).first(expected.length)))
                    co_return Status::failed;
                co_return to_status(reply_cache->send(target,mark,client,data));
            }
        };
        struct Resolve {
            Session& session;
            corosio::io_context& context;
            net::UdpEndpoint source;
            auto operator()(std::string name,std::uint16_t port,Clock::time_point deadline) {
                return resolve_udp_domain(session,context,std::move(name),port,deadline,&source);
            }
        };
        struct FlowKey {
            net::UdpEndpoint client, target;
            std::uint32_t ingress_ifindex = 0;
            auto operator==(FlowKey const&) const noexcept -> bool = default;
        };
        struct FlowKeyHash {
            auto operator()(FlowKey const& k) const noexcept -> std::size_t {
                std::uint64_t h = 14695981039346656037ull;
                auto mix = [&](std::uint64_t v) noexcept { h = (h ^ v) * 1099511628211ull; };
                mix((static_cast<std::uint64_t>(k.client.family) << 48) | (static_cast<std::uint64_t>(k.client.port) << 32) | k.ingress_ifindex);
                mix((static_cast<std::uint64_t>(k.target.family) << 16) | k.target.port);
                std::uint64_t a = 0, b = 0;
                std::memcpy(&a, k.client.address.data(), 8); std::memcpy(&b, k.client.address.data() + 8, 8);
                mix(a); if (k.client.family == 6) mix(b);
                std::memcpy(&a, k.target.address.data(), 8); std::memcpy(&b, k.target.address.data() + 8, 8);
                mix(a); if (k.target.family == 6) mix(b);
                return static_cast<std::size_t>(h);
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
            explicit Flow(corosio::io_context& context) : session(context) {}
        };
    }

    class TransparentUdp {
        static constexpr std::size_t default_flow_limit = 4096;
        static constexpr std::size_t kRecvBatch=8;
        static constexpr std::size_t kCtrlSize=CMSG_SPACE(sizeof(sockaddr_in6))+CMSG_SPACE(sizeof(in6_pktinfo))+CMSG_SPACE(sizeof(int));
        Server& server_;
        Socket socket_;
        TproxyReplySocketCache reply_cache_;
        net::UdpEndpoint listen_;
        bool listen_any_=false;
        std::optional<std::uint32_t> mark_;
        containers::LruSlab<FlowKey,std::shared_ptr<Flow>,FlowKeyHash> flows_;
        std::unordered_map<std::uint32_t,std::array<char,IF_NAMESIZE>> ifname_cache_;
#if !defined(__linux__)
        std::unique_ptr<std::uint8_t[]> payload_;
#endif
        Clock::time_point last_reap_{};

        auto resolve_ifname(std::uint32_t idx, std::array<char,IF_NAMESIZE>& out) -> bool {
            if (auto it = ifname_cache_.find(idx); it != ifname_cache_.end()) {
                out = it->second;
                return out[0] != '\0';
            }
            if (::if_indextoname(idx, out.data())) {
                if (ifname_cache_.size() < 64) ifname_cache_.emplace(idx, out);
                return true;
            }
            return false;
        }

        auto accept(net::UdpEndpoint const& client,TransparentDatagram const& incoming) -> Flow* {
            auto const& target=incoming.original_destination;
            FlowKey key{client,target,incoming.ingress_ifindex};
            if (auto idx=flows_.find_index_and_touch(key)) {
                auto& existing=flows_.slot_value(*idx);
                if (!existing->session.closed) return existing.get();
                if (!existing->active) flows_.erase(*idx);
                else return nullptr;
            }
            auto lease=server_.acquire_session();
            if (!lease) return nullptr;
            auto& context=server_.executor_context();
            auto flow=std::make_shared<Flow>(context);
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
            if (flow->ingress_ifindex && resolve_ifname(flow->ingress_ifindex,flow->ingress_name))
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
            auto [slot_idx, inserted]=flows_.emplace_or_evict(key,
                [](std::uint32_t,FlowKey const&,std::shared_ptr<Flow>& victim) noexcept {
                    victim->session.close();
                    if (victim->relays) victim->relays->cancel();
                }, flow);
            if (!inserted) return nullptr;
            auto on_done = [this, key, raw = current]() noexcept {
                raw->session.close();
                raw->active = false;
                if (auto idx = flows_.find_index(key); idx && flows_.slot_value(*idx).get() == raw)
                    flows_.erase(*idx);
            };
            try {
                capy::run_async(context.get_executor(), on_done,
                    [on_done](std::exception_ptr) noexcept { on_done(); })(relay(std::move(flow)));
            } catch (...) {
                flows_.erase(slot_idx);
                throw;
            }
            return current;
        }

        static auto relay(std::shared_ptr<Flow> flow) -> capy::task<> {
            (void)co_await capy::when_all(net::stream_datagrams::tasks(*flow->relays));
        }

        auto dispatch_datagram(msghdr& header, std::uint8_t const* data, std::size_t length, bool ipv6, Clock::time_point now) -> void {
            if (header.msg_flags&(MSG_TRUNC|MSG_CTRUNC)) return;
            auto client=decode(header.msg_name,header.msg_namelen,ipv6);
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
            if (!client || !target || (target->port==listen_.port && (target->address==listen_.address || listen_any_)))
                return;
            auto* flow=accept(*client,{*target,ingress_ifindex});
            if (!flow) return;
            auto& state=*flow->relays;
            if (state.pending.size()>=64 || state.pending_bytes+length>1024*1024) return;
            state.pending.emplace_back(flow->route_target,
                std::vector<std::uint8_t>(data,data+length),now,
                server_.transparent_metadata(*client,dscp,ingress_ifindex));
            state.pending_bytes+=length;
            state.notify_pending();
        }

    public:
        TransparentUdp(Server& server,std::optional<std::uint32_t> mark,std::size_t flow_limit=default_flow_limit)
            : server_(server),mark_(mark),flows_(flow_limit)
#if !defined(__linux__)
            ,payload_(std::make_unique_for_overwrite<std::uint8_t[]>(65536))
#endif
        {}
        auto start(corosio::endpoint endpoint,bool reuse,config::ListenOptions const* listen = nullptr) -> std::error_code {
            listen_.family=endpoint.is_v6() ? 6 : 4;
            listen_.port=endpoint.port();
            if (endpoint.is_v6()) std::ranges::copy(endpoint.address().to_v6().to_bytes(),listen_.address.begin());
            else std::ranges::copy(endpoint.address().to_v4().to_bytes(),listen_.address.begin());
            listen_any_=std::ranges::all_of(listen_.address,[](auto byte) {return byte==0;});
            reply_cache_.refresh_netns();
            return socket_.bind(listen_,true,reuse,mark_,listen);
        }
        auto poll() -> std::error_code {
            auto now=Clock::now();
            if (now-last_reap_>=1s) {
                reply_cache_.reap_idle(now);
                last_reap_=now;
            }
            bool ipv6=listen_.family==6;
#if defined(__linux__)
            thread_local std::unique_ptr<std::uint8_t[]> batch_slab;
            if (!batch_slab) batch_slab=std::make_unique_for_overwrite<std::uint8_t[]>(kRecvBatch*65536);
            std::array<mmsghdr,kRecvBatch> msgs;
            std::array<iovec,kRecvBatch> iovs;
            std::array<sockaddr_storage,kRecvBatch> addrs;
            alignas(cmsghdr) std::array<std::array<unsigned char,kCtrlSize>,kRecvBatch> ctrls;
            for (unsigned round=0;round<4;++round) {
                for (std::size_t i=0;i<kRecvBatch;++i) {
                    iovs[i]={batch_slab.get()+i*65536,65536};
                    msgs[i].msg_hdr={.msg_name=&addrs[i],.msg_namelen=sizeof(sockaddr_storage),
                        .msg_iov=&iovs[i],.msg_iovlen=1,.msg_control=ctrls[i].data(),.msg_controllen=kCtrlSize,.msg_flags=0};
                    msgs[i].msg_len=0;
                }
                int got=0;
                do { got=::recvmmsg(socket_.fd,msgs.data(),static_cast<unsigned int>(kRecvBatch),MSG_DONTWAIT,nullptr); }
                while (got<0 && errno==EINTR);
                if (got<0) {
                    if (errno==EAGAIN || errno==EWOULDBLOCK) break;
                    return {errno,std::generic_category()};
                }
                for (int i=0;i<got;++i)
                    dispatch_datagram(msgs[i].msg_hdr,batch_slab.get()+static_cast<std::size_t>(i)*65536,msgs[i].msg_len,ipv6,now);
                if (static_cast<std::size_t>(got)<kRecvBatch) break;
            }
#else
            for (unsigned count=0;count<32;++count) {
                sockaddr_storage address;
                alignas(cmsghdr) std::array<unsigned char,kCtrlSize> control;
                iovec data{payload_.get(),65536};
                msghdr header{.msg_name=&address,.msg_namelen=sizeof(address),.msg_iov=&data,.msg_iovlen=1,
                    .msg_control=control.data(),.msg_controllen=control.size(),.msg_flags=0};
                auto size=::recvmsg(socket_.fd,&header,MSG_DONTWAIT);
                if (size<0) {
                    if (errno==EAGAIN || errno==EWOULDBLOCK) break;
                    if (errno==EINTR) continue;
                    return {errno,std::generic_category()};
                }
                dispatch_datagram(header,payload_.get(),static_cast<std::size_t>(size),ipv6,now);
            }
#endif
            return {};
        }
        auto stop() noexcept -> void {
            socket_.close();
            flows_.for_each([](std::uint32_t,FlowKey const&,std::shared_ptr<Flow>& flow) noexcept {
                flow->session.close();
                if (flow->relays) flow->relays->cancel();
            });
            flows_.clear();
            reply_cache_.clear();
        }
    };

    auto Server::start_transparent_udp(corosio::endpoint listen,bool reuse) -> std::error_code {
        auto mark=listen_options.routing_mark ? listen_options.routing_mark : direct_tcp_options.binding.routing_mark;
        auto owner=std::make_shared<TransparentUdp>(*this,mark);
        if(auto error=owner->start(listen,reuse,&listen_options)) return error;
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
