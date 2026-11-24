module;
#include <cerrno>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
module socks5.udp_ingress;
import net.principal_bytes;
import platform.ip_address;
import std;
import rules;
import capy;
import corosio;
namespace socks5 {
    namespace {
        auto error() -> std::error_code { return {errno,std::generic_category()}; }
        struct SocketAddress { sockaddr_storage data{}; socklen_t size=0; };
        auto address(UdpPeer const& peer) -> SocketAddress {
            SocketAddress result;
            if (peer.address_type==1) {
                sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_port=platform::host_to_net16(peer.port);
                std::copy_n(peer.address.begin(),4,reinterpret_cast<std::uint8_t*>(&addr.sin_addr));
                std::memcpy(&result.data,&addr,sizeof(addr)); result.size=sizeof(addr);
            } else {
                sockaddr_in6 addr{}; addr.sin6_family=AF_INET6; addr.sin6_port=platform::host_to_net16(peer.port);
                std::ranges::copy(peer.address,addr.sin6_addr.s6_addr);
                std::memcpy(&result.data,&addr,sizeof(addr)); result.size=sizeof(addr);
            }
            return result;
        }
        auto peer(sockaddr_storage const& storage,socklen_t length) -> std::optional<UdpPeer> {
            if (storage.ss_family==AF_INET && length==sizeof(sockaddr_in)) {
                sockaddr_in addr{}; std::memcpy(&addr,&storage,sizeof(addr));
                UdpPeer result{1,{},platform::net_to_host16(addr.sin_port)};
                std::copy_n(reinterpret_cast<std::uint8_t const*>(&addr.sin_addr),4,result.address.begin()); return result;
            }
            if (storage.ss_family==AF_INET6 && length==sizeof(sockaddr_in6)) {
                sockaddr_in6 addr{}; std::memcpy(&addr,&storage,sizeof(addr));
                if (addr.sin6_scope_id || IN6_IS_ADDR_V4MAPPED(&addr.sin6_addr)) return {};
                UdpPeer result{4,{},platform::net_to_host16(addr.sin6_port)};
                std::copy_n(addr.sin6_addr.s6_addr,16,result.address.begin()); return result;
            }
            return {};
        }
        auto open_dgram_fd(bool ipv6) noexcept -> int {
#if defined(SOCK_NONBLOCK) && defined(SOCK_CLOEXEC)
            return ::socket(ipv6 ? AF_INET6 : AF_INET,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
#else
            int fd=::socket(ipv6 ? AF_INET6 : AF_INET,SOCK_DGRAM,0);
            if (fd<0) return -1;
            int fl=::fcntl(fd,F_GETFL,0), fdfl=::fcntl(fd,F_GETFD,0);
            if (fl<0 || ::fcntl(fd,F_SETFL,fl|O_NONBLOCK)<0 || fdfl<0 || ::fcntl(fd,F_SETFD,fdfl|FD_CLOEXEC)<0) {
                int err=errno; ::close(fd); errno=err; return -1;
            }
#ifdef SO_NOSIGPIPE
            int one=1; (void)::setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));
#endif
            return fd;
#endif
        }
    }
    UdpIngress::~UdpIngress() { close(); }
    auto UdpIngress::close() noexcept -> void {
        closed_=true; backpressured_family_=0; wake(); pending_.reset(); tunnel_.reset(); input_pending_=false; domain_pending_=false; route_pending_=false; input_size_=0; direct_.close();
        tunnel_alias_.reset();
        deferred_.clear(); deferred_bytes_=0;parked_=replaying_=collecting_=false;input_metadata_={};parked_metadata_={};std::vector<std::uint8_t>{}.swap(parked_bytes_);
        aliases_.clear();
        if (!waiting_) watches_.clear();
        if (fd_>=0) { ::close(fd_); fd_=-1; }
    }
    auto UdpIngress::open(UdpPeer local) -> std::expected<UdpPeer,UdpDirectError> {
        if (closed_ || association_.closed()) return std::unexpected(UdpDirectError{Status::association_closed});
        if (fd_>=0) return std::unexpected(UdpDirectError{std::make_error_code(std::errc::operation_not_permitted)});
        if ((local.address_type!=1 && local.address_type!=4) ||
            std::ranges::all_of(local.address,[](auto b){return b==0;}) ||
            (local.address_type==1 && std::ranges::any_of(std::span(local.address).subspan(4),[](auto b){return b!=0;})) ||
            (local.address_type==4 && std::ranges::all_of(std::span(local.address).first<10>(),[](auto b){return b==0;}) &&
             local.address[10]==255 && local.address[11]==255))
            return std::unexpected(UdpDirectError{Status::invalid_address});
        int fd=open_dgram_fd(local.address_type==4);
        if (fd<0) return std::unexpected(UdpDirectError{error()});
        if (local.address_type==4) {
            int on=1;
            if (::setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&on,sizeof(on))<0) {
                auto failure=error(); ::close(fd); return std::unexpected(UdpDirectError{failure});
            }
        }
        auto addr=address(local);
        if (::bind(fd,reinterpret_cast<sockaddr*>(&addr.data),addr.size)<0) {
            auto failure=error(); ::close(fd); return std::unexpected(UdpDirectError{failure});
        }
        sockaddr_storage bound{}; socklen_t length=sizeof(bound);
        if (::getsockname(fd,reinterpret_cast<sockaddr*>(&bound),&length)<0) {
            auto failure=error(); ::close(fd); return std::unexpected(UdpDirectError{failure});
        }
        auto result=peer(bound,length);
        if (!result) { ::close(fd); return std::unexpected(UdpDirectError{Status::invalid_address}); }
        fd_=fd; return *result;
    }
    auto UdpIngress::reserve_bytes(bool upstream,std::size_t size) const
        -> std::optional<net::PrincipalBytes::Reservation> {
        if (byte_budget_) return byte_budget_->reserve_datagram(upstream,size,std::chrono::steady_clock::now());
        return std::optional<net::PrincipalBytes::Reservation>(std::in_place);
    }
    auto UdpIngress::send_target(UdpDatagram const& packet,UdpPeer target,std::chrono::steady_clock::time_point deadline)
        -> std::expected<void,UdpDirectError> {
        auto credit=reserve_bytes(true,packet.data.size());
        if (!credit) return std::unexpected(UdpDirectError{UdpRouteError::blocked});
        auto sent=direct_.send_selected(packet,target,deadline);
        if (sent) credit->complete(packet.data.size());
        return sent;
    }

    auto UdpIngress::step() -> std::expected<UdpIngressStep,UdpDirectError> {
        if (closed_ || association_.closed()) { close(); return std::unexpected(UdpDirectError{Status::association_closed}); }
        if (fd_<0) return std::unexpected(UdpDirectError{std::make_error_code(std::errc::bad_file_descriptor)});
        work_.clear(); backpressured_family_=0;
        UdpIngressStep report;
        auto now=std::chrono::steady_clock::now();
        std::erase_if(aliases_,[&](auto const& relay) {
            if (now-relay.touched<std::chrono::seconds(60)) return false;
            auto descriptors=relay.socket->native_handles();
            std::erase_if(watches_,[&](auto const& watch) {return std::ranges::find(descriptors,watch.fd)!=descriptors.end();});
            return true;
        });
        if(collecting_ && route_pending_) {
            auto received=read_lookahead(report);if(!received)return std::unexpected(received.error());
        }
        if (!input_pending_ && !replaying_) {
            sockaddr_storage from{}; socklen_t length=sizeof(from);
            auto n=::recvfrom(fd_,input_bytes_.data(),input_bytes_.size(),MSG_TRUNC,reinterpret_cast<sockaddr*>(&from),&length);
            if (n>=0) {
                report.input=true;
                auto source=peer(from,length);
                if (static_cast<std::size_t>(n)>input_bytes_.size()) report.input_error=UdpDirectError{Status::too_large};
                else if (!source) report.input_error=UdpDirectError{Status::invalid_address};
                else { input_size_=static_cast<std::size_t>(n); input_source_=*source; input_pending_=true; input_metadata_={}; }
            } else if (errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR) {
                auto failure=error(); close(); return std::unexpected(UdpDirectError{failure});
            }
        }
        if (input_pending_ && !domain_pending_ && !route_pending_ && !tunnel_) {
            report.input=true;
            auto packet=association_.admit(input_source_,std::span(input_bytes_).first(input_size_));
            if(packet && input_metadata_.deadline==std::chrono::steady_clock::time_point{}) {
                input_metadata_.started=std::chrono::steady_clock::now();
                input_metadata_.deadline=input_metadata_.started+std::chrono::seconds(10);
            }
            if (!packet) report.input_error=UdpDirectError{packet.error()};
            else if(std::chrono::steady_clock::now()>=input_metadata_.deadline)
                report.input_error=UdpDirectError{std::make_error_code(std::errc::timed_out)};
            else if(external_route_) {
                route_pending_=true;report.route_pending=true;
            }
            else if (packet->address_type==3) {
                auto preflight=allow_tunnels_ ?
                    udp_select_preflight(policy_,*packet,&input_source_,auth_user_).transform([](auto) {}) : udp_preflight(policy_,*packet,&input_source_,auth_user_);
                if (std::ranges::find(std::span(packet->address).first(packet->address_length),0)!=
                    std::span(packet->address).first(packet->address_length).end())
                    report.input_error=UdpDirectError{Status::invalid_address};
                else if (!preflight) report.input_error=UdpDirectError{preflight.error()};
                else if (!allow_domains_) report.input_error=UdpDirectError{UdpRouteError::unsupported};
                else { domain_pending_=true; report.domain_pending=true; }
            }
            else {
                UdpPeer target{packet->address_type,{},packet->port};
                std::copy_n(packet->address.begin(),packet->address_length,target.address.begin());
                if (allow_target_ && !allow_target_(filter_context_,target)) {
                    route_pending_=true;
                    report.route_pending=true;
                } else {
                    auto selected=udp_select(policy_,*packet,target,&input_source_,auth_user_);
                    if (!selected) report.input_error=UdpDirectError{selected.error()};
                    else if (selected->outbound>=2) {
                        if (allow_tunnels_) { tunnel_=*selected; report.tunnel_pending=true; }
                        else report.input_error=UdpDirectError{UdpRouteError::unsupported};
                    }
                    else {
                        auto sent=send_target(*packet,selected->target,input_metadata_.deadline);
                        if (sent) {
                            route_delivery_(false,*selected);
                            delivery_(true,packet->data.size());
                            report.forwarded=true;
                        }
                        else if (auto error=std::get_if<std::error_code>(&sent.error()); error &&
                                 (*error==std::errc::resource_unavailable_try_again || *error==std::errc::interrupted))
                            { report.input_backpressured=true; backpressured_family_=selected->target.address_type; }
                        else report.input_error=sent.error();
                    }
                }
            }
            if (!report.input_backpressured && !domain_pending_ && !route_pending_ && !tunnel_) { input_pending_=false; input_size_=0; }
        }
        if (domain_pending_) report.domain_pending=true;
        if (route_pending_) report.route_pending=true;
        if (tunnel_) report.tunnel_pending=true;
        alias_turn_=!alias_turn_;
        if (!pending_ && alias_turn_ && !aliases_.empty()) poll_aliases(report);
        if (!pending_) {
            bool consumed=false;
            auto reply=direct_.poll(&consumed);
            if (!reply) report.output_error=reply.error();
            else if (*reply) pending_=std::move(**reply);
            else if (consumed) report.output_dropped=true;
        }
        if (!pending_ && !alias_turn_ && !aliases_.empty()) poll_aliases(report);
        if (pending_) {
            auto credit=reserve_bytes(false,pending_->payload_size);
            if (!credit) {
                report.output_dropped=true;
                pending_.reset();
                changed_.set();
                return report;
            }
            auto dest=address(pending_->client);
            auto sent=::sendto(fd_,pending_->wire.data(),pending_->wire.size(),0,reinterpret_cast<sockaddr*>(&dest.data),dest.size);
            if (sent<0 && (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR)) report.backpressured=true;
            else if (sent<0 && (errno==EMSGSIZE || errno==ENETUNREACH || errno==EHOSTUNREACH || errno==ECONNREFUSED)) {
                report.output_dropped=true; pending_.reset();
            }
            else if (sent<0 || static_cast<std::size_t>(sent)!=pending_->wire.size()) {
                report.output_error=UdpDirectError{sent<0 ? error() : std::make_error_code(std::errc::io_error)}; pending_.reset();
            } else {
                credit->complete(pending_->payload_size);
                delivery_(false,pending_->payload_size);
                report.delivered=true;
                pending_.reset();
            }
        }
        if (report.input || report.delivered || report.output_dropped) changed_.set();
        return report;
    }

    auto UdpIngress::wait(corosio::io_context& context,UdpIngressStep const& report,
        std::chrono::steady_clock::time_point deadline) -> capy::task<bool> {
        namespace capy = ::capy;
        namespace io = ::corosio;
        using Wait=capy::task<capy::results<std::error_code>>;
        using Direction=io::wait_type;
        if (closed_) { watches_.clear(); co_return false; }
        if (work_.is_set()) co_return true;
        struct WaitGuard { UdpIngress& s; ~WaitGuard() { s.waiting_=false; if (s.closed_) s.watches_.clear(); } };
        waiting_=true; WaitGuard guard{*this};

        std::vector<std::pair<int,Direction>> ready;
        if (report.backpressured) ready.emplace_back(fd_,Direction::write);
        else if ((!input_pending_ && !replaying_) || (collecting_ && route_pending_ && !route_lookahead_full()))
            ready.emplace_back(fd_,Direction::read);

        auto direct=direct_.native_handles();
        std::size_t blocked_idx=(direct[1]>=0 && backpressured_family_==4) ? 1u : 0u;
        for (std::size_t i=0;i<direct.size();++i) if (direct[i]>=0 && (!pending_ || (report.input_backpressured && i==blocked_idx)))
            ready.emplace_back(direct[i],(report.input_backpressured && i==blocked_idx) ? Direction::write : Direction::read);
        for (auto const& relay:aliases_) {
            deadline=std::min(deadline,relay.touched+std::chrono::seconds(60));
            if (!pending_) for (int fd:relay.socket->native_handles())
                if (fd>=0) ready.emplace_back(fd,Direction::read);
        }

        std::erase_if(watches_,[&](auto const& watch) {
            return std::ranges::none_of(ready,[&](auto const& item) {return item.first==watch.fd;});
        });
        for (auto [fd,direction]:ready) {
            (void)direction;
            if (std::ranges::find(watches_,fd,&Watch::fd)!=watches_.end()) continue;
            Watch watch{fd,io::udp_socket(context)};
            auto duplicate=::fcntl(fd,F_DUPFD_CLOEXEC,0);
            if (duplicate<0) co_return false;
            if (watch.socket.assign(duplicate)) {
                ::close(duplicate);
                co_return false;
            }
            watches_.push_back(std::move(watch));
        }
        auto wait_socket=[](io::udp_socket& socket,Direction direction) -> Wait {
            auto [error]=co_await socket.wait(direction);
            co_return capy::results<std::error_code>{std::error_code{},error};
        };
        auto wait_work=[](capy::async_event& work) -> Wait {
            auto [error]=co_await work.wait();
            co_return capy::results<std::error_code>{std::error_code{},error};
        };
        auto wait_deadline=[](std::chrono::steady_clock::time_point until) -> Wait {
            auto [error]=co_await io::delay(until);
            co_return capy::results<std::error_code>{std::error_code{},error};
        };
        std::vector<Wait> waits;
        waits.reserve(ready.size()+2);
        for (auto [fd,direction]:ready) {
            auto watch=std::ranges::find(watches_,fd,&Watch::fd);
            waits.push_back(wait_socket(watch->socket,direction));
        }
        waits.push_back(wait_work(work_));
        if (deadline!=std::chrono::steady_clock::time_point::max()) waits.push_back(wait_deadline(deadline));
        auto result=co_await capy::when_any(std::move(waits));
        auto winner=std::get_if<1>(&result);
        co_return winner && !winner->second;
    }

    auto UdpIngress::promote_parked() -> void {
        // Count the fixed current packet in the original eight-packet/256 KiB
        // storage budget. One overflow packet can still occupy the parked slot.
        if(!parked_ || deferred_.size()+1>=deferred_limit_ ||
           input_size_+deferred_bytes_>deferred_byte_limit_ ||
           parked_bytes_.size()>deferred_byte_limit_-input_size_-deferred_bytes_)return;
        DeferredRoute item{parked_bytes_,parked_source_,parked_metadata_};
        deferred_.push_back(std::move(item));deferred_bytes_+=parked_bytes_.size();
        parked_=false;parked_bytes_.clear();parked_metadata_={};
    }
    auto UdpIngress::read_lookahead(UdpIngressStep& report) -> std::expected<void,UdpDirectError> {
        if(route_lookahead_full())return {};
        // Reuse the existing overflow storage as receive scratch. Tail entries
        // copy their exact wire size, so small datagrams do not each retain a
        // 64 KiB scratch allocation.
        parked_bytes_.resize(input_bytes_.size());
        sockaddr_storage from{};socklen_t length=sizeof(from);
        auto n=::recvfrom(fd_,parked_bytes_.data(),parked_bytes_.size(),MSG_TRUNC,reinterpret_cast<sockaddr*>(&from),&length);
        if(n<0) {
            parked_bytes_.clear();
            if(errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR)return {};
            auto failure=error();close();return std::unexpected(UdpDirectError{failure});
        }
        report.input=true;auto source=peer(from,length);
        if(static_cast<std::size_t>(n)>parked_bytes_.size())report.input_error=UdpDirectError{Status::too_large};
        else if(!source)report.input_error=UdpDirectError{Status::invalid_address};
        else {
            parked_bytes_.resize(static_cast<std::size_t>(n));
            auto packet=association_.admit(*source,parked_bytes_);
            if(!packet)report.input_error=UdpDirectError{packet.error()};
            else {
                parked_source_=*source;
                auto started=std::chrono::steady_clock::now();
                parked_metadata_={.deadline=started+std::chrono::seconds(10),.started=started};
                parked_=true;promote_parked();return {};
            }
        }
        parked_bytes_.clear();return {};
    }
    auto UdpIngress::begin_route_lookahead() -> bool {
        if(closed_ || association_.closed() || !external_route_ || !route_pending_ || collecting_)return false;
        promote_parked();collecting_=true;replaying_=true;wake();return true;
    }
    auto UdpIngress::lookahead_route(std::size_t index) const noexcept -> std::optional<UdpRouteLookahead> {
        if(closed_ || association_.closed() || !route_pending_)return {};
        std::span<std::uint8_t const> wire;UdpPeer source;std::chrono::steady_clock::time_point deadline;
        if(index<deferred_.size()) {
            auto const& item=deferred_[index];wire=item.wire;source=item.source;deadline=item.metadata.deadline;
        } else if(index==deferred_.size() && parked_) {
            wire=parked_bytes_;source=parked_source_;deadline=parked_metadata_.deadline;
        } else return {};
        auto packet=parse_udp_datagram(wire);if(!packet)return {};
        return UdpRouteLookahead{*packet,source,deadline};
    }
    auto UdpIngress::remember_route_sniff(std::optional<std::string> domain,bool matched) -> bool {
        if(closed_ || !route_pending_)return false;
        input_metadata_.quic_inspected=true;
        input_metadata_.quic_matched=matched || domain.has_value();
        input_metadata_.quic_domain=std::move(domain);
        return true;
    }
    auto UdpIngress::remember_lookahead_sniff(std::size_t index,std::optional<std::string> domain,bool matched) -> bool {
        if(closed_ || !route_pending_)return false;
        auto* metadata=index<deferred_.size() ? &deferred_[index].metadata :
            index==deferred_.size() && parked_ ? &parked_metadata_ : nullptr;
        if(!metadata)return false;
        metadata->quic_inspected=true;
        metadata->quic_matched=matched || domain.has_value();
        metadata->quic_domain=std::move(domain);
        return true;
    }
    auto UdpIngress::pending_route() const noexcept -> std::optional<UdpDatagram> {
        if(closed_ || association_.closed() || !route_pending_)return {};
        auto packet=parse_udp_datagram(std::span(input_bytes_).first(input_size_));
        if(!packet)return {};
        return *packet;
    }
    auto UdpIngress::send_selected(UdpPeer candidate,std::size_t outbound,std::optional<std::size_t> rule)
        -> std::expected<void,UdpDirectError> {
        if(closed_ || association_.closed()) {close();return std::unexpected(UdpDirectError{Status::association_closed});}
        auto packet=pending_route();
        if(!packet)return std::unexpected(UdpDirectError{std::make_error_code(std::errc::operation_not_permitted)});
        if(std::chrono::steady_clock::now()>=input_metadata_.deadline)
            return std::unexpected(UdpDirectError{std::make_error_code(std::errc::timed_out)});
        auto checked=net::udp_validate_candidate(udp_target(*packet),udp_endpoint(candidate));
        if(!checked)return std::unexpected(UdpDirectError{checked.error()});
        auto target=udp_peer(*checked);
        if (allow_target_ && !allow_target_(filter_context_,target))
            return std::unexpected(UdpDirectError{UdpRouteError::blocked});
        if(outbound==1)return std::unexpected(UdpDirectError{UdpRouteError::blocked});
        if(outbound>=2) {
            if(!allow_tunnels_)return std::unexpected(UdpDirectError{UdpRouteError::unsupported});
            tunnel_=UdpSelection{target,outbound,rule};route_pending_=false;wake();return {};
        }
        auto sent=send_target(*packet,target,input_metadata_.deadline);
        if (sent) {
            route_delivery_(external_route_,{target,outbound,rule});
            delivery_(true,packet->data.size());
            discard_route();
        }
        return sent;
    }

    auto UdpIngress::discard_route() noexcept -> void {
        if(route_pending_) {route_pending_=false;input_pending_=false;input_size_=0;input_metadata_={};wake();}
    }
    auto UdpIngress::defer_route() -> bool {
        if(closed_ || association_.closed() || replaying_ || collecting_ || !route_pending_ || !input_pending_ ||
           deferred_.size()>=deferred_limit_ || input_size_>deferred_byte_limit_-deferred_bytes_) return false;
        DeferredRoute item{{input_bytes_.begin(),input_bytes_.begin()+input_size_},input_source_,input_metadata_};
        deferred_.push_back(std::move(item)); deferred_bytes_+=input_size_;
        route_pending_=false;input_pending_=false;input_size_=0;input_metadata_={};
        return true;
    }
    auto UdpIngress::begin_deferred_replay() -> bool {
        if(closed_ || association_.closed() || replaying_ || collecting_ || domain_pending_ || tunnel_)return false;
        if(input_pending_) {
            if(!route_pending_)return false;
            parked_bytes_.assign(input_bytes_.begin(),input_bytes_.begin()+input_size_);
            parked_source_=input_source_;parked_metadata_=std::move(input_metadata_);parked_=true;
            input_pending_=route_pending_=false;input_size_=0;
        }
        replaying_=true;return true;
    }
    auto UdpIngress::replay_deferred() noexcept -> bool {
        if(closed_ || association_.closed() || !replaying_ || collecting_ || input_pending_ || domain_pending_ || route_pending_ || tunnel_)return false;
        if(!deferred_.empty()) {
            auto& item=deferred_.front();
            std::ranges::copy(item.wire,input_bytes_.begin());input_size_=item.wire.size();input_source_=item.source;input_metadata_=std::move(item.metadata);
            deferred_bytes_-=input_size_;deferred_.pop_front();
        } else if(parked_) {
            std::ranges::copy(parked_bytes_,input_bytes_.begin());input_size_=parked_bytes_.size();input_source_=parked_source_;input_metadata_=std::move(parked_metadata_);
            parked_=false;std::vector<std::uint8_t>{}.swap(parked_bytes_);
        } else {replaying_=false;std::vector<std::uint8_t>{}.swap(parked_bytes_);wake();return false;}
        input_pending_=true;route_pending_=true;
        return true;
    }
    auto UdpIngress::pending_domain() const noexcept -> std::optional<UdpDatagram> {
        if (closed_ || association_.closed() || !domain_pending_) return {};
        auto packet=parse_udp_datagram(std::span(input_bytes_).first(input_size_));
        if (!packet || packet->address_type!=3) return {};
        return *packet;
    }
    auto UdpIngress::send_resolved(UdpPeer candidate) -> std::expected<void,UdpDirectError> {
        if (closed_ || association_.closed()) { close(); return std::unexpected(UdpDirectError{Status::association_closed}); }
        auto packet=pending_domain();
        if (!packet) return std::unexpected(UdpDirectError{std::make_error_code(std::errc::operation_not_permitted)});
        if(std::chrono::steady_clock::now()>=input_metadata_.deadline) return std::unexpected(UdpDirectError{std::make_error_code(std::errc::timed_out)});
        auto selected=udp_select(policy_,*packet,candidate,&input_source_,auth_user_);
        if (!selected) return std::unexpected(UdpDirectError{selected.error()});
        if (allow_target_ && !allow_target_(filter_context_,selected->target)) return std::unexpected(UdpDirectError{UdpRouteError::blocked});
        if (selected->outbound>=2) {
            if (!allow_tunnels_) return std::unexpected(UdpDirectError{UdpRouteError::unsupported});
            tunnel_=*selected; domain_pending_=false; wake(); return {};
        }
        auto sent=send_target(*packet,selected->target,input_metadata_.deadline);
        if (sent) { route_delivery_(false,*selected); delivery_(true,packet->data.size()); discard_domain(); }
        return sent;
    }
    auto UdpIngress::discard_domain() noexcept -> void {
        if (domain_pending_) { domain_pending_=false; input_pending_=false; input_size_=0; wake(); }
    }
    auto UdpIngress::pending_tunnel() const noexcept -> std::optional<UdpTunnelPacket> {
        if (closed_ || association_.closed() || !tunnel_) return {};
        auto packet=parse_udp_datagram(std::span(input_bytes_).first(input_size_));
        if (!packet) return {};
        return UdpTunnelPacket{*packet,tunnel_->target,tunnel_->outbound,input_metadata_.deadline,tunnel_alias_};
    }
    auto UdpIngress::complete_tunnel(bool delivered) noexcept -> void {
        if (!tunnel_) return;
        if (delivered) route_delivery_(external_route_,*tunnel_);
        tunnel_.reset(); tunnel_alias_.reset(); input_pending_=false; input_size_=0; input_metadata_={}; wake();
    }
    auto UdpIngress::reply_route(std::span<std::uint8_t const> payload) -> std::expected<UdpReplyStatus,UdpDirectError> {
        auto packet=pending_route();
        if(!packet)return std::unexpected(UdpDirectError{std::make_error_code(std::errc::operation_not_permitted)});
        packet->data=payload; return queue_reply(*packet);
    }
    auto UdpIngress::queue_tunnel_reply(UdpPeer source, std::span<std::uint8_t const> payload) -> std::expected<UdpReplyStatus,UdpDirectError> {
        if ((source.address_type!=1 && source.address_type!=4) || !source.port ||
            (source.address_type==1 && std::ranges::any_of(std::span(source.address).subspan(4),[](auto b){ return b!=0; })))
            return std::unexpected(UdpDirectError{Status::invalid_address});
        UdpDatagram packet; packet.address_type=source.address_type; packet.address_length=source.address_type==1 ? 4 : 16;
        packet.port=source.port; std::copy_n(source.address.begin(),packet.address_length,packet.address.begin()); packet.data=payload;
        return queue_reply(packet);
    }
    auto UdpIngress::queue_reply(UdpDatagram packet) -> std::expected<UdpReplyStatus,UdpDirectError> {
        if (closed_ || association_.closed()) { close(); return std::unexpected(UdpDirectError{Status::association_closed}); }
        if (fd_<0) return std::unexpected(UdpDirectError{std::make_error_code(std::errc::bad_file_descriptor)});
        if (pending_) return UdpReplyStatus::busy;
        auto client=association_.client_peer();
        if (!client) return std::unexpected(UdpDirectError{Status::unauthorized_source});
        auto limit=client->address_type==1 ? std::size_t{65507} : std::size_t{65527};
        if (packet.data.size()+6+packet.address_length+(packet.address_type==3)>limit) return UdpReplyStatus::dropped;
        auto wire=encode_udp_datagram(packet);
        if (!wire) return std::unexpected(UdpDirectError{wire.error()});
        pending_=UdpDirectReply{*client,std::move(*wire),packet.data.size()}; work_.set(); return UdpReplyStatus::queued;
    }
}
