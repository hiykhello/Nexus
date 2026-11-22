module;
#include <cerrno>
#include <netinet/in.h>
#include <sys/socket.h>
export module masque.udp_owner;
import std;
import masque.connect_udp;
import masque.target;
import masque.udp_session;
import masque.datagram;
import net.udp_socket;
import http.header;

export namespace masque {
    enum class OwnerError { stopped,capacity,malformed,identity,target,resolution,policy,socket,stale,not_ready };
    enum class OwnerSend { sent,dropped,would_block };
    struct PendingTarget {UdpHandle handle;std::string_view host;std::uint16_t port;};
    // One executor owns all entries and serializes policy, socket, and stop.
    // Policy::authenticate(headers) checks actual identity synchronously;
    // Policy::allow(identity,target,resolved) checks both the name and the
    // final numeric destination. Empty/no authentication is never implicit.
    // The caller copies PendingTarget before suspension; finish_resolve checks
    // the generation and stopping state again after DNS/cancellation returns.
    template<class Policy,std::size_t Streams=16> class UdpOwner {
        struct Entry {
            UdpTarget target;
            typename Policy::Identity identity;
            net::UdpSocket socket;
            net::UdpEndpoint peer{};
            explicit Entry(UdpTarget value,typename Policy::Identity selected):target(std::move(value)),identity(std::move(selected)) {}
        };
        Policy& policy_;
        std::string authority_;
        UdpRequests<Streams> requests_;
        std::array<std::optional<Entry>,Streams> entries_;
        bool stopping_=false;
        auto entry(UdpHandle h) noexcept -> Entry* {
            if(h.slot>=Streams || !requests_.phase(h) || !entries_[h.slot])return nullptr;
            return &*entries_[h.slot];
        }
        static auto no_fragment(net::UdpSocket& socket) noexcept -> bool {
            int mode=IP_PMTUDISC_DO;
            if(::setsockopt(socket.native_handle(),IPPROTO_IP,IP_MTU_DISCOVER,&mode,sizeof(mode))<0)return false;
            mode=IPV6_PMTUDISC_DO;
            return ::setsockopt(socket.native_handle(),IPPROTO_IPV6,IPV6_MTU_DISCOVER,&mode,sizeof(mode))==0;
        }
    public:
        UdpOwner(Policy& policy,std::string authority):policy_(policy),authority_(std::move(authority)) {}
        UdpOwner(UdpOwner const&)=delete;
        auto operator=(UdpOwner const&) -> UdpOwner& = delete;
        // During this call header views remain borrowed from nghttp3; a
        // successful identity is owned by Entry and no credential is retained.
        auto begin(std::uint64_t stream,std::span<http::HeaderField const> headers) -> std::expected<PendingTarget,OwnerError> {
            if(stopping_)return std::unexpected(OwnerError::stopped);
            auto request=parse_connect_udp_request(headers);
            if(!request || request->authority!=authority_)return std::unexpected(OwnerError::malformed);
            auto identity=policy_.authenticate(headers);if(!identity)return std::unexpected(OwnerError::identity);
            auto target=parse_well_known_udp_target(request->path);if(!target)return std::unexpected(OwnerError::target);
            auto handle=requests_.open(stream,true);if(!handle)return std::unexpected(OwnerError::capacity);
            try {entries_[handle->slot].emplace(std::move(*target),std::move(*identity));}
            catch(...) {requests_.close(*handle);throw;}
            auto& e=*entries_[handle->slot];return PendingTarget{*handle,e.target.host,e.target.port};
        }
        // Resolving a name and selecting an endpoint precedes HTTP 2xx. The
        // policy runs on the resolved address, preventing DNS rebinding from
        // bypassing name-only checks. No association exists on any failure.
        auto finish_resolve(UdpHandle h,net::UdpEndpoint peer) -> std::expected<void,OwnerError> {
            if(stopping_)return std::unexpected(OwnerError::stopped);
            auto* e=entry(h);if(!e || requests_.phase(h)!=UdpPhase::authorizing)return std::unexpected(OwnerError::stale);
            // IPv4-mapped IPv6 must not bypass an IPv4-specific policy.
            // This owner rejects mapped answers before invoking the policy.
            auto mapped=peer.family==6 && std::ranges::all_of(std::span(peer.address).first(10),[](auto b){return b==0;}) && peer.address[10]==0xff && peer.address[11]==0xff;
            if((peer.family!=4 && peer.family!=6) || mapped || peer.port!=e->target.port ||
               std::ranges::all_of(peer.address,[](auto b){return b==0;}) ||
               (peer.family==4 && std::ranges::any_of(std::span(peer.address).subspan(4),[](auto b){return b!=0;})))return std::unexpected(OwnerError::resolution);
            if(!policy_.allow(e->identity,e->target,peer))return std::unexpected(OwnerError::policy);
            net::UdpEndpoint local{};local.family=peer.family;
            if(!e->socket.bind(local) || !no_fragment(e->socket)) {close(h);return std::unexpected(OwnerError::socket);}
            e->peer=peer;
            if(!requests_.approve(h)){e->socket.close();return std::unexpected(OwnerError::stale);}
            return {};
        }
        auto pending(UdpHandle h) noexcept -> std::optional<PendingTarget> {
            auto* e=entry(h);if(stopping_ || !e || requests_.phase(h)!=UdpPhase::authorizing)return {};
            return PendingTarget{h,e->target.host,e->target.port};
        }
        auto ready(UdpHandle h) noexcept -> bool {return !stopping_ && requests_.can_receive(h) && requests_.can_send(h);}
        auto close_receive(UdpHandle h) noexcept -> void {requests_.receive_close(h);}
        auto close_send(UdpHandle h) noexcept -> void {requests_.send_close(h);}
        // Borrow only for readiness registration; the owner still owns it.
        auto native_handle(UdpHandle h) noexcept -> std::optional<int> {
            auto* e=entry(h);return !stopping_ && e && (requests_.can_receive(h) || requests_.can_send(h)) ? std::optional(e->socket.native_handle()) : std::nullopt;
        }
        auto permits(UdpHandle h,net::UdpEndpoint peer) -> bool {
            auto* e=entry(h);if(stopping_ || !e || requests_.phase(h)!=UdpPhase::authorizing)return false;
            auto mapped=peer.family==6 && std::ranges::all_of(std::span(peer.address).first(10),[](auto b){return b==0;}) && peer.address[10]==0xff && peer.address[11]==0xff;
            if((peer.family!=4 && peer.family!=6) || mapped || peer.port!=e->target.port ||
               std::ranges::all_of(peer.address,[](auto b){return b==0;}) ||
               (peer.family==4 && std::ranges::any_of(std::span(peer.address).subspan(4),[](auto b){return b!=0;})))return false;
            return policy_.allow(e->identity,e->target,peer);
        }
        auto send(UdpHandle h,std::span<std::uint8_t const> payload) -> std::expected<OwnerSend,OwnerError> {
            auto* e=entry(h);if(stopping_)return std::unexpected(OwnerError::stopped);
            if(!e || !requests_.can_receive(h))return std::unexpected(OwnerError::not_ready);
            if(payload.size()>max_udp_payload)return OwnerSend::dropped;
            auto result=e->socket.send(e->peer,payload);if(result)return OwnerSend::sent;
            if(result.error()==std::errc::message_size)return OwnerSend::dropped;
            if(result.error()==std::errc::resource_unavailable_try_again || result.error()==std::errc::operation_would_block)return OwnerSend::would_block;
            return std::unexpected(OwnerError::socket);
        }
        auto receive(UdpHandle h,std::span<std::uint8_t> output) -> std::expected<std::optional<std::size_t>,OwnerError> {
            auto* e=entry(h);if(stopping_)return std::unexpected(OwnerError::stopped);
            if(!e || !requests_.can_send(h))return std::unexpected(OwnerError::not_ready);
            auto packet=e->socket.receive(output);if(!packet)return std::unexpected(OwnerError::socket);
            if(!*packet || !(**packet).valid || (**packet).source!=e->peer)return std::optional<std::size_t>{};
            return std::optional<std::size_t>{(**packet).size};
        }
        // Abort immediately revokes the handle before any further DATAGRAM
        // callback; socket close and generation invalidation are synchronous.
        auto close(UdpHandle h) noexcept -> void {
            if(!entry(h))return;requests_.receive_close(h);requests_.send_close(h);
            entries_[h.slot]->socket.close();entries_[h.slot].reset();(void)requests_.close(h);
        }
        auto stop() noexcept -> void {
            if(std::exchange(stopping_,true))return;
            for(std::size_t i=0;i<Streams;++i)if(entries_[i]) {
                entries_[i]->socket.close();entries_[i].reset();
            }
        }
        auto drained() const noexcept -> bool {return stopping_ && std::ranges::all_of(entries_,[](auto const& e){return !e;});}
    };
}
