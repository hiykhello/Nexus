export module wireguard.identity;
import std;
import crypto;
import net.udp_socket;
import wireguard;
import wireguard.admission;
import wireguard.crypto;
import wireguard.initiation;
import wireguard.routing;

export namespace wireguard {
    namespace identity {
        using PeerHandle=routing::PeerHandle;
        enum class ErrorCode { invalid_peer,invalid_key,stale_peer,duplicate_key,identity_changed,unknown_peer,closed,protocol,admission,rate_limited };
        struct Failure { ErrorCode code; std::optional<Error> protocol; std::optional<admission::Failure> admission; };
        struct Entry { bool live=false; std::uint64_t generation=0; Key public_key{}; };
        // Applied only after MAC2 proves return reachability. Source ports do
        // not form separate quotas. Full tables reject new sources until an
        // inactive entry expires; active sources cannot reset their buckets.
        template<std::size_t Capacity=256> class HandshakeLimiter {
            static_assert(Capacity>0);
            struct Slot {
                std::array<std::uint8_t,16> address{};
                Clock::time_point updated{};
                Clock::duration tokens{};
                std::uint8_t family=0;
            };
            std::array<Slot,Capacity> slots_{};
            static constexpr auto cost=std::chrono::duration_cast<Clock::duration>(std::chrono::milliseconds(50));
            static constexpr auto burst=cost*5;
            static constexpr auto idle=std::chrono::duration_cast<Clock::duration>(std::chrono::seconds(1));
            static_assert(cost>Clock::duration::zero());
        public:
            [[nodiscard]] auto allow(net::UdpEndpoint const& source,Clock::time_point now) noexcept -> bool {
                if (!admission::valid_source(source) || now<Clock::time_point{}) return false;
                Slot* empty=nullptr;
                for (auto& slot:slots_) {
                    if (slot.family==source.family && slot.address==source.address) {
                        if (now<slot.updated) return false;
                        auto elapsed=now-slot.updated;
                        slot.tokens=elapsed>=burst ? burst : std::min(burst,slot.tokens+elapsed);
                        slot.updated=now;
                        if (slot.tokens<cost) return false;
                        slot.tokens-=cost;return true;
                    }
                    if (!empty && (!slot.family || (now>=slot.updated && now-slot.updated>idle))) empty=&slot;
                }
                if (!empty) return false;
                *empty=Slot{source.address,now,burst-cost,source.family};return true;
            }
            auto clear() noexcept -> void { slots_={}; }
        };
        inline auto failure(ErrorCode code,std::optional<Error> protocol={},std::optional<admission::Failure> admission={}) noexcept -> std::unexpected<Failure> {
            return std::unexpected(Failure{code,protocol,admission});
        }
    }
    template<std::size_t PeerCapacity=32> class PeerKeys;
    class PeerKeyView {
        template<std::size_t> friend class PeerKeys;
        std::span<identity::Entry const> entries_;
        explicit PeerKeyView(std::span<identity::Entry const> entries) noexcept : entries_(entries) {}
    public:
        [[nodiscard]] auto matches(identity::PeerHandle peer,Key const& public_key) const noexcept -> bool {
            return peer.slot<entries_.size() && peer.generation && entries_[peer.slot].live && entries_[peer.slot].generation==peer.generation && entries_[peer.slot].public_key==public_key;
        }
        [[nodiscard]] auto find(Key const& public_key) const noexcept -> std::optional<identity::PeerHandle> {
            for (std::size_t i=0;i<entries_.size();++i) if (entries_[i].live && entries_[i].public_key==public_key) return identity::PeerHandle{static_cast<std::uint16_t>(i),entries_[i].generation};
            return {};
        }
    };
    // Fixed public-key dispatch only. It never attempts DH/Noise for peers.
    // Replacing a public identity requires a newer handle generation, so an
    // old selected token cannot survive key removal/reuse under the same ID.
    template<std::size_t PeerCapacity> class PeerKeys {
        static_assert(PeerCapacity>0 && PeerCapacity<=4096);
        std::array<identity::Entry,PeerCapacity> entries_{};
    public:
        PeerKeys()=default;
        PeerKeys(PeerKeys const&)=delete;
        auto operator=(PeerKeys const&) -> PeerKeys& = delete;
        PeerKeys(PeerKeys&&)=delete;
        auto operator=(PeerKeys&&) -> PeerKeys& = delete;
        [[nodiscard]] auto view() const noexcept -> PeerKeyView { return PeerKeyView(entries_); }
        [[nodiscard]] auto activate(identity::PeerHandle peer,Key const& public_key) noexcept -> std::expected<void,identity::Failure> {
            if (peer.slot>=PeerCapacity || !peer.generation) return identity::failure(identity::ErrorCode::invalid_peer);
            if (std::ranges::all_of(public_key,[](auto c) { return c==0; })) return identity::failure(identity::ErrorCode::invalid_key);
            auto& entry=entries_[peer.slot];
            if (peer.generation<entry.generation || (peer.generation==entry.generation && !entry.live)) return identity::failure(identity::ErrorCode::stale_peer);
            if (peer.generation==entry.generation && entry.public_key!=public_key) return identity::failure(identity::ErrorCode::identity_changed);
            for (std::size_t i=0;i<entries_.size();++i) if (i!=peer.slot && entries_[i].live && entries_[i].public_key==public_key) return identity::failure(identity::ErrorCode::duplicate_key);
            entry={true,peer.generation,public_key}; return {};
        }
        [[nodiscard]] auto erase(identity::PeerHandle peer) noexcept -> std::expected<void,identity::Failure> {
            if (peer.slot>=PeerCapacity || !peer.generation || !entries_[peer.slot].live || entries_[peer.slot].generation!=peer.generation) return identity::failure(identity::ErrorCode::stale_peer);
            auto& entry=entries_[peer.slot]; entry.live=false; crypto::cleanse(entry.public_key); return {};
        }
        [[nodiscard]] auto size() const noexcept -> std::size_t { return std::ranges::count(entries_,true,&identity::Entry::live); }
    };
    struct SelectedInitiationState { identity::PeerHandle peer; net::UdpEndpoint source; OpenedInitiation opened; };
    class IdentityIngress;
    class SelectedInitiation {
        friend class IdentityIngress;
        identity::PeerHandle peer_;
        net::UdpEndpoint source_;
        OpenedInitiation opened_;
        bool active_=true;
        SelectedInitiation(identity::PeerHandle peer,net::UdpEndpoint source,OpenedInitiation opened) noexcept : peer_(peer),source_(source),opened_(std::move(opened)) {}
    public:
        ~SelectedInitiation() { close(); }
        SelectedInitiation(SelectedInitiation const&)=delete;
        auto operator=(SelectedInitiation const&) -> SelectedInitiation& = delete;
        SelectedInitiation(SelectedInitiation&& other) noexcept : peer_(other.peer_),source_(other.source_),opened_(std::move(other.opened_)),active_(std::exchange(other.active_,false)) {}
        auto operator=(SelectedInitiation&& other) noexcept -> SelectedInitiation& {
            if (this!=&other) { opened_=std::move(other.opened_); peer_=other.peer_; source_=other.source_; active_=std::exchange(other.active_,false); } return *this;
        }
        auto close() noexcept -> void { opened_.close(); active_=false; }
        [[nodiscard]] auto peer() const noexcept -> identity::PeerHandle { return peer_; }
        [[nodiscard]] auto take(PeerKeyView peers) noexcept -> std::expected<SelectedInitiationState,identity::Failure> {
            if (!std::exchange(active_,false) || !opened_.valid()) return identity::failure(identity::ErrorCode::stale_peer);
            if (!peers.matches(peer_,opened_.remote_public())) { opened_.close(); return identity::failure(identity::ErrorCode::stale_peer); }
            return SelectedInitiationState{peer_,source_,std::move(opened_)};
        }
    };
    namespace identity { struct Received { std::optional<admission::CookieRequest> cookie; std::optional<SelectedInitiation> selected; }; }
    // Borrows the stable immutable local key for the host's lifetime. Tokens
    // themselves own every byte needed after receive; no task/key/span borrow
    // escapes. Admission precedes exactly one static decrypt, then key lookup.
    class IdentityIngress {
    public:
        class ConstructionKey { friend class IdentityIngress; ConstructionKey()=default; public: ConstructionKey(ConstructionKey&&)=default; };
    private:
        crypto::X25519Private const& local_;
        CookieAdmission admission_;
        identity::HandshakeLimiter<> limiter_;
        bool closed_=false;
    public:
        IdentityIngress(ConstructionKey,crypto::X25519Private const& local,Key public_key) noexcept : local_(local),admission_(public_key) {}
        ~IdentityIngress() { close(); }
        IdentityIngress(IdentityIngress const&)=delete;
        auto operator=(IdentityIngress const&) -> IdentityIngress& = delete;
        IdentityIngress(IdentityIngress&&)=delete;
        auto operator=(IdentityIngress&&) -> IdentityIngress& = delete;
        [[nodiscard]] static auto create(crypto::X25519Private const& local) noexcept -> std::expected<IdentityIngress,identity::Failure> {
            auto public_key=local.public_key(); if (!public_key) return identity::failure(identity::ErrorCode::invalid_key,Error::invalid_key);
            return std::expected<IdentityIngress,identity::Failure>(std::in_place,ConstructionKey{},local,*public_key);
        }
        static auto create(crypto::X25519Private&&) -> std::expected<IdentityIngress,identity::Failure> = delete;
        static auto create(crypto::X25519Private const&&) -> std::expected<IdentityIngress,identity::Failure> = delete;
        auto close() noexcept -> void { admission_.close(); limiter_.clear(); closed_=true; }
        [[nodiscard]] auto rotate_cookie_secret(SecretKey secret,Clock::time_point now) noexcept -> std::expected<void,admission::Failure> { return admission_.rotate_secret(std::move(secret),now); }
        [[nodiscard]] auto poll_cookie(Clock::time_point now) noexcept -> std::expected<std::optional<admission::CookieRequest>,admission::Failure> { return admission_.poll(now); }
        [[nodiscard]] auto respond_cookie(admission::CookieRequest request,std::span<std::uint8_t const,24> nonce,Clock::time_point now) -> std::expected<admission::Reply,admission::Failure> { return admission_.respond(request,nonce,now); }
        [[nodiscard]] auto cookie_output_valid(std::uint64_t ticket) const noexcept -> bool { return admission_.reply_valid(ticket); }
        auto cancel_cookie() noexcept -> void { admission_.cancel(); }
        [[nodiscard]] auto admit_response(std::span<std::uint8_t const> wire,net::UdpEndpoint source,bool source_allowed,Clock::time_point now,bool require_cookie=false,bool allow_challenge=true)
            -> std::expected<admission::Decision,identity::Failure> {
            if (closed_) return identity::failure(identity::ErrorCode::closed);
            auto type=message_type(wire); if (!type || *type!=MessageType::response) return identity::failure(identity::ErrorCode::protocol,type ? Error::invalid_type : type.error());
            auto admitted=admission_.admit(wire,source,source_allowed,now,require_cookie,allow_challenge);
            if (!admitted) return identity::failure(identity::ErrorCode::admission,{},admitted.error());
            if (require_cookie && admitted->admitted && !limiter_.allow(source,now)) return identity::failure(identity::ErrorCode::rate_limited);
            return std::move(*admitted);
        }
        template<class Hooks=initiation_detail::NoHooks>
        [[nodiscard]] auto receive(std::span<std::uint8_t const> wire,net::UdpEndpoint source,bool source_allowed,Clock::time_point now,PeerKeyView peers,bool require_cookie=false,bool allow_challenge=true)
            -> std::expected<identity::Received,identity::Failure> {
            if (closed_) return identity::failure(identity::ErrorCode::closed);
            auto type=message_type(wire); if (!type || *type!=MessageType::initiation) return identity::failure(identity::ErrorCode::protocol,type ? Error::invalid_type : type.error());
            auto admitted=admission_.admit(wire,source,source_allowed,now,require_cookie,allow_challenge);
            if (!admitted) return identity::failure(identity::ErrorCode::admission,{},admitted.error());
            identity::Received result;
            if (admitted->cookie) { result.cookie=*admitted->cookie; return result; }
            if (require_cookie && !limiter_.allow(source,now)) return identity::failure(identity::ErrorCode::rate_limited);
            auto opened=OpenedInitiation::open<Hooks>(local_,admission_.local_public(),std::move(*admitted->admitted)); if (!opened) return identity::failure(identity::ErrorCode::protocol,opened.error());
            auto peer=peers.find(opened->remote_public()); if (!peer) return identity::failure(identity::ErrorCode::unknown_peer);
            result.selected.emplace(SelectedInitiation(*peer,source,std::move(*opened))); return result;
        }
    };
}
