// Included in the Tailscale WireGuard implementation unit.
namespace discovery {
    using Key = control_messages::DiscoKey;
    using Address = net::UdpEndpoint;
    using Transaction = stun::Transaction;
    using Bytes = std::span<const std::uint8_t>;
    inline constexpr std::array<std::uint8_t,6> magic{0x54,0x53,0xf0,0x9f,0x92,0xac};
    inline constexpr std::size_t header = magic.size() + Key{}.size() + box::nonce_size;
    inline constexpr auto interval = std::chrono::seconds(1);
    inline constexpr auto lifetime = std::chrono::seconds(3);

    struct Peer {
        Key node, key;
        box::SharedKey secret;
        nexus::inplace_vector<Address, control_messages::max_endpoints> candidates;
        std::optional<Address> verified, pending;
        Transaction transaction{};
        Clock::time_point next{}, expires{}, sent{}, last_ping{};
        std::size_t cursor = 0;
    };

    class Paths {
        std::optional<crypto::X25519Private> identity_;
        std::optional<Key> local_;
        Key node_{};
        std::vector<Peer> peers_;
        std::optional<Address> stun_server_, mapped_;
        Clock::time_point next_stun_{}, mapping_expiry_{};
        stun::Queries<1> queries_;
        bool changed_ = false;

        template<class Send>
        auto send(Send& transmit, Peer const& peer, Address address, Bytes body) -> bool {
            std::array<std::uint8_t, header + 64 + box::tag_size> wire;
            std::ranges::copy(magic,wire.begin());
            std::ranges::copy(*local_,wire.begin()+magic.size());
            auto nonce=std::span(wire).subspan(magic.size()+local_->size(),box::nonce_size);
            if(!crypto::random_bytes(nonce))return false;
            auto length=peer.secret.seal_to(std::span(wire).subspan(header),nonce,body);
            return length && transmit(address,std::span(wire).first(header+*length));
        }

    public:
        Paths(Bytes node, bool enabled, std::optional<Address> stun_server) : stun_server_(stun_server) {
            auto key=crypto::X25519Private::from_bytes(node);
            if(key) if(auto public_key=key->public_key())node_=*public_key;
            Key secret;
            if(enabled && crypto::random_bytes(secret)) {
                auto identity=crypto::X25519Private::from_bytes(secret);
                crypto::cleanse(secret);
                if(identity)if(auto public_key=identity->public_key()) {
                    local_=*public_key;
                    identity_.emplace(std::move(*identity));
                }
            }
        }

        auto public_key() const noexcept -> std::optional<Key> { return local_; }
        auto mapped_endpoint() const noexcept -> std::optional<Address> { return mapped_; }
        auto changed() noexcept -> bool { return std::exchange(changed_,false); }
        auto clear() noexcept -> void { peers_.clear(); changed_=false; }

        auto install(map_session::State const& state) -> void {
            if(!identity_)return;
            std::vector<Peer> next;
            auto now=Wall::now();
            for(auto const& remote:state.peers()) {
                if(!remote.discovery || !wireguard_routes::usable(remote,now) ||
                   std::ranges::count(state.peers(),remote.discovery,&snapshot::Peer::discovery)!=1)continue;
                Key node;
                std::ranges::copy(remote.key.view(),node.begin());
                nexus::inplace_vector<Address,control_messages::max_endpoints> addresses;
                for(auto const& endpoint:remote.endpoints)
                    addresses.push_back({endpoint.family,endpoint.address,endpoint.port});
                auto same=std::ranges::find_if(peers_,[&](auto const& previous) {
                    return previous.node==node && previous.key==*remote.discovery && previous.candidates==addresses;
                });
                if(same!=peers_.end()) {next.push_back(std::move(*same));continue;}
                auto secret=box::SharedKey::derive(*identity_,*remote.discovery);
                if(secret)next.push_back({node,*remote.discovery,std::move(*secret),addresses});
            }
            peers_=std::move(next);
            changed_=false;
        }

        auto verified(Key const& node) const noexcept -> std::optional<Address> {
            auto peer=std::ranges::find(peers_,node,&Peer::node);
            return peer==peers_.end() ? std::nullopt : peer->verified;
        }

        template<class Send>
        auto receive(Address source, Bytes packet, Clock::time_point now, Send transmit) -> bool {
            if(stun_server_ && source==*stun_server_ && stun::parse_message(packet)) {
                if(auto result=queries_.accept(packet,source,now)) {
                    mapped_=result->mapped;
                    mapping_expiry_=now+std::chrono::seconds(9);
                }
                return true;
            }
            if(!local_ || packet.size()<header+box::tag_size+14 ||
               !std::ranges::equal(packet.first(magic.size()),magic)) return false;
            auto key=packet.subspan(magic.size(),local_->size());
            auto peer=std::ranges::find_if(peers_,[&](auto const& value) {return std::ranges::equal(key,value.key);});
            if(peer==peers_.end() || std::ranges::find(peer->candidates,source)==peer->candidates.end())return true;
            std::array<std::uint8_t,512> plaintext;
            auto length=peer->secret.open_to(plaintext,packet.subspan(header-box::nonce_size,box::nonce_size),packet.subspan(header));
            if(!length || *length<14 || plaintext[1]!=0)return true;
            auto transaction=std::span(plaintext).subspan(2,12);
            if(plaintext[0]==2 && *length>=32 && peer->pending==source && now<peer->sent+lifetime &&
               std::ranges::equal(transaction,peer->transaction)) {
                peer->pending.reset();
                if(peer->verified!=source)changed_=true;
                peer->verified=source;
                peer->expires=now+lifetime;
            } else if(plaintext[0]==1 && now>=peer->last_ping+std::chrono::milliseconds(200)) {
                if(*length>=46 && !std::ranges::equal(std::span(plaintext).subspan(14,32),peer->node))return true;
                peer->last_ping=now;
                std::array<std::uint8_t,32> pong{2,0};
                std::ranges::copy(transaction,pong.begin()+2);
                if(source.family==4) {
                    pong[24]=pong[25]=0xff;
                    std::copy_n(source.address.begin(),4,pong.begin()+26);
                } else std::ranges::copy(source.address,pong.begin()+14);
                pong[30]=static_cast<std::uint8_t>(source.port>>8);
                pong[31]=static_cast<std::uint8_t>(source.port);
                (void)send(transmit,*peer,source,pong);
            }
            return true;
        }

        template<class Send>
        auto poll(Clock::time_point now, Send transmit) -> void {
            if (stun_server_ && now>=next_stun_) {
                Transaction transaction;
                next_stun_=now+std::chrono::seconds(3);
                if(crypto::random_bytes(transaction)) {
                    if(auto query=queries_.reserve(transaction,*stun_server_,now,now+interval)) {
                        auto wire=stun::encode_request(transaction);
                        if(!transmit(*stun_server_,wire)) (void)queries_.cancel(*query);
                    }
                }
            }
            if(mapped_ && now>=mapping_expiry_)mapped_.reset();
            for(auto& peer:peers_) {
                if(peer.verified && now>=peer.expires) {peer.verified.reset();changed_=true;}
                if(peer.candidates.empty() || now<peer.next)continue;
                auto target=peer.verified.value_or(peer.candidates[peer.cursor++%peer.candidates.size()]);
                peer.next=now+interval;
                peer.pending.reset();
                if(!crypto::random_bytes(peer.transaction))continue;
                std::array<std::uint8_t,46> ping{1,0};
                std::ranges::copy(peer.transaction,ping.begin()+2);
                std::ranges::copy(node_,ping.begin()+14);
                if(send(transmit,peer,target,ping)) {peer.pending=target;peer.sent=now;}
            }
        }
    };
}
