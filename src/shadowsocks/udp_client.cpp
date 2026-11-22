module shadowsocks.udp_client;
import std;
import crypto;

namespace shadowsocks {
    UdpClientSession::UdpClientSession(std::span<std::uint8_t const> key,
        std::array<std::uint8_t,8> client,std::size_t server_capacity,CipherMethod method)
        : client_(client),capacity_(server_capacity),method_(method) {
        if (key.size()==32 || (key.size()==16 && method==CipherMethod::aes)) {
            std::ranges::copy(key,key_.begin()); key_size_=key.size();
        }
    }
    UdpClientSession::~UdpClientSession() { crypto::cleanse(key_); }
    auto UdpClientSession::advance(Clock::time_point now,std::uint64_t wall) noexcept -> bool {
        if (clock_failed_) return false;
        if (last_) {
            if (now<*last_ || wall<last_wall_) { clock_failed_=true; return false; }
            auto elapsed=std::chrono::duration_cast<std::chrono::seconds>(now-anchor_mono_).count();
            auto seconds=static_cast<std::uint64_t>(elapsed);
            auto delta=wall-anchor_wall_;
            if (seconds>delta && seconds-delta>1) { clock_failed_=true; return false; }
            if (delta>seconds) { anchor_mono_=now; anchor_wall_=wall; }
        } else { anchor_mono_=now; anchor_wall_=wall; }
        last_=now; last_wall_=wall; return true;
    }
    auto UdpClientSession::request(std::span<std::uint8_t const> address,
        std::span<std::uint8_t const> payload,std::span<std::uint8_t const> padding,Clock::time_point now,std::uint64_t wall,
        std::span<std::array<std::uint8_t,32> const> identities) -> std::expected<std::vector<std::uint8_t>,UdpClientError> {
        if (!key_size_) return std::unexpected(UdpClientError::invalid_key);
        if (!advance(now,wall)) return std::unexpected(UdpClientError::time_reversed);
        if (exhausted_) return std::unexpected(UdpClientError::exhausted);
        auto id=next_;
        if (id==std::numeric_limits<std::uint64_t>::max()) exhausted_=true;
        else ++next_;
        UdpPacket packet{client_,id,wall,{}, {address.begin(),address.end()}, {payload.begin(),payload.end()}};
        auto result=encode_udp_packet(std::span{key_}.first(key_size_),UdpDirection::client,packet,padding,method_,identities);
        if (!result) return std::unexpected(UdpClientError::packet);
        return std::move(*result);
    }
    auto UdpClientSession::receive(std::span<std::uint8_t const> wire,Clock::time_point now,std::uint64_t wall)
        -> std::expected<UdpPacket,UdpClientError> {
        if (!key_size_) return std::unexpected(UdpClientError::invalid_key);
        if (!advance(now,wall)) return std::unexpected(UdpClientError::time_reversed);
        auto packet=decode_udp_packet(std::span{key_}.first(key_size_),UdpDirection::server,wire,wall,client_,method_);
        if (!packet) return std::unexpected(packet.error()==UdpPacketError::session_collision ?
            UdpClientError::session_conflict : UdpClientError::packet);
        auto it=servers_.find(packet->session_id);
        if (it==servers_.end()) {
            if (servers_.size()>=capacity_) return std::unexpected(UdpClientError::full);
            it=servers_.try_emplace(packet->session_id).first;
        }
        switch (it->second.commit(packet->packet_id)) {
            case UdpReplayResult::duplicate: return std::unexpected(UdpClientError::duplicate);
            case UdpReplayResult::too_old: return std::unexpected(UdpClientError::too_old);
            case UdpReplayResult::fresh: return std::move(*packet);
        }
        std::unreachable();
    }

    UdpClientPool::UdpClientPool(std::span<std::uint8_t const> key,std::size_t active_limit,
        std::size_t history_limit,std::size_t server_limit)
        : active_limit_(active_limit),history_limit_(history_limit),server_limit_(server_limit) {
        if (key.size()==16 || key.size()==32) { std::ranges::copy(key,key_.begin()); key_size_=key.size(); }
    }
    UdpClientPool::~UdpClientPool() { crypto::cleanse(key_); }
    auto UdpClientPool::advance(Clock::time_point now,std::uint64_t wall) noexcept -> bool {
        if (last_) {
            if (now<*last_ || wall<last_wall_) { failed_=true; return false; }
            auto seconds=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(now-anchor_mono_).count());
            auto delta=wall-anchor_wall_;
            if (seconds>delta && seconds-delta>1) { failed_=true; return false; }
            if (delta>seconds) { anchor_mono_=now; anchor_wall_=wall; }
        } else { anchor_mono_=now; anchor_wall_=wall; }
        last_=now; last_wall_=wall; return true;
    }
    auto UdpClientPool::open() -> std::expected<Id,UdpClientError> {
        if (failed_) return std::unexpected(UdpClientError::failed);
        if (!key_size_) return std::unexpected(UdpClientError::invalid_key);
        if (active_.size()>=active_limit_ || clients_.size()>=history_limit_) return std::unexpected(UdpClientError::full);
        if (!next_ && !exhausted_) {
            std::array<std::uint8_t,8> seed{};
            if (!crypto::random_bytes(seed)) return std::unexpected(UdpClientError::random);
            std::uint64_t value=0; for (auto byte:seed) value=(value<<8)|byte;
            next_=value;
        }
        while (!exhausted_) {
            auto value=*next_;
            if (value==std::numeric_limits<std::uint64_t>::max()) { exhausted_=true; next_.reset(); }
            else next_=value+1;
            Id id{}; for (std::size_t i=0;i<id.size();++i) id[i]=static_cast<std::uint8_t>(value>>(56-8*i));
            if (clients_.contains(id) || servers_.contains(id)) continue;
            // Reserve before allocation; an exception may waste an ID, never reuse it.
            clients_.insert(id);
            active_.emplace(id,std::make_unique<UdpClientSession>(std::span{key_}.first(key_size_),id,server_limit_));
            return id;
        }
        return std::unexpected(UdpClientError::exhausted);
    }
    auto UdpClientPool::close(Id id) noexcept -> bool { return active_.erase(id)!=0; }
    auto UdpClientPool::request(Id id,std::span<std::uint8_t const> address,std::span<std::uint8_t const> payload,
        std::span<std::uint8_t const> padding,Clock::time_point now,std::uint64_t wall)
        -> std::expected<std::vector<std::uint8_t>,UdpClientError> {
        if (failed_) return std::unexpected(UdpClientError::failed);
        auto it=active_.find(id);
        if (it==active_.end()) return std::unexpected(UdpClientError::missing);
        if (!advance(now,wall)) return std::unexpected(UdpClientError::time_reversed);
        return it->second->request(address,payload,padding,now,wall);
    }
    auto UdpClientPool::receive(Id id,std::span<std::uint8_t const> wire,Clock::time_point now,std::uint64_t wall)
        -> std::expected<UdpPacket,UdpClientError> {
        if (failed_) return std::unexpected(UdpClientError::failed);
        auto it=active_.find(id);
        if (it==active_.end()) return std::unexpected(UdpClientError::missing);
        if (!advance(now,wall)) return std::unexpected(UdpClientError::time_reversed);
        auto packet=it->second->receive(wire,now,wall);
        if (!packet) {
            if (packet.error()==UdpClientError::session_conflict || packet.error()==UdpClientError::time_reversed) failed_=true;
            return std::unexpected(packet.error());
        }
        auto server=servers_.find(packet->session_id);
        if (clients_.contains(packet->session_id) || (server!=servers_.end() && server->second!=id)) {
            failed_=true; return std::unexpected(UdpClientError::session_conflict);
        }
        if (server==servers_.end()) {
            if (servers_.size()>=server_limit_) { failed_=true; return std::unexpected(UdpClientError::full); }
            // The per-session replay window is already committed. If recording
            // the global identity throws, no other session may continue with
            // an incomplete history.
            try { servers_.emplace(packet->session_id,id); }
            catch (...) { failed_=true; throw; }
        }
        return std::move(*packet);
    }
}
