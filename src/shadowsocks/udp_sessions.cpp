module nexus.shadowsocks.udp_sessions;
import std;
import nexus.crypto;
namespace nexus::shadowsocks {
    namespace { constexpr std::uint64_t wall_reservation_seconds=60; }
    UdpServerSessions::~UdpServerSessions() { crypto::cleanse(key_); }
    auto UdpServerSessions::advance(Clock::time_point now,std::uint64_t wall) -> bool {
        if (last_ && now<*last_) return false;
        if (last_) {
            auto elapsed=std::chrono::duration_cast<std::chrono::seconds>(now-anchor_mono_).count();
            if (wall<last_wall_) return false;
            auto delta=wall-anchor_wall_;
            auto seconds=static_cast<std::uint64_t>(elapsed);
            if (seconds>delta && seconds-delta>1) return false;
            if (delta>seconds) { anchor_mono_=now; anchor_wall_=wall; }
        } else { anchor_mono_=now; anchor_wall_=wall; }
        last_=now; last_wall_=wall;
        return true;
    }
    auto UdpServerSessions::restore_durable(std::span<std::uint8_t const> psk,
        std::span<UdpStoredSession const> records,std::uint64_t watermark,Clock::time_point now,std::uint64_t wall,
        UdpIdWatermark ids,std::uint64_t block_size)
        -> std::expected<void,UdpSessionError> {
        if (committing_) return std::unexpected(UdpSessionError::busy);
        if (storage_failed_) return std::unexpected(UdpSessionError::storage);
        if (!durable_) return std::unexpected(UdpSessionError::durability_required);
        if (recovered_ || last_ || key_size_ || !entries_.empty()) return std::unexpected(UdpSessionError::invalid_state);
        if (psk.size()!=16 && psk.size()!=32) return std::unexpected(UdpSessionError::key_mismatch);
        if (wall<watermark) return std::unexpected(UdpSessionError::time_reversed);
        if (records.size()>capacity_) return std::unexpected(UdpSessionError::full);
        if (records.size()>=std::numeric_limits<std::uint64_t>::max()) return std::unexpected(UdpSessionError::exhausted);
        auto allocator=UdpIdReservation::create(ids,block_size);
        if (!allocator) return std::unexpected(UdpSessionError::invalid_state);
        decltype(entries_) restored;
        decltype(known_client_ids_) clients;
        std::uint64_t generation=1;
        for (auto const& record:records) {
            auto [it,inserted]=restored.try_emplace(record.id);
            if (!inserted || !record.replay.initialized || !it->second.replay.restore(record.replay))
                return std::unexpected(UdpSessionError::invalid_state);
            if (clients.size()>=max_server_ids_) return std::unexpected(UdpSessionError::full);
            clients.insert(record.id);
            it->second.last=now;
            it->second.generation=generation++;
        }
        entries_.swap(restored);
        known_client_ids_.swap(clients);
        std::ranges::copy(psk,key_.begin()); key_size_=psk.size();
        next_generation_=generation;
        durable_ids_=std::move(*allocator);
        durable_wall_=watermark;
        (void)advance(now,wall);
        recovered_=true;
        return {};
    }
    auto UdpServerSessions::receive(std::span<std::uint8_t const> psk,std::span<std::uint8_t const> wire,
        UdpPeer peer,Clock::time_point now,std::uint64_t wall) -> std::expected<UdpAccepted,UdpSessionError> {
        return receive_impl(psk,wire,peer,now,wall,{},{});
    }
    auto UdpServerSessions::receive_durable(std::span<std::uint8_t const> psk,std::span<std::uint8_t const> wire,
        UdpPeer peer,Clock::time_point now,std::uint64_t wall,Commit commit,SampleClock sample) -> std::expected<UdpAccepted,UdpSessionError> {
        return receive_impl(psk,wire,peer,now,wall,commit,sample);
    }
    auto UdpServerSessions::receive_impl(std::span<std::uint8_t const> psk,std::span<std::uint8_t const> wire,
        UdpPeer peer,Clock::time_point now,std::uint64_t wall,std::optional<Commit> commit,std::optional<SampleClock> sample) -> std::expected<UdpAccepted,UdpSessionError> {
        if (committing_) return std::unexpected(UdpSessionError::busy);
        if (storage_failed_) return std::unexpected(UdpSessionError::storage);
        if (durable_!=commit.has_value()) return std::unexpected(UdpSessionError::durability_required);
        if (durable_ && !recovered_) return std::unexpected(UdpSessionError::invalid_state);
        if ((peer.family!=4 && peer.family!=6) || !peer.port ||
            (peer.family==4 && std::ranges::any_of(std::span{peer.address}.subspan(4),[](auto byte){return byte!=0;})))
            return std::unexpected(UdpSessionError::invalid_peer);
        if (key_size_ && !crypto::constant_time_equal(psk,std::span{key_}.first(key_size_)))
            return std::unexpected(UdpSessionError::key_mismatch);
        auto packet=decode_udp_packet(psk,UdpDirection::client,wire,wall);
        if (!packet) return std::unexpected(UdpSessionError::packet);
        if (issued_server_ids_.contains(packet->session_id)) return std::unexpected(UdpSessionError::session_id_conflict);
        if (durable_) {
            std::uint64_t id=0;
            for (auto byte:packet->session_id) id=(id<<8)|byte;
            if (durable_ids_->reserved(id) && !known_client_ids_.contains(packet->session_id))
                return std::unexpected(UdpSessionError::session_id_conflict);
        }
        if (!key_size_) { std::ranges::copy(psk,key_.begin()); key_size_=psk.size(); }
        if (!advance(now,wall)) return std::unexpected(UdpSessionError::time_reversed);
        if (commit && wall>std::numeric_limits<std::uint64_t>::max()-wall_reservation_seconds)
            return std::unexpected(UdpSessionError::exhausted);
        auto it=entries_.find(packet->session_id);
        bool fresh=it==entries_.end();
        if (fresh) {
            if (entries_.size()>=capacity_) return std::unexpected(UdpSessionError::full);
            if (generations_exhausted_) return std::unexpected(UdpSessionError::exhausted);
            if (!known_client_ids_.contains(packet->session_id) && known_client_ids_.size()>=max_server_ids_)
                return std::unexpected(UdpSessionError::full);
            known_client_ids_.insert(packet->session_id);
            it=entries_.try_emplace(packet->session_id).first;
            it->second.generation=next_generation_;
            if (next_generation_==std::numeric_limits<std::uint64_t>::max()) generations_exhausted_=true;
            else ++next_generation_;
        }
        if (commit) {
            auto watermark=std::max(durable_wall_,wall+wall_reservation_seconds);
            auto proposal=it->second.replay.prepare(packet->packet_id);
            if (!proposal) {
                if (fresh) entries_.erase(it);
                return std::unexpected(proposal.error()==UdpReplayResult::duplicate ? UdpSessionError::duplicate : UdpSessionError::too_old);
            }
            committing_=true;
            auto written=(*commit)(packet->session_id,proposal->next_state(),watermark);
            committing_=false;
            if (!written) {
                storage_failed_=true;
                if (fresh) entries_.erase(it);
                return std::unexpected(UdpSessionError::storage);
            }
            durable_wall_=watermark;
            if (!it->second.replay.apply(*proposal)) {
                storage_failed_=true;
                if (fresh) entries_.erase(it);
                return std::unexpected(UdpSessionError::storage);
            }
            committing_=true;
            auto after=(*sample)();
            committing_=false;
            if (!after || after->wall>durable_wall_ || !advance(after->monotonic,after->wall)) {
                storage_failed_=true;
                return std::unexpected(UdpSessionError::time_reversed);
            }
            now=after->monotonic;
            auto timestamp=packet->timestamp;
            if ((timestamp>after->wall ? timestamp-after->wall : after->wall-timestamp)>30)
                return std::unexpected(UdpSessionError::packet);
        } else {
            auto replay=it->second.replay.commit(packet->packet_id);
            if (replay==UdpReplayResult::duplicate) return std::unexpected(UdpSessionError::duplicate);
            if (replay==UdpReplayResult::too_old) return std::unexpected(UdpSessionError::too_old);
        }
        it->second.peer=peer; it->second.last=now;
        return UdpAccepted{std::move(*packet),fresh,it->second.generation,this};
    }
    auto UdpServerSessions::allocate_server_id(std::array<std::uint8_t,8> client)
        -> std::expected<std::array<std::uint8_t,8>,UdpSessionError> {
        if (!next_server_id_ && !server_ids_exhausted_) {
            std::array<std::uint8_t,8> seed{};
            if (!nexus::crypto::random_bytes(seed)) return std::unexpected(UdpSessionError::random);
            std::uint64_t value=0;
            for (auto byte:seed) value=(value<<8)|byte;
            next_server_id_=value;
        }
        while (!server_ids_exhausted_) {
            auto value=*next_server_id_;
            if (value==std::numeric_limits<std::uint64_t>::max()) server_ids_exhausted_=true;
            else ++*next_server_id_;
            std::array<std::uint8_t,8> id{};
            for (std::size_t i=0;i<8;++i) id[i]=static_cast<std::uint8_t>(value>>(56-8*i));
            if (id!=client && !known_client_ids_.contains(id)) return id;
        }
        return std::unexpected(UdpSessionError::exhausted);
    }
    auto UdpServerSessions::response(std::span<std::uint8_t const> psk,std::array<std::uint8_t,8> client,
        std::span<std::uint8_t const> address,std::span<std::uint8_t const> payload,
        std::span<std::uint8_t const> padding,Clock::time_point now,std::uint64_t wall)
        -> std::expected<UdpResponse,UdpSessionError> {
        return response_impl(psk,client,address,payload,padding,now,wall,{},{},{});
    }
    auto UdpServerSessions::response_durable(std::span<std::uint8_t const> psk,std::array<std::uint8_t,8> client,
        std::span<std::uint8_t const> address,std::span<std::uint8_t const> payload,
        std::span<std::uint8_t const> padding,Clock::time_point now,std::uint64_t wall,IdCommit commit,WallCommit wall_commit,SampleClock sample)
        -> std::expected<UdpResponse,UdpSessionError> {
        return response_impl(psk,client,address,payload,padding,now,wall,commit,wall_commit,sample);
    }
    auto UdpServerSessions::response_impl(std::span<std::uint8_t const> psk,std::array<std::uint8_t,8> client,
        std::span<std::uint8_t const> address,std::span<std::uint8_t const> payload,
        std::span<std::uint8_t const> padding,Clock::time_point now,std::uint64_t wall,std::optional<IdCommit> commit,
        std::optional<WallCommit> wall_commit,std::optional<SampleClock> sample)
        -> std::expected<UdpResponse,UdpSessionError> {
        if (committing_) return std::unexpected(UdpSessionError::busy);
        if (storage_failed_) return std::unexpected(UdpSessionError::storage);
        if (durable_!=commit.has_value()) return std::unexpected(UdpSessionError::durability_required);
        if (durable_ && !recovered_) return std::unexpected(UdpSessionError::invalid_state);
        if (key_size_ && !crypto::constant_time_equal(psk,std::span{key_}.first(key_size_)))
            return std::unexpected(UdpSessionError::key_mismatch);
        auto it=entries_.find(client);
        if (it==entries_.end()) return std::unexpected(UdpSessionError::missing);
        if (!it->second.peer.port) return std::unexpected(UdpSessionError::missing);
        if (!advance(now,wall)) return std::unexpected(UdpSessionError::time_reversed);
        if (wall_commit) {
            if (wall>std::numeric_limits<std::uint64_t>::max()-wall_reservation_seconds)
                return std::unexpected(UdpSessionError::exhausted);
            auto watermark=std::max(durable_wall_,wall+wall_reservation_seconds);
            committing_=true;
            auto written=(*wall_commit)(watermark);
            committing_=false;
            if (!written) { storage_failed_=true; return std::unexpected(UdpSessionError::storage); }
            durable_wall_=watermark;
        }
        auto& entry=it->second;
        if (!entry.server_id) {
            if (issued_server_ids_.size()>=max_server_ids_) return std::unexpected(UdpSessionError::full);
            if (commit) {
                for (;;) {
                    committing_=true;
                    auto value=durable_ids_->take(*commit);
                    committing_=false;
                    if (!value) {
                        if (value.error()==UdpIdError::storage) storage_failed_=true;
                        return std::unexpected(value.error()==UdpIdError::storage ? UdpSessionError::storage : UdpSessionError::exhausted);
                    }
                    std::array<std::uint8_t,8> id{};
                    for (std::size_t i=0;i<8;++i) id[i]=static_cast<std::uint8_t>(*value>>(56-8*i));
                    if (id!=client && !known_client_ids_.contains(id)) { entry.server_id=id; break; }
                }
            } else {
                auto id=allocate_server_id(client);
                if (!id) return std::unexpected(id.error());
                entry.server_id=*id;
            }
            // If allocation fails, do not retain an ID that could be used
            // without being recorded. The consumed allocator ID is not reused.
            try { issued_server_ids_.insert(*entry.server_id); }
            catch (...) { entry.server_id.reset(); throw; }
        }
        if (sample) {
            committing_=true;
            auto after=(*sample)();
            committing_=false;
            if (!after || after->wall>durable_wall_ || !advance(after->monotonic,after->wall)) {
                storage_failed_=true;
                return std::unexpected(UdpSessionError::time_reversed);
            }
            now=after->monotonic;
            wall=after->wall;
        }
        if (entry.exhausted) return std::unexpected(UdpSessionError::exhausted);
        auto packet_id=entry.next_packet;
        if (packet_id==std::numeric_limits<std::uint64_t>::max()) entry.exhausted=true;
        else ++entry.next_packet;
        UdpPacket packet{*entry.server_id,packet_id,wall,client,
            std::vector<std::uint8_t>(address.begin(),address.end()),
            std::vector<std::uint8_t>(payload.begin(),payload.end())};
        auto wire=encode_udp_packet(psk,UdpDirection::server,packet,padding);
        if (!wire) return std::unexpected(UdpSessionError::packet);
        entry.last=now;
        return UdpResponse{entry.peer,std::move(*wire)};
    }
    auto UdpServerSessions::expire(Clock::time_point now,std::uint64_t wall)
        -> std::expected<std::vector<std::array<std::uint8_t,8>>,UdpSessionError> {
        if (committing_) return std::unexpected(UdpSessionError::busy);
        if (storage_failed_) return std::unexpected(UdpSessionError::storage);
        if (durable_) return std::unexpected(UdpSessionError::durability_required);
        if (!advance(now,wall)) return std::unexpected(UdpSessionError::time_reversed);
        std::vector<std::array<std::uint8_t,8>> expired;
        // Reserve first so allocation failure cannot remove sessions silently.
        expired.reserve(entries_.size());
        for (auto it=entries_.begin();it!=entries_.end();) {
            if (now-it->second.last>=std::chrono::seconds(62)) {
                expired.push_back(it->first); it=entries_.erase(it);
            } else ++it;
        }
        return expired;
    }
    auto UdpServerSessions::current(UdpAccepted const& packet) const noexcept -> bool {
        if (packet.owner!=this || storage_failed_ || committing_) return false;
        auto it=entries_.find(packet.packet.session_id);
        return it!=entries_.end() && it->second.generation==packet.generation;
    }
    auto UdpServerSessions::authorize_durable(UdpAccepted const& packet,SampleClock sample)
        -> std::expected<void,UdpSessionError> {
        if (committing_) return std::unexpected(UdpSessionError::busy);
        if (storage_failed_) return std::unexpected(UdpSessionError::storage);
        if (!durable_) return std::unexpected(UdpSessionError::durability_required);
        if (!current(packet)) return std::unexpected(UdpSessionError::missing);
        committing_=true;
        auto now=sample();
        committing_=false;
        if (!now || now->wall>durable_wall_ || !advance(now->monotonic,now->wall)) {
            storage_failed_=true;
            return std::unexpected(UdpSessionError::time_reversed);
        }
        auto timestamp=packet.packet.timestamp;
        if ((timestamp>now->wall ? timestamp-now->wall : now->wall-timestamp)>30)
            return std::unexpected(UdpSessionError::packet);
        return {};
    }
    auto UdpServerSessions::peer(std::array<std::uint8_t,8> id) const -> std::optional<UdpPeer> {
        auto it=entries_.find(id);
        return it==entries_.end() || !it->second.peer.port ? std::nullopt : std::optional{it->second.peer};
    }
}
