export module shadowsocks.udp_sessions;
import std;
import functional;
import shadowsocks.key;
import shadowsocks.udp_packet;
import shadowsocks.udp_replay;
import shadowsocks.udp_id_reservation;
import net.principal_bytes;

export namespace shadowsocks::udp_detail {
    [[nodiscard]] constexpr auto id_to_u64(std::array<std::uint8_t,8> id) noexcept -> std::uint64_t {
        return std::bit_cast<std::uint64_t>(id);
    }
    [[nodiscard]] constexpr auto u64_to_id(std::uint64_t id) noexcept -> std::array<std::uint8_t,8> {
        return std::bit_cast<std::array<std::uint8_t,8>>(id);
    }
    [[nodiscard]] constexpr auto hash_u64(std::uint64_t x) noexcept -> std::size_t {
        x^=x>>30; x*=0xbf58476d1ce4e5b9ULL;
        x^=x>>27; x*=0x94d049bb133111ebULL;
        x^=x>>31;
        return static_cast<std::size_t>(x);
    }

    // Append-only flat open-addressed uint64_t set (zero per-key node mallocs).
    class FlatU64Set {
        std::vector<std::uint64_t> table_;
        std::size_t size_=0;
        bool has_zero_=false;
        auto rehash(std::size_t cap) -> void {
            std::vector<std::uint64_t> next(cap,0);
            std::size_t const mask=cap-1;
            for (auto k:table_) {
                if (!k) continue;
                auto pos=hash_u64(k)&mask;
                while (next[pos]) pos=(pos+1)&mask;
                next[pos]=k;
            }
            table_.swap(next);
        }
    public:
        [[nodiscard]] auto size() const noexcept -> std::size_t { return size_; }
        [[nodiscard]] auto contains(std::uint64_t k) const noexcept -> bool {
            if (!k) return has_zero_;
            if (table_.empty()) return false;
            std::size_t const mask=table_.size()-1;
            auto pos=hash_u64(k)&mask;
            for (;;) {
                auto cur=table_[pos];
                if (cur==k) return true;
                if (!cur) return false;
                pos=(pos+1)&mask;
            }
        }
        auto insert(std::uint64_t k) -> bool {
            if (!k) { if (has_zero_) return false; has_zero_=true; ++size_; return true; }
            if (table_.empty()) rehash(32);
            else if ((size_+1)*2>table_.size()) rehash(table_.size()*2);
            std::size_t const mask=table_.size()-1;
            auto pos=hash_u64(k)&mask;
            for (;;) {
                auto cur=table_[pos];
                if (cur==k) return false;
                if (!cur) { table_[pos]=k; ++size_; return true; }
                pos=(pos+1)&mask;
            }
        }
        auto swap(FlatU64Set& other) noexcept -> void {
            table_.swap(other.table_); std::swap(size_,other.size_); std::swap(has_zero_,other.has_zero_);
        }
    };

    // Append-only flat open-addressed uint64_t -> uint64_t map (zero node mallocs).
    class FlatU64Map {
        struct Slot { std::uint64_t key=0,value=0; };
        std::vector<Slot> table_;
        std::size_t size_=0;
        bool has_zero_=false;
        std::uint64_t zero_value_=0;
        auto rehash(std::size_t cap) -> void {
            std::vector<Slot> next(cap);
            std::size_t const mask=cap-1;
            for (auto const& s:table_) {
                if (!s.key) continue;
                auto pos=hash_u64(s.key)&mask;
                while (next[pos].key) pos=(pos+1)&mask;
                next[pos]=s;
            }
            table_.swap(next);
        }
    public:
        [[nodiscard]] auto size() const noexcept -> std::size_t { return size_; }
        [[nodiscard]] auto find(std::uint64_t k) const noexcept -> std::optional<std::uint64_t> {
            if (!k) return has_zero_ ? std::optional(zero_value_) : std::nullopt;
            if (table_.empty()) return std::nullopt;
            std::size_t const mask=table_.size()-1;
            auto pos=hash_u64(k)&mask;
            for (;;) {
                auto const& cur=table_[pos];
                if (cur.key==k) return cur.value;
                if (!cur.key) return std::nullopt;
                pos=(pos+1)&mask;
            }
        }
        [[nodiscard]] auto contains(std::uint64_t k) const noexcept -> bool { return find(k).has_value(); }
        auto emplace(std::uint64_t k,std::uint64_t v) -> bool {
            if (!k) { if (has_zero_) return false; has_zero_=true; zero_value_=v; ++size_; return true; }
            if (table_.empty()) rehash(32);
            else if ((size_+1)*2>table_.size()) rehash(table_.size()*2);
            std::size_t const mask=table_.size()-1;
            auto pos=hash_u64(k)&mask;
            for (;;) {
                auto& cur=table_[pos];
                if (cur.key==k) return false;
                if (!cur.key) { cur={k,v}; ++size_; return true; }
                pos=(pos+1)&mask;
            }
        }
    };

    // Pointer-stable chunked intrusive LRU/FIFO table keyed by uint64_t with
    // O(1) flat open-addressed lookup and backward-shift deletion (supports
    // non-movable entries like UdpReplayWindow and net::UdpDialSockets).
    template<class Entry>
    class IntrusiveU64Table {
        static constexpr std::size_t kBlockShift=6,kBlockSize=1u<<kBlockShift,kBlockMask=kBlockSize-1;
    public:
        static constexpr std::uint32_t kNull=std::numeric_limits<std::uint32_t>::max();
    private:
        struct Node {
            std::optional<Entry> value;
            std::uint64_t key=0;
            std::uint32_t prev=kNull,next=kNull;
        };
        std::vector<std::unique_ptr<Node[]>> blocks_;
        std::vector<std::uint32_t> buckets_;
        std::size_t bucket_mask_=0,size_=0,next_alloc_=0;
        std::uint32_t head_=kNull,tail_=kNull,free_head_=kNull;

        [[nodiscard]] auto node(std::uint32_t idx) noexcept -> Node& { return blocks_[idx>>kBlockShift][idx&kBlockMask]; }
        [[nodiscard]] auto node(std::uint32_t idx) const noexcept -> Node const& { return blocks_[idx>>kBlockShift][idx&kBlockMask]; }

        auto ensure_buckets(std::size_t target) -> void {
            if (!buckets_.empty() && target*2<=buckets_.size()) return;
            std::size_t cap=buckets_.empty() ? 16 : buckets_.size();
            while (cap<target*2) cap<<=1;
            std::vector<std::uint32_t> next(cap,kNull);
            std::size_t const mask=cap-1;
            for (std::uint32_t cur=head_;cur!=kNull;cur=node(cur).next) {
                auto pos=hash_u64(node(cur).key)&mask;
                while (next[pos]!=kNull) pos=(pos+1)&mask;
                next[pos]=cur;
            }
            buckets_.swap(next);
            bucket_mask_=mask;
        }
        auto insert_bucket(std::uint64_t key,std::uint32_t idx) noexcept -> void {
            auto pos=hash_u64(key)&bucket_mask_;
            while (buckets_[pos]!=kNull) pos=(pos+1)&bucket_mask_;
            buckets_[pos]=idx;
        }
        auto erase_bucket(std::uint64_t key,std::uint32_t idx) noexcept -> void {
            if (buckets_.empty()) return;
            auto pos=hash_u64(key)&bucket_mask_;
            for (;;) {
                auto cur=buckets_[pos];
                if (cur==kNull) return;
                if (cur==idx) break;
                pos=(pos+1)&bucket_mask_;
            }
            std::size_t hole=pos;
            for (;;) {
                std::size_t cur_pos=(hole+1)&bucket_mask_;
                for (;;) {
                    auto cur=buckets_[cur_pos];
                    if (cur==kNull) { buckets_[hole]=kNull; return; }
                    auto ideal=hash_u64(node(cur).key)&bucket_mask_;
                    if (((hole-ideal)&bucket_mask_)<((cur_pos-ideal)&bucket_mask_)) {
                        buckets_[hole]=cur;
                        hole=cur_pos;
                        break;
                    }
                    cur_pos=(cur_pos+1)&bucket_mask_;
                }
            }
        }
        auto unlink(std::uint32_t idx) noexcept -> void {
            auto& n=node(idx);
            if (n.prev!=kNull) node(n.prev).next=n.next; else head_=n.next;
            if (n.next!=kNull) node(n.next).prev=n.prev; else tail_=n.prev;
            n.prev=n.next=kNull;
        }
        auto link_front(std::uint32_t idx) noexcept -> void {
            auto& n=node(idx);
            n.prev=kNull; n.next=head_;
            if (head_!=kNull) node(head_).prev=idx; else tail_=idx;
            head_=idx;
        }
        auto link_back(std::uint32_t idx) noexcept -> void {
            auto& n=node(idx);
            n.next=kNull; n.prev=tail_;
            if (tail_!=kNull) node(tail_).next=idx; else head_=idx;
            tail_=idx;
        }
        auto alloc_slot() -> std::uint32_t {
            if (free_head_!=kNull) {
                auto idx=free_head_;
                free_head_=node(idx).next;
                node(idx).next=kNull;
                return idx;
            }
            if ((next_alloc_&kBlockMask)==0) blocks_.push_back(std::make_unique<Node[]>(kBlockSize));
            return static_cast<std::uint32_t>(next_alloc_++);
        }
    public:
        IntrusiveU64Table()=default;
        IntrusiveU64Table(IntrusiveU64Table const&)=delete;
        auto operator=(IntrusiveU64Table const&) -> IntrusiveU64Table& = delete;

        [[nodiscard]] auto size() const noexcept -> std::size_t { return size_; }
        [[nodiscard]] auto empty() const noexcept -> bool { return size_==0; }
        [[nodiscard]] auto head() const noexcept -> std::uint32_t { return head_; }
        [[nodiscard]] auto tail() const noexcept -> std::uint32_t { return tail_; }
        [[nodiscard]] auto next_of(std::uint32_t idx) const noexcept -> std::uint32_t { return node(idx).next; }
        [[nodiscard]] auto prev_of(std::uint32_t idx) const noexcept -> std::uint32_t { return node(idx).prev; }
        [[nodiscard]] auto key_of(std::uint32_t idx) const noexcept -> std::uint64_t { return node(idx).key; }
        [[nodiscard]] auto at(std::uint32_t idx) noexcept -> Entry& { return *node(idx).value; }
        [[nodiscard]] auto at(std::uint32_t idx) const noexcept -> Entry const& { return *node(idx).value; }

        [[nodiscard]] auto find(std::uint64_t key) const noexcept -> std::optional<std::uint32_t> {
            if (buckets_.empty() || !size_) return std::nullopt;
            auto pos=hash_u64(key)&bucket_mask_;
            for (;;) {
                auto cur=buckets_[pos];
                if (cur==kNull) return std::nullopt;
                if (node(cur).key==key && node(cur).value) return cur;
                pos=(pos+1)&bucket_mask_;
            }
        }
        template<class... Args>
        auto emplace_front(std::uint64_t key,Args&&... args) -> std::uint32_t {
            ensure_buckets(size_+1);
            auto idx=alloc_slot();
            auto& n=node(idx);
            try { n.value.emplace(std::forward<Args>(args)...); }
            catch (...) { n.next=free_head_; free_head_=idx; throw; }
            n.key=key;
            link_front(idx);
            insert_bucket(key,idx);
            ++size_;
            return idx;
        }
        template<class... Args>
        auto emplace_back(std::uint64_t key,Args&&... args) -> std::uint32_t {
            ensure_buckets(size_+1);
            auto idx=alloc_slot();
            auto& n=node(idx);
            try { n.value.emplace(std::forward<Args>(args)...); }
            catch (...) { n.next=free_head_; free_head_=idx; throw; }
            n.key=key;
            link_back(idx);
            insert_bucket(key,idx);
            ++size_;
            return idx;
        }
        auto promote(std::uint32_t idx) noexcept -> void {
            if (idx==head_) return;
            unlink(idx);
            link_front(idx);
        }
        auto move_before(std::uint32_t idx,std::uint32_t target) noexcept -> void {
            if (idx==target) return;
            unlink(idx);
            if (target==head_) { link_front(idx); return; }
            auto& n=node(idx);
            auto p=node(target).prev;
            n.prev=p; n.next=target;
            node(p).next=idx;
            node(target).prev=idx;
        }
        auto erase(std::uint32_t idx) noexcept -> void {
            auto& n=node(idx);
            if (!n.value) return;
            unlink(idx);
            erase_bucket(n.key,idx);
            n.value.reset();
            n.next=free_head_;
            free_head_=idx;
            --size_;
        }
        auto clear() noexcept -> void {
            for (std::uint32_t cur=head_;cur!=kNull;) {
                auto next=node(cur).next;
                node(cur).value.reset();
                cur=next;
            }
            blocks_.clear(); buckets_.clear();
            bucket_mask_=size_=next_alloc_=0;
            head_=tail_=free_head_=kNull;
        }
        auto swap(IntrusiveU64Table& other) noexcept -> void {
            blocks_.swap(other.blocks_); buckets_.swap(other.buckets_);
            std::swap(bucket_mask_,other.bucket_mask_); std::swap(size_,other.size_);
            std::swap(next_alloc_,other.next_alloc_); std::swap(head_,other.head_);
            std::swap(tail_,other.tail_); std::swap(free_head_,other.free_head_);
        }
    };
}

export namespace shadowsocks {
    struct UdpPeer {
        // Family is 4 or 6; IPv4 uses the first four address bytes and zeros the rest.
        std::uint8_t family=0;
        std::array<std::uint8_t,16> address{};
        std::uint16_t port=0;
        // Opaque owner-local listener index, used only for client replies.
        std::size_t ingress=0;
        auto operator<=>(UdpPeer const&) const = default;
    };
    enum class UdpSessionError { packet, invalid_peer, time_reversed, duplicate, too_old, full, missing, random, exhausted, key_mismatch,
                                 storage, durability_required, busy, invalid_state, session_id_conflict, other_listener_generation, admission, byte_quota };
    struct UdpRequestIdentity {
        std::array<std::uint8_t,16> header;
        std::string_view user;
        void const* principal=nullptr;
        net::PrincipalBytes const* byte_budget=nullptr;
        std::shared_ptr<void> (*acquire)(void const*)=nullptr;
    };
    struct UdpReceiveScope {
        std::uint64_t listener_generation=0;
        bool allow_new=true;
        std::optional<UdpRequestIdentity> identity{};
    };
    class UdpServerSessions;
    struct UdpSessionHandle {
        std::array<std::uint8_t,8> id{};
        std::uint64_t generation=0;
        UdpServerSessions const* owner=nullptr;
    };
    // Capture the authenticated datagram's sender. The session's reply peer
    // can change while this packet is waiting for DNS or another operation.
    struct UdpAccepted {
        UdpPacket packet;
        bool new_session;
        std::uint64_t generation;
        UdpServerSessions const* owner;
        UdpPeer source;
        std::optional<std::string_view> auth_user{};
    };
    struct UdpResponse {
        UdpPeer peer;
        std::vector<std::uint8_t> wire;
        UdpSessionHandle session;
        std::size_t payload_size=0;
    };
    struct UdpStoredSession { std::array<std::uint8_t,8> id; UdpReplaySnapshot replay; };
    struct UdpClockSample { std::chrono::steady_clock::time_point monotonic; std::uint64_t wall; };
    // One serialized owner for one PSK across all listeners and workers. The
    // caller must preserve it while that key is active. The first authenticated
    // packet binds the PSK; mismatched keys fail closed. Removing this object or
    // restarting loses replay protection.
    class UdpServerSessions {
        using Clock=std::chrono::steady_clock;
        struct Entry {
            UdpReplayWindow replay; UdpPeer peer; Clock::time_point last; std::uint64_t generation=0;
            std::uint64_t listener_generation=0;
            std::shared_ptr<void> principal_lease;
            net::PrincipalBytes const* byte_budget=nullptr;
            std::optional<std::array<std::uint8_t,8>> server_id;
            std::uint64_t next_packet=0; bool exhausted=false,retired=false;
        };
        udp_detail::IntrusiveU64Table<Entry> entries_;
        // Never recycle IDs during this owner's lifetime, including after
        // expiry. The fixed bound prevents unbounded attacker-driven growth.
        udp_detail::FlatU64Set issued_server_ids_;
        udp_detail::FlatU64Set known_client_ids_;
        static constexpr std::size_t max_server_ids_=65536;
        std::size_t capacity_;
        CipherMethod method_;
        std::array<std::uint8_t,32> key_{};
        std::size_t key_size_=0;
        std::optional<Clock::time_point> last_;
        Clock::time_point anchor_mono_{};
        std::uint64_t anchor_wall_=0;
        std::uint64_t last_wall_=0;
        std::optional<std::pair<Clock::time_point,std::uint64_t>> recovery_anchor_;
        std::optional<std::uint64_t> next_server_id_;
        bool server_ids_exhausted_=false;
        std::uint64_t next_generation_=1;
        bool generations_exhausted_=false;
        bool durable_=false;
        bool recovered_=false;
        bool storage_failed_=false;
        bool committing_=false;
        std::uint64_t durable_wall_=0;
        std::unique_ptr<UdpIdReservation> durable_ids_;
        using Commit = functional::function_ref<bool(std::array<std::uint8_t,8> const&, UdpReplaySnapshot const&, std::uint64_t) noexcept>;
        using IdCommit = functional::function_ref<bool(UdpIdWatermark) noexcept>;
        using WallCommit = functional::function_ref<bool(std::uint64_t) noexcept>;
        using SampleClock = functional::function_ref<std::optional<UdpClockSample>() noexcept>;
        auto touch_order(std::uint32_t idx) noexcept -> void;
        auto allocate_server_id(std::array<std::uint8_t,8> client) -> std::expected<std::array<std::uint8_t,8>,UdpSessionError>;
        auto advance(Clock::time_point now, std::uint64_t wall) -> bool;
        auto receive_impl(std::span<std::uint8_t const> psk, std::span<std::uint8_t const> wire,
            UdpPeer peer, Clock::time_point now, std::uint64_t wall, std::optional<Commit> commit,
            std::optional<SampleClock> sample,UdpReceiveScope scope)
            -> std::expected<UdpAccepted,UdpSessionError>;
        auto response_impl(std::span<std::uint8_t const> psk, std::array<std::uint8_t,8> client,
            std::span<std::uint8_t const> address, std::span<std::uint8_t const> payload,
            std::span<std::uint8_t const> padding, Clock::time_point now, std::uint64_t wall,
            std::optional<IdCommit> commit, std::optional<WallCommit> wall_commit,
            std::optional<SampleClock> sample) -> std::expected<UdpResponse,UdpSessionError>;
    public:
        // Durable mode is experimental: expiry and actual trusted storage are
        // not implemented, so it is not suitable for the live service.
        explicit UdpServerSessions(std::size_t capacity, bool durable=false,CipherMethod method=CipherMethod::aes)
            : capacity_(capacity),method_(method),durable_(durable) {}
        [[nodiscard]] auto method() const noexcept -> CipherMethod {return method_;}
        ~UdpServerSessions();
        [[nodiscard]] auto has_history() const noexcept -> bool {return key_size_!=0;}
        [[nodiscard]] auto active(std::uint64_t generation) const noexcept -> bool {
            for (auto cur=entries_.head();cur!=udp_detail::IntrusiveU64Table<Entry>::kNull;cur=entries_.next_of(cur)) {
                auto const& e=entries_.at(cur);
                if (!e.retired && e.listener_generation==generation) return true;
            }
            return false;
        }
        UdpServerSessions(UdpServerSessions const&) = delete;
        auto operator=(UdpServerSessions const&) -> UdpServerSessions& = delete;
        [[nodiscard]] auto restore_durable(std::span<std::uint8_t const> psk,
            std::span<UdpStoredSession const> records, std::uint64_t watermark,
            Clock::time_point now, std::uint64_t wall, UdpIdWatermark ids, std::uint64_t block_size)
            -> std::expected<void,UdpSessionError>;
        [[nodiscard]] auto receive(std::span<std::uint8_t const> psk, std::span<std::uint8_t const> wire,
            UdpPeer peer, Clock::time_point now, std::uint64_t wall,UdpReceiveScope scope={})
            -> std::expected<UdpAccepted,UdpSessionError>;
        [[nodiscard]] auto receive_durable(std::span<std::uint8_t const> psk, std::span<std::uint8_t const> wire,
            UdpPeer peer, Clock::time_point now, std::uint64_t wall, Commit commit, SampleClock sample) -> std::expected<UdpAccepted,UdpSessionError>;
        [[nodiscard]] auto response(std::span<std::uint8_t const> psk, std::array<std::uint8_t,8> client,
            std::span<std::uint8_t const> address, std::span<std::uint8_t const> payload,
            std::span<std::uint8_t const> padding, Clock::time_point now, std::uint64_t wall)
            -> std::expected<UdpResponse,UdpSessionError>;
        [[nodiscard]] auto response_durable(std::span<std::uint8_t const> psk, std::array<std::uint8_t,8> client,
            std::span<std::uint8_t const> address, std::span<std::uint8_t const> payload,
            std::span<std::uint8_t const> padding, Clock::time_point now, std::uint64_t wall,
            IdCommit commit, WallCommit wall_commit, SampleClock sample)
            -> std::expected<UdpResponse,UdpSessionError>;
        [[nodiscard]] auto expire(Clock::time_point now, std::uint64_t wall,
            std::optional<std::uint64_t> listener_generation={})
            -> std::expected<std::vector<std::array<std::uint8_t,8>>,UdpSessionError>;
        [[nodiscard]] auto peer(std::array<std::uint8_t,8> id) const -> std::optional<UdpPeer>;
        auto retire_listener(std::uint64_t listener_generation,Clock::time_point now) noexcept -> void;
        [[nodiscard]] auto authorize_durable(UdpAccepted const& packet, SampleClock sample)
            -> std::expected<void,UdpSessionError>;
        [[nodiscard]] auto current(UdpAccepted const& packet,std::optional<std::uint64_t> listener_generation={}) const noexcept -> bool;
        [[nodiscard]] auto retire(UdpSessionHandle const& session,Clock::time_point now) noexcept -> bool;
        [[nodiscard]] auto current(UdpSessionHandle const& session,std::optional<std::uint64_t> listener_generation={}) const noexcept -> bool;
        [[nodiscard]] auto reserve_bytes(UdpSessionHandle const&,std::uint64_t listener_generation,
            bool upstream,std::size_t size,Clock::time_point now) const -> std::optional<net::PrincipalBytes::Reservation>;
        [[nodiscard]] auto size() const noexcept -> std::size_t { return entries_.size(); }
    };
}
