export module hysteria2.fragments;
import std;
import containers.ring_queue;
import hysteria2.wire;
import hysteria2.udp;
import hysteria2.sessions;

export namespace hysteria2 {
    // Shared across executors. This accounts for admitted dynamic UDP payload
    // storage, including both old and new buffers during a growth operation.
    class UdpMemoryBudget {
        std::atomic<std::size_t> used_{0};
        std::size_t const limit_;
    public:
        explicit UdpMemoryBudget(std::size_t limit) noexcept :limit_(limit) {}
        UdpMemoryBudget(UdpMemoryBudget const&)=delete;
        auto operator=(UdpMemoryBudget const&) -> UdpMemoryBudget& = delete;
        [[nodiscard]] auto acquire(std::size_t size) noexcept -> bool {
            auto used=used_.load(std::memory_order_relaxed);
            for (;;) {
                if (size>limit_ || used>limit_-size) return false;
                if (used_.compare_exchange_weak(used,used+size,std::memory_order_acquire,std::memory_order_relaxed)) return true;
            }
        }
        auto release(std::size_t size) noexcept -> void {used_.fetch_sub(size,std::memory_order_release);}
        [[nodiscard]] auto used() const noexcept -> std::size_t {return used_.load(std::memory_order_acquire);}
        [[nodiscard]] auto limit() const noexcept -> std::size_t {return limit_;}
    };
    inline auto default_udp_memory_budget() noexcept -> UdpMemoryBudget& {
        static UdpMemoryBudget budget(32*1024*1024);return budget;
    }
    enum class ReassemblyStatus { incomplete,accepted,duplicate,expired,malformed,too_large,full,backpressure,session,clock,allocation_failed,closed };
    struct ReassembledPacket {
        UdpSessionHandle owner;
        std::uint32_t session;
        std::string_view address;
        std::span<std::uint8_t const> payload;
    };
    // The table and caller's clock outlive this owner. Slots and fragment
    // metadata are fixed; only admitted fragment payloads allocate. Their
    // allowance counts each retained fragment byte. Metadata and the first
    // completed packet buffer add sizeof(owner) storage, not an RSS claim.
    // Additional ready buffers grow to the required packet size and are
    // reused while the queue is nonempty; draining releases their budget.
    // Failed or expired packet keys occupy a slot until twice their original
    // lifetime. Late fragments never extend that bounded discard interval.
    template<class Sessions,std::size_t PacketCapacity=64,std::size_t ReadyCapacity=1>
    class UdpReassembler {
        static_assert(PacketCapacity>0 && PacketCapacity<=256 && ReadyCapacity>0 && ReadyCapacity<=64);
        struct Fragment {
            std::unique_ptr<std::uint8_t[]> bytes;
            std::size_t size=0;
            bool present=false;
        };
        struct Packet {
            std::array<Fragment,255> fragments;
            std::array<char,max_address_bytes> address{};
            UdpSessionHandle owner;
            UdpClock::time_point started{};
            std::uint32_t session=0;
            std::uint16_t id=0;
            std::uint8_t count=0;
            std::size_t address_size=0,received=0,bytes=0;
            bool active=false,discarded=false;
        };
        Sessions& sessions_;
        std::array<Packet,PacketCapacity> packets_;
        struct Ready {
            std::array<char,max_address_bytes> address{};
            UdpSessionHandle owner;
            std::uint32_t session=0;
            std::size_t size=0,address_size=0;
        };
        std::array<Ready,ReadyCapacity> ready_{};
        std::array<std::uint8_t,max_udp_payload> first_ready_{};
        struct ExtraReady {std::unique_ptr<std::uint8_t[]> bytes;std::size_t capacity=0;};
        std::array<ExtraReady,ReadyCapacity-1> extra_ready_{};
        containers::RingQueue<ReadyCapacity> ready_slots_;
        std::size_t buffered_=0,active_=0;
        std::size_t max_bytes_,max_packet_;
        UdpMemoryBudget* budget_;
        std::chrono::milliseconds lifetime_;
        std::optional<UdpClock::time_point> observed_;
        bool closed_=false;
        auto next_ready() noexcept -> Ready& {return ready_[ready_slots_.tail()];}
        auto ensure_ready(std::size_t size) noexcept -> ReassemblyStatus {
            auto index=ready_slots_.tail();if (!index || extra_ready_[index-1].capacity>=size) return ReassemblyStatus::accepted;
            auto& extra=extra_ready_[index-1];
            if (budget_ && !budget_->acquire(size)) return ReassemblyStatus::full;
            try {extra.bytes=std::make_unique_for_overwrite<std::uint8_t[]>(size);}
            catch (std::bad_alloc const&) {if (budget_) budget_->release(size);return ReassemblyStatus::allocation_failed;}
            if (budget_) budget_->release(extra.capacity);
            extra.capacity=size;
            return ReassemblyStatus::accepted;
        }
        auto ready_bytes(std::size_t index) noexcept -> std::uint8_t* {return index ? extra_ready_[index-1].bytes.get() : first_ready_.data();}
        auto ready_bytes(std::size_t index) const noexcept -> std::uint8_t const* {return index ? extra_ready_[index-1].bytes.get() : first_ready_.data();}
        auto release_extra() noexcept -> void {
            for (auto& extra:extra_ready_) {extra.bytes.reset();if (budget_) budget_->release(extra.capacity);extra.capacity=0;}
        }
        auto discard_ready() noexcept -> void {
            if (!ready_slots_.empty()) ready_slots_.consume();
            if (ready_slots_.empty()) release_extra();
        }
        auto clear(Packet& packet) noexcept -> void {
            if (!packet.active) return;
            buffered_-=packet.bytes; --active_;
            for (auto& fragment:packet.fragments) { fragment.bytes.reset(); fragment.size=0; fragment.present=false; }
            if (budget_) budget_->release(packet.bytes);
            packet.active=packet.discarded=false; packet.bytes=packet.received=packet.address_size=0; packet.count=0;
        }
        auto discard(Packet& packet) noexcept -> void {
            buffered_-=packet.bytes;
            for (auto& fragment:packet.fragments) { fragment.bytes.reset(); fragment.size=0; fragment.present=false; }
            if (budget_) budget_->release(packet.bytes);
            packet.bytes=packet.received=0; packet.discarded=true;
        }
        auto same_address(Packet const& packet,std::string_view address) const noexcept -> bool {
            return address==std::string_view(packet.address.data(),packet.address_size);
        }
    public:
        UdpReassembler(Sessions& sessions,std::size_t bytes=1024*1024,std::size_t packet_bytes=max_udp_payload,
            std::chrono::milliseconds lifetime=std::chrono::seconds(5),UdpMemoryBudget* budget=nullptr)
            : sessions_(sessions),max_bytes_(bytes),max_packet_(packet_bytes),budget_(budget),lifetime_(lifetime) {
            if (!bytes || bytes>16*1024*1024 || !packet_bytes || packet_bytes>max_udp_payload ||
                lifetime.count()<1 || lifetime>std::chrono::minutes(1)) throw std::invalid_argument("invalid Hy2 reassembly limits");
        }
        UdpReassembler(UdpReassembler const&)=delete;
        auto operator=(UdpReassembler const&) -> UdpReassembler& = delete;
        ~UdpReassembler() {close();}
        auto prune(UdpClock::time_point now) noexcept -> bool {
            if (observed_ && now<*observed_) return false;
            observed_=now;
            for (auto& packet:packets_) if (packet.active) {
                if (!sessions_.live(packet.owner,now) || (now>=packet.started && now-packet.started>=lifetime_*2)) clear(packet);
                else if (!packet.discarded && now>=packet.started && now-packet.started>=lifetime_) discard(packet);
            }
            while(!ready_slots_.empty() && !sessions_.live(ready_[ready_slots_.front()].owner,now))discard_ready();
            return true;
        }
        auto feed(UdpSessionHandle owner,UdpPacket const& input,UdpClock::time_point now) noexcept -> ReassemblyStatus {
            if (closed_) return ReassemblyStatus::closed;
            if (!prune(now)) return ReassemblyStatus::clock;
            if (ready_slots_.full()) return ReassemblyStatus::backpressure;
            if (!sessions_.live(owner,now) || sessions_.id(owner)!=input.session) return ReassemblyStatus::session;
            if (input.address.empty() || input.address.size()>max_address_bytes || !valid_fragment(input.fragment,input.count)) return ReassemblyStatus::malformed;
            if (input.payload.size()>max_packet_) return ReassemblyStatus::too_large;
            if (input.count==1) {
                auto capacity=ensure_ready(input.payload.size());if (capacity!=ReassemblyStatus::accepted) return capacity;
                auto& ready=next_ready();if (!input.payload.empty()) std::ranges::copy(input.payload,ready_bytes(ready_slots_.tail()));
                std::ranges::copy(input.address,ready.address.begin());
                ready.owner=owner;ready.session=input.session;ready.size=input.payload.size();ready.address_size=input.address.size();ready_slots_.commit();
                return ReassemblyStatus::accepted;
            }
            Packet* selected=nullptr;
            for (auto& packet:packets_) if (packet.active && packet.owner==owner && packet.id==input.packet) { selected=&packet; break; }
            if (selected && selected->discarded) return ReassemblyStatus::expired;
            if (selected && (selected->session!=input.session || selected->count!=input.count || !same_address(*selected,input.address))) {
                discard(*selected); return ReassemblyStatus::malformed;
            }
            if (selected && selected->fragments[input.fragment].present) {
                auto const& previous=selected->fragments[input.fragment];
                if (previous.size!=input.payload.size() || !std::equal(input.payload.begin(),input.payload.end(),previous.bytes.get())) {
                    discard(*selected); return ReassemblyStatus::malformed;
                }
                return ReassemblyStatus::duplicate;
            }
            if (selected && input.payload.size()>max_packet_-selected->bytes) { discard(*selected); return ReassemblyStatus::too_large; }
            if (input.payload.size()>max_bytes_-buffered_) return ReassemblyStatus::full;
            if (!selected) {
                auto free=std::ranges::find_if(packets_,[](auto const& packet) { return !packet.active; });
                if (free==packets_.end()) return ReassemblyStatus::full;
                selected=&*free;
            }
            std::unique_ptr<std::uint8_t[]> bytes;
            if (!input.payload.empty()) {
                if (budget_ && !budget_->acquire(input.payload.size())) return ReassemblyStatus::full;
                try { bytes=std::make_unique_for_overwrite<std::uint8_t[]>(input.payload.size()); }
                catch (std::bad_alloc const&) {if (budget_) budget_->release(input.payload.size());return ReassemblyStatus::allocation_failed; }
                std::ranges::copy(input.payload,bytes.get());
            }
            if (selected->active && selected->received+1==selected->count) {
                auto capacity=ensure_ready(selected->bytes+input.payload.size());
                if (capacity!=ReassemblyStatus::accepted) {
                    bytes.reset();if (budget_) budget_->release(input.payload.size());return capacity;
                }
            }
            if (!selected->active) {
                selected->active=true; selected->owner=owner; selected->session=input.session; selected->id=input.packet;
                selected->count=input.count; selected->started=now; selected->address_size=input.address.size();
                std::ranges::copy(input.address,selected->address.begin()); ++active_;
            }
            auto& fragment=selected->fragments[input.fragment];
            fragment.bytes=std::move(bytes); fragment.size=input.payload.size(); fragment.present=true;
            ++selected->received; selected->bytes+=input.payload.size(); buffered_+=input.payload.size();
            if (selected->received!=selected->count) return ReassemblyStatus::incomplete;
            auto& ready=next_ready();std::size_t offset=0;
            for (std::size_t i=0;i<selected->count;++i) {
                auto const& part=selected->fragments[i];
                if (part.size) std::copy_n(part.bytes.get(),part.size,ready_bytes(ready_slots_.tail())+offset);
                offset+=part.size;
            }
            std::copy_n(selected->address.begin(),selected->address_size,ready.address.begin());ready.address_size=selected->address_size;
            ready.owner=selected->owner;ready.session=selected->session;ready.size=offset;ready_slots_.commit();
            clear(*selected); return ReassemblyStatus::accepted;
        }
        auto packet(UdpClock::time_point now) const noexcept -> std::optional<ReassembledPacket> {
            if (ready_slots_.empty() || (observed_ && now<*observed_)) return {};
            auto const& ready=ready_[ready_slots_.front()];if(!sessions_.live(ready.owner,now))return {};
            return ReassembledPacket{ready.owner,ready.session,{ready.address.data(),ready.address_size},{ready_bytes(ready_slots_.front()),ready.size}};
        }
        auto consume() noexcept -> bool {
            if (ready_slots_.empty()) return false;
            discard_ready();return true;
        }
        auto close() noexcept -> void {
            for (auto& packet:packets_) clear(packet);
            ready_slots_.reset();release_extra();closed_=true;
        }
        auto buffered_bytes() const noexcept -> std::size_t { return buffered_; }
        auto pending_packets() const noexcept -> std::size_t { return active_; }
        auto expiry() const noexcept -> std::optional<UdpClock::time_point> {
            std::optional<UdpClock::time_point> result;
            for(auto const& packet:packets_)if(packet.active){
                auto duration=packet.discarded ? lifetime_*2 : lifetime_;
                auto value=packet.started>UdpClock::time_point::max()-duration ? UdpClock::time_point::max() : packet.started+duration;
                if(!result || value<*result)result=value;
            }return result;
        }
    };
}

