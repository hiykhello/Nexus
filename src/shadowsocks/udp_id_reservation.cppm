export module nexus.shadowsocks.udp_id_reservation;
import std;

export namespace nexus::shadowsocks {
    // The persistent high-water mark is an exclusive bound. Exhausted means
    // every ID including UINT64_MAX has been reserved; next must then be zero.
    struct UdpIdWatermark {
        std::uint64_t next=0;
        bool exhausted=false;
        auto operator==(UdpIdWatermark const&) const -> bool = default;
    };
    enum class UdpIdError { invalid_state, exhausted, storage, busy };

    // Experimental single-owner allocator. Recovery starts at the persisted
    // bound and deliberately skips any IDs left unused by the prior process.
    class UdpIdReservation {
        using Commit=std::function_ref<bool(UdpIdWatermark) noexcept>;
        UdpIdWatermark watermark_;
        std::uint64_t cursor_=0;
        std::uint64_t remaining_=0;
        std::uint64_t block_size_;
        bool failed_=false;
        bool committing_=false;
        UdpIdReservation(UdpIdWatermark state,std::uint64_t block_size) noexcept
            : watermark_(state), block_size_(block_size) {}
    public:
        UdpIdReservation(UdpIdReservation const&)=delete;
        auto operator=(UdpIdReservation const&) -> UdpIdReservation& = delete;
        UdpIdReservation(UdpIdReservation&&)=delete;
        auto operator=(UdpIdReservation&&) -> UdpIdReservation& = delete;

        // State must come from a trusted, rollback-protected store with an
        // exclusive owner for the PSK. This class cannot establish those facts.
        [[nodiscard]] static auto create(UdpIdWatermark state,std::uint64_t block_size)
            -> std::expected<std::unique_ptr<UdpIdReservation>,UdpIdError> {
            if (!block_size || (state.exhausted && state.next!=0)) return std::unexpected(UdpIdError::invalid_state);
            return std::unique_ptr<UdpIdReservation>(new UdpIdReservation(state,block_size));
        }
        // All values below the committed bound are reserved, including
        // unused values lost on restart. Initial allocation must start at 0.
        [[nodiscard]] auto reserved(std::uint64_t id) const noexcept -> bool {
            return watermark_.exhausted || id<watermark_.next;
        }
        // Persist the next bound before returning any ID. A failed or
        // ambiguous commit permanently closes this allocator. Never reenter.
        [[nodiscard]] auto take(Commit commit) noexcept -> std::expected<std::uint64_t,UdpIdError> {
            if (committing_) return std::unexpected(UdpIdError::busy);
            if (failed_) return std::unexpected(UdpIdError::storage);
            if (!remaining_) {
                if (watermark_.exhausted) return std::unexpected(UdpIdError::exhausted);
                auto start=watermark_.next;
                auto available=std::numeric_limits<std::uint64_t>::max()-start;
                auto final_block=block_size_-1>=available;
                auto count=final_block ? available+1 : block_size_;
                // available+1 cannot overflow here: final_block with start=0
                // would require a block size larger than uint64_t can hold.
                UdpIdWatermark next=final_block ? UdpIdWatermark{0,true} : UdpIdWatermark{start+count,false};
                committing_=true;
                auto written=commit(next);
                committing_=false;
                if (!written) { failed_=true; return std::unexpected(UdpIdError::storage); }
                watermark_=next; cursor_=start; remaining_=count;
            }
            auto id=cursor_;
            --remaining_;
            if (remaining_) ++cursor_;
            return id;
        }
    };
}
