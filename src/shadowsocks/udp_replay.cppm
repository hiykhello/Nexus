export module shadowsocks.udp_replay;
import std;

export namespace shadowsocks {
    enum class UdpReplayResult { fresh, duplicate, too_old };

    // Logical state, not a disk format. Bit d records highest - d.
    struct UdpReplaySnapshot {
        bool initialized=false;
        std::uint64_t highest=0;
        std::array<std::uint64_t,16> seen{};
        auto operator==(UdpReplaySnapshot const&) const -> bool = default;
    };

    // One owner serializes access. Each instance belongs to exactly one peer
    // session ID and direction. Packet IDs never wrap within a session.
    class UdpReplayWindow {
        static constexpr std::size_t width_=1024;
        std::bitset<width_> seen_;
        std::uint64_t highest_=0;
        bool initialized_=false;
    public:
        static constexpr std::size_t width=width_;
        class Proposal {
            friend class UdpReplayWindow;
            UdpReplayWindow const* owner_;
            UdpReplaySnapshot before_;
            UdpReplaySnapshot after_;
            std::uint64_t packet_id_;
            Proposal(UdpReplayWindow const* owner, UdpReplaySnapshot before,
                UdpReplaySnapshot after, std::uint64_t packet_id) noexcept
                : owner_(owner), before_(before), after_(after), packet_id_(packet_id) {}
        public:
            [[nodiscard]] auto next_state() const noexcept -> UdpReplaySnapshot const& { return after_; }
        };
        UdpReplayWindow() = default;
        UdpReplayWindow(UdpReplayWindow const&) = delete;
        auto operator=(UdpReplayWindow const&) -> UdpReplayWindow& = delete;
        UdpReplayWindow(UdpReplayWindow&&) = delete;
        auto operator=(UdpReplayWindow&&) -> UdpReplayWindow& = delete;

        [[nodiscard]] auto snapshot() const noexcept -> UdpReplaySnapshot;
        // Restore only into a fresh owner. Invalid or noncanonical states leave
        // it unchanged; callers must authenticate and trust the source state.
        [[nodiscard]] auto restore(UdpReplaySnapshot const& state) noexcept -> bool;

        // Speculative check does not modify state. Authentication, timestamp,
        // session and semantic checks must succeed before commit is called.
        [[nodiscard]] auto check(std::uint64_t packet_id) const noexcept -> UdpReplayResult;
        // Rechecks against the current state, so delayed validation cannot
        // authorize the same ID twice or revive a now-expired packet.
        [[nodiscard]] auto commit(std::uint64_t packet_id) noexcept -> UdpReplayResult;
        // Prepare without mutating the live window. The serialized owner must
        // not process another transition while its durable write is pending.
        // A proposal is valid only during the originating owner's lifetime.
        [[nodiscard]] auto prepare(std::uint64_t packet_id) const noexcept
            -> std::expected<Proposal,UdpReplayResult>;
        // Apply only after durable commit. A stale or foreign proposal fails
        // without mutation. If a write is ambiguous or apply fails after a
        // write, stop the owner and reconcile before accepting further packets.
        [[nodiscard]] auto apply(Proposal const& proposal) noexcept -> bool;
    };

    // Version 1: version, initialized flag, highest ID, then 16 bitmap words;
    // all integers are unsigned big endian. This is a logical encoding, not
    // authentication, rollback protection, or a complete storage format.
    inline constexpr std::size_t udp_replay_encoded_size=138;
    [[nodiscard]] auto encode_udp_replay(UdpReplaySnapshot const& snapshot) noexcept
        -> std::optional<std::array<std::uint8_t,udp_replay_encoded_size>>;
    [[nodiscard]] auto decode_udp_replay(std::span<std::uint8_t const> bytes) noexcept
        -> std::optional<UdpReplaySnapshot>;
}

module :private;

namespace shadowsocks {
    auto UdpReplayWindow::snapshot() const noexcept -> UdpReplaySnapshot {
        UdpReplaySnapshot result{initialized_,highest_,{}};
        for (std::size_t i=0;i<width_;++i)
            if (seen_[i]) result.seen[i/64] |= std::uint64_t{1} << (i%64);
        return result;
    }
    auto UdpReplayWindow::restore(UdpReplaySnapshot const& state) noexcept -> bool {
        if (initialized_) return false;
        if (!state.initialized) {
            return state.highest==0 && std::ranges::all_of(state.seen,[](auto word) { return word==0; });
        }
        if (!(state.seen[0] & 1)) return false;
        if (state.highest < width_-1) {
            for (std::size_t i=static_cast<std::size_t>(state.highest)+1;i<width_;++i)
                if (state.seen[i/64] & (std::uint64_t{1} << (i%64))) return false;
        }
        for (std::size_t i=0;i<width_;++i)
            if (state.seen[i/64] & (std::uint64_t{1} << (i%64))) seen_.set(i);
        highest_=state.highest; initialized_=true;
        return true;
    }
    auto UdpReplayWindow::check(std::uint64_t packet_id) const noexcept -> UdpReplayResult {
        if (!initialized_ || packet_id>highest_) return UdpReplayResult::fresh;
        auto distance=highest_-packet_id;
        if (distance>=width_) return UdpReplayResult::too_old;
        return seen_[static_cast<std::size_t>(distance)] ? UdpReplayResult::duplicate : UdpReplayResult::fresh;
    }
    auto UdpReplayWindow::commit(std::uint64_t packet_id) noexcept -> UdpReplayResult {
        auto result=check(packet_id);
        if (result!=UdpReplayResult::fresh) return result;
        if (!initialized_) {
            initialized_=true; highest_=packet_id; seen_.set(0);
        } else if (packet_id>highest_) {
            auto distance=packet_id-highest_;
            if (distance>=width_) seen_.reset();
            else seen_ <<= static_cast<std::size_t>(distance);
            highest_=packet_id; seen_.set(0);
        } else seen_.set(static_cast<std::size_t>(highest_-packet_id));
        return UdpReplayResult::fresh;
    }
    auto UdpReplayWindow::prepare(std::uint64_t packet_id) const noexcept
        -> std::expected<Proposal,UdpReplayResult> {
        auto result=check(packet_id);
        if (result!=UdpReplayResult::fresh) return std::unexpected(result);
        auto before=snapshot();
        UdpReplayWindow candidate;
        (void)candidate.restore(before);
        (void)candidate.commit(packet_id);
        return Proposal(this,before,candidate.snapshot(),packet_id);
    }
    auto UdpReplayWindow::apply(Proposal const& proposal) noexcept -> bool {
        if (proposal.owner_!=this || snapshot()!=proposal.before_) return false;
        return commit(proposal.packet_id_)==UdpReplayResult::fresh;
    }
    auto encode_udp_replay(UdpReplaySnapshot const& snapshot) noexcept
        -> std::optional<std::array<std::uint8_t,udp_replay_encoded_size>> {
        UdpReplayWindow check;
        if (!check.restore(snapshot)) return {};
        std::array<std::uint8_t,udp_replay_encoded_size> bytes{};
        bytes[0]=1; bytes[1]=snapshot.initialized ? 1 : 0;
        auto put=[&](std::size_t offset,std::uint64_t value) {
            for (std::size_t i=0;i<8;++i) bytes[offset+i]=static_cast<std::uint8_t>(value>>(56-8*i));
        };
        put(2,snapshot.highest);
        for (std::size_t i=0;i<snapshot.seen.size();++i) put(10+8*i,snapshot.seen[i]);
        return bytes;
    }
    auto decode_udp_replay(std::span<std::uint8_t const> bytes) noexcept
        -> std::optional<UdpReplaySnapshot> {
        if (bytes.size()!=udp_replay_encoded_size || bytes[0]!=1 || bytes[1]>1) return {};
        auto get=[&](std::size_t offset) {
            std::uint64_t result=0;
            for (std::size_t i=0;i<8;++i) result=(result<<8)|bytes[offset+i];
            return result;
        };
        UdpReplaySnapshot snapshot{bytes[1]!=0,get(2),{}};
        for (std::size_t i=0;i<snapshot.seen.size();++i) snapshot.seen[i]=get(10+8*i);
        UdpReplayWindow check;
        if (!check.restore(snapshot)) return {};
        return snapshot;
    }
}
