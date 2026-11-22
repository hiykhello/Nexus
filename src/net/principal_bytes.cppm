export module net.principal_bytes;
import std;

export namespace net {
    // A shared budget for both directions of one authenticated principal.
    class PrincipalBytes {
        using Clock=std::chrono::steady_clock;
        struct State;
        std::shared_ptr<State> state_;
    public:
        struct Limits {
            std::optional<std::uint64_t> quota;
            std::uint32_t bytes_per_second=0;
            std::uint32_t burst=0;
        };
        struct Usage {
            std::uint64_t uploaded,downloaded,unconfirmed,denied;
        };
        class Reservation {
            friend PrincipalBytes;
            std::shared_ptr<State> state_;
            std::size_t bytes_=0;
            bool upstream_=false;
            bool submitted_=false;
            std::optional<std::uint64_t> rate_epoch_;
            Reservation(std::shared_ptr<State>,std::size_t,bool,std::optional<std::uint64_t>) noexcept;
            auto settle(std::size_t delivered,std::size_t charged) noexcept -> void;
        public:
            Reservation() noexcept=default;
            Reservation(Reservation const&)=delete;
            auto operator=(Reservation const&) -> Reservation& =delete;
            Reservation(Reservation&&) noexcept=default;
            auto operator=(Reservation&& other) noexcept -> Reservation&;
            ~Reservation();
            [[nodiscard]] auto size() const noexcept -> std::size_t {return bytes_;}
            auto submit() noexcept -> void {submitted_=true;}
            // Commit the number accepted by the I/O operation. Unused credit
            // is returned even when a task is canceled before the write.
            auto complete(std::size_t delivered) noexcept -> void;
        };
        enum class Denial { quota, pending, rate, size };
        struct Wait {
            Denial reason;
            Clock::time_point retry=Clock::time_point::max();
        };
        PrincipalBytes();
        auto publish(Limits,Clock::time_point now) noexcept -> void;
        [[nodiscard]] auto metered() const noexcept -> bool;
        [[nodiscard]] auto reserve(bool upstream,std::size_t wanted,bool whole_packet,Clock::time_point now) const
            -> std::expected<Reservation,Wait>;
        [[nodiscard]] auto reserve_datagram(bool upstream,std::size_t size,Clock::time_point now) const
            -> std::optional<Reservation>;
        [[nodiscard]] auto usage() const noexcept -> Usage;
    };
}

module :private;

namespace net {
    constexpr std::uint64_t byte_credit=1'000'000'000;
    auto saturated_add(std::uint64_t left,std::uint64_t right) noexcept -> std::uint64_t {
        return left+std::min(right,std::numeric_limits<std::uint64_t>::max()-left);
    }

    struct PrincipalBytes::State {
        mutable std::mutex mutex;
        Limits limits;
        std::atomic_bool metered=false;
        std::uint64_t uploaded=0,downloaded=0,unconfirmed=0,held=0,denied=0,credit=0,rate_epoch=0;
        Clock::time_point sampled{};
        auto refill(Clock::time_point now) noexcept -> void {
            if (now<=sampled) return;
            if (auto rate=limits.bytes_per_second) {
                auto cap=byte_credit*limits.burst;
                auto room=cap-credit;
                auto ticks=static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::nanoseconds>(now-sampled).count());
                credit+=std::min(ticks,room/rate)*rate;
                if (ticks>room/rate) credit=cap;
            }
            sampled=now;
        }
    };

    PrincipalBytes::PrincipalBytes() : state_(std::make_shared<State>()) {}
    auto PrincipalBytes::publish(Limits limits,Clock::time_point now) noexcept -> void {
        auto& state=*state_;
        std::lock_guard lock(state.mutex);
        state.refill(now);
        auto cap=byte_credit*limits.burst;
        if (bool(limits.bytes_per_second)!=bool(state.limits.bytes_per_second)) ++state.rate_epoch;
        if (!limits.bytes_per_second) state.credit=0;
        else if (!state.limits.bytes_per_second) state.credit=cap;
        else state.credit=std::min(state.credit,cap);
        state.limits=limits;
        if (limits.bytes_per_second || limits.quota) state.metered.store(true,std::memory_order_release);
    }

    PrincipalBytes::Reservation::Reservation(std::shared_ptr<State> state,std::size_t bytes,bool upstream,
        std::optional<std::uint64_t> rate_epoch) noexcept
        : state_(std::move(state)),bytes_(bytes),upstream_(upstream),rate_epoch_(rate_epoch) {}
    PrincipalBytes::Reservation::~Reservation() {settle(0,submitted_ ? bytes_ : 0);}
    auto PrincipalBytes::Reservation::operator=(Reservation&& other) noexcept -> Reservation& {
        if (this==&other) return *this;
        settle(0,submitted_ ? bytes_ : 0);
        state_=std::move(other.state_);
        bytes_=other.bytes_;
        upstream_=other.upstream_;
        submitted_=other.submitted_;
        rate_epoch_=other.rate_epoch_;
        return *this;
    }
    auto PrincipalBytes::Reservation::complete(std::size_t delivered) noexcept -> void {
        delivered=std::min(delivered,bytes_);
        settle(delivered,delivered);
    }
    auto PrincipalBytes::Reservation::settle(std::size_t delivered,std::size_t charged) noexcept -> void {
        if (!state_) return;
        {
            std::lock_guard lock(state_->mutex);
            auto& state=*state_;
            auto& direction=upstream_ ? state.uploaded : state.downloaded;
            direction=saturated_add(direction,delivered);
            state.unconfirmed=saturated_add(state.unconfirmed,charged-delivered);
            state.held-=bytes_;
            if (state.limits.bytes_per_second && rate_epoch_==state.rate_epoch) {
                auto cap=byte_credit*state.limits.burst;
                auto refund=std::min<std::uint64_t>(bytes_-charged,state.limits.burst)*byte_credit;
                state.credit+=std::min(cap-state.credit,refund);
            }
        }
        state_.reset();
    }

    auto PrincipalBytes::metered() const noexcept -> bool {
        return state_->metered.load(std::memory_order_acquire);
    }
    auto PrincipalBytes::reserve(bool upstream,std::size_t wanted,bool whole_packet,Clock::time_point now) const
        -> std::expected<Reservation,Wait> {
        auto& state=*state_;
        std::lock_guard lock(state.mutex);
        state.refill(now);
        auto deny=[&](Denial reason,Clock::time_point retry=Clock::time_point::max()) {
            state.denied=saturated_add(state.denied,1);
            return std::unexpected(Wait{reason,retry});
        };
        auto used=saturated_add(state.unconfirmed,saturated_add(state.uploaded,state.downloaded));
        auto room=std::numeric_limits<std::uint64_t>::max()-state.held;
        if (state.limits.quota) {
            auto remaining=*state.limits.quota-std::min(*state.limits.quota,used);
            auto required=whole_packet ? wanted : std::min(wanted,std::size_t{1});
            if (required>remaining) return deny(Denial::quota);
            room=remaining-std::min(remaining,state.held);
            if (required>room) return deny(Denial::pending,now+std::chrono::milliseconds(5));
        }
        auto granted=std::min<std::uint64_t>(wanted,room);
        if (auto rate=state.limits.bytes_per_second;rate && wanted) {
            if (whole_packet && granted>state.limits.burst) return deny(Denial::size);
            auto available=state.credit/byte_credit;
            auto required=whole_packet ? granted : 1;
            if (available<required) {
                auto deficit=required*byte_credit-state.credit;
                auto wait=std::chrono::nanoseconds((deficit+rate-1)/rate);
                return deny(Denial::rate,state.sampled+wait);
            }
            granted=std::min(granted,available);
            state.credit-=granted*byte_credit;
        }
        state.held+=granted;
        auto epoch=state.limits.bytes_per_second ? std::optional(state.rate_epoch) : std::nullopt;
        return Reservation(state_,granted,upstream,epoch);
    }

    auto PrincipalBytes::reserve_datagram(bool upstream,std::size_t size,Clock::time_point now) const
        -> std::optional<Reservation> {
        if (!metered()) return std::optional<Reservation>(std::in_place);
        auto credit=reserve(upstream,size,true,now);
        if (!credit) return {};
        return std::optional<Reservation>(std::in_place,std::move(*credit));
    }

    auto PrincipalBytes::usage() const noexcept -> Usage {
        auto const& state=*state_;
        std::lock_guard lock(state.mutex);
        return {state.uploaded,state.downloaded,state.unconfirmed,state.denied};
    }
}
