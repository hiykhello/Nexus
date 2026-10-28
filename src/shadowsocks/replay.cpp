module nexus.shadowsocks.replay;
import std;
namespace nexus::shadowsocks {
    auto ReplayTable::admit(std::span<std::uint8_t const> salt, std::chrono::steady_clock::time_point now, std::uint64_t wall_seconds)
        -> std::expected<void,ReplayError> {
        if (salt.size()!=16 && salt.size()!=32) return std::unexpected(ReplayError::invalid_salt);
        std::lock_guard lock(mutex_);
        return admit_locked(salt,now,wall_seconds);
    }
    auto ReplayTable::admit_current(std::span<std::uint8_t const> salt, std::uint64_t timestamp)
        -> std::expected<void,ReplayError> {
        if (salt.size()!=16 && salt.size()!=32) return std::unexpected(ReplayError::invalid_salt);
        std::lock_guard lock(mutex_);
        auto now=std::chrono::steady_clock::now();
        auto wall=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        if (wall<0) return std::unexpected(ReplayError::time_reversed);
        auto seconds=static_cast<std::uint64_t>(wall);
        if ((timestamp>seconds ? timestamp-seconds : seconds-timestamp)>30)
            return std::unexpected(ReplayError::invalid_timestamp);
        return admit_locked(salt,now,seconds);
    }
    auto ReplayTable::admit_locked(std::span<std::uint8_t const> salt, std::chrono::steady_clock::time_point now, std::uint64_t wall_seconds)
        -> std::expected<void,ReplayError> {
        if (last_ && now<*last_) return std::unexpected(ReplayError::time_reversed);
        if (last_) {
            auto elapsed=std::chrono::duration_cast<std::chrono::seconds>(now-anchor_mono_).count();
            if (wall_seconds<anchor_wall_) return std::unexpected(ReplayError::time_reversed);
            auto wall_delta=wall_seconds-anchor_wall_;
            auto elapsed_seconds=static_cast<std::uint64_t>(elapsed);
            // One second accounts for the phase of the whole-second wall clock.
            if (elapsed_seconds>wall_delta && elapsed_seconds-wall_delta>1)
                return std::unexpected(ReplayError::time_reversed);
            if (wall_delta>elapsed_seconds) { anchor_wall_=wall_seconds; anchor_mono_=now; }
        } else { anchor_wall_=wall_seconds; anchor_mono_=now; }
        // Inclusive wire timestamp window and one-second clock sampling tolerance.
        while (!entries_.empty() && now-entries_.front().admitted>=std::chrono::seconds(62)) {
            index_.erase(entries_.front().salt);
            entries_.pop_front();
        }
        last_=now;
        Salt key; std::ranges::copy(salt,key.bytes.begin()); key.size=salt.size();
        if (index_.contains(key)) return std::unexpected(ReplayError::duplicate);
        if (entries_.size()>=capacity_) return std::unexpected(ReplayError::full);
        auto [position,inserted]=index_.insert(key);
        try { entries_.push_back({key,now}); }
        catch (...) { if (inserted) index_.erase(position); throw; }
        return {};
    }
    auto ReplayTable::size() const -> std::size_t {
        std::lock_guard lock(mutex_);
        return entries_.size();
    }
}
