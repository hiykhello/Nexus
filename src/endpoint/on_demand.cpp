module endpoint.on_demand;
import std;

namespace endpoint::on_demand {
    namespace {
        [[nodiscard]] auto enqueue_if_room(Config const& cfg, std::uint32_t& queued, Stats& stats) noexcept -> bool {
            if (queued >= cfg.max_queued_packets) {
                ++stats.dropped_packets;
                return false;
            }
            ++queued;
            ++stats.queued_packets;
            return true;
        }
    }

    auto Controller::on_outbound_packet(std::int64_t now_ms, std::size_t packet_size) noexcept -> WakeAction {
        if (packet_size == 0) {
            ++stats_.dropped_packets;
            return WakeAction::dropped;
        }
        if (state_ == State::active) {
            last_activity_ms_ = now_ms;
            return WakeAction::pass;
        }
        if (state_ == State::cooldown) {
            auto const backoff_ms = std::chrono::duration_cast<std::chrono::milliseconds>(config_.wake_backoff).count();
            if (now_ms - state_entered_ms_ < backoff_ms) {
                ++stats_.dropped_packets;
                return WakeAction::dropped;
            }
            state_ = State::sleeping;
            state_entered_ms_ = now_ms;
        }
        if (state_ == State::sleeping) {
            if (!config_.wake_on_outbound) {
                ++stats_.dropped_packets;
                return WakeAction::dropped;
            }
            state_ = State::waking;
            state_entered_ms_ = now_ms;
            last_activity_ms_ = now_ms;
            ++stats_.wake_transitions;
            (void)enqueue_if_room(config_, queued_count_, stats_);
            return WakeAction::initiate_wake;
        }
        // waking: buffer up to max_queued_packets while tunnel negotiates
        last_activity_ms_ = now_ms;
        return enqueue_if_room(config_, queued_count_, stats_) ? WakeAction::queued : WakeAction::dropped;
    }

    auto Controller::on_inbound_packet(std::int64_t now_ms) noexcept -> void {
        if (state_ == State::active) {
            last_activity_ms_ = now_ms;
        }
    }

    auto Controller::on_tunnel_up(std::int64_t now_ms) noexcept -> std::uint32_t {
        state_ = State::active;
        state_entered_ms_ = now_ms;
        last_activity_ms_ = now_ms;
        auto drained = queued_count_;
        queued_count_ = 0;
        return drained;
    }

    auto Controller::on_tunnel_down(std::int64_t now_ms, bool error) noexcept -> void {
        queued_count_ = 0;
        state_ = error ? State::cooldown : State::sleeping;
        state_entered_ms_ = now_ms;
        if (!error) ++stats_.sleep_transitions;
    }

    auto Controller::on_keepalive(std::int64_t now_ms) noexcept -> void {
        if (config_.keepalive_prevents_sleep && state_ == State::active) {
            last_activity_ms_ = now_ms;
        }
    }

    auto Controller::tick(std::int64_t now_ms) noexcept -> State {
        if (state_ == State::active && config_.idle_timeout.count() > 0) {
            auto const idle_ms = std::chrono::duration_cast<std::chrono::milliseconds>(config_.idle_timeout).count();
            if (now_ms - last_activity_ms_ >= idle_ms) {
                state_ = State::sleeping;
                state_entered_ms_ = now_ms;
                ++stats_.sleep_transitions;
            }
        } else if (state_ == State::cooldown) {
            auto const backoff_ms = std::chrono::duration_cast<std::chrono::milliseconds>(config_.wake_backoff).count();
            if (now_ms - state_entered_ms_ >= backoff_ms) {
                state_ = State::sleeping;
                state_entered_ms_ = now_ms;
            }
        }
        return state_;
    }
}
