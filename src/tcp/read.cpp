module tcp.engine;
import std;

namespace tcp {
    auto MemoryEngine::reset(ConnectionId id, std::uint64_t now) -> std::expected<ReadResult, EngineError> {
        if (initialized_ && now < now_) return std::unexpected(EngineError::time_reversed);
        initialized_ = true; now_ = now;
        auto* flow = table_.get(id);
        if (!flow) return std::unexpected(EngineError::unknown_flow);
        if (mtu_ < 40) return std::unexpected(EngineError::invalid_mtu);
        ReadResult result; result.notification.id = id;
        if (pending_) { result.notification.backpressured = true; return result; }
        auto view = flow->ack(0); view.flags = 0x14; view.options = {};
        auto packet = packet::make_tcp4(view, mtu_);
        if (!packet) return std::unexpected(EngineError::invalid_mtu);
        auto aborted = flow->abort(now);
        if (!aborted) { result.connection_error = aborted.error(); return result; }
        (void)table_.hold_reset(id, true);
        pending_ = std::move(*packet); pending_id_ = id; pending_reset_ = true;
        flush(result.notification);
        return result;
    }
    auto MemoryEngine::read(ConnectionId id, std::span<std::uint8_t> output, std::uint64_t now, bool observe_eof)
        -> std::expected<ReadResult, EngineError> {
        if (initialized_ && now < now_) return std::unexpected(EngineError::time_reversed);
        initialized_ = true; now_ = now;
        auto* flow = table_.get(id);
        if (!flow) return std::unexpected(EngineError::unknown_flow);
        if (mtu_ < 40) return std::unexpected(EngineError::invalid_mtu);
        ReadResult result;
        result.notification.id = id;
        if (pending_) { result.notification.backpressured = true; return result; }
        auto time = flow->send_due(now, 0);
        if (!time) { result.connection_error = time.error(); return result; }
        auto max_opts = mtu_ > 40 ? std::min<std::size_t>(28, mtu_ - 40) : 0;
        auto previous = flow->ack(0).window;
        auto after = flow->ack_after_read(output.size(), max_opts);
        std::optional<packet::Bytes> update;
        if (after.window > previous) {
            auto packet = packet::make_tcp4(after, mtu_);
            if (!packet) return std::unexpected(EngineError::invalid_mtu);
            update = std::move(*packet);
        }
        result.bytes = flow->read(output);
        result.eof = flow->eof();
        if (result.eof && observe_eof) (void)table_.observe_eof(id);
        if (update) {
            pending_ = std::move(*update); pending_id_ = id;
            flush(result.notification);
        }
        return result;
    }
    auto MemoryEngine6::reset(ConnectionId id, std::uint64_t now) -> std::expected<ReadResult, EngineError> {
        if (initialized_ && now < now_) return std::unexpected(EngineError::time_reversed);
        initialized_ = true; now_ = now;
        auto* flow = table_.get(id);
        if (!flow) return std::unexpected(EngineError::unknown_flow);
        if (mtu_ < 60) return std::unexpected(EngineError::invalid_mtu);
        ReadResult result; result.notification.id = id;
        if (pending_) { result.notification.backpressured = true; return result; }
        auto view = flow->ack(0); view.flags = 0x14; view.options = {};
        auto packet = packet::make_tcp6(view, mtu_);
        if (!packet) return std::unexpected(EngineError::invalid_mtu);
        auto aborted = flow->abort(now);
        if (!aborted) { result.connection_error = aborted.error(); return result; }
        (void)table_.hold_reset(id, true);
        pending_ = std::move(*packet); pending_id_ = id; pending_reset_ = true;
        flush(result.notification);
        return result;
    }
    auto MemoryEngine6::read(ConnectionId id, std::span<std::uint8_t> output, std::uint64_t now, bool observe_eof)
        -> std::expected<ReadResult, EngineError> {
        if (initialized_ && now < now_) return std::unexpected(EngineError::time_reversed);
        initialized_ = true; now_ = now;
        auto* flow = table_.get(id);
        if (!flow) return std::unexpected(EngineError::unknown_flow);
        if (mtu_ < 60) return std::unexpected(EngineError::invalid_mtu);
        ReadResult result;
        result.notification.id = id;
        if (pending_) { result.notification.backpressured = true; return result; }
        auto time = flow->send_due(now, 0);
        if (!time) { result.connection_error = time.error(); return result; }
        auto max_opts = mtu_ > 60 ? std::min<std::size_t>(28, mtu_ - 60) : 0;
        auto previous = flow->ack(0).window;
        auto after = flow->ack_after_read(output.size(), max_opts);
        std::optional<packet::Bytes> update;
        if (after.window > previous) {
            auto packet = packet::make_tcp6(after, mtu_);
            if (!packet) return std::unexpected(EngineError::invalid_mtu);
            update = std::move(*packet);
        }
        result.bytes = flow->read(output);
        result.eof = flow->eof();
        if (result.eof && observe_eof) (void)table_.observe_eof(id);
        if (update) {
            pending_ = std::move(*update); pending_id_ = id;
            flush(result.notification);
        }
        return result;
    }
}
