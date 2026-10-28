module nexus.tcp.engine;
import std;

namespace nexus::tcp {
    MemoryEngine::~MemoryEngine() {
        if (pending_reset_ && pending_id_) (void)table_.hold_reset(*pending_id_, false);
    }
    auto MemoryEngine::flush(EngineStep& report) -> void {
        auto* flow = table_.get(*pending_id_);
        if (!flow || (flow->state() == ConnectionState::reset && !pending_reset_) || flow->state() == ConnectionState::expired) {
            pending_.reset(); pending_id_.reset(); pending_reset_ = false; report.stale_reply = true; return;
        }
        std::expected<void, packet::DeviceError> sent;
        try { sent = link_.send(packet::Side::second, *pending_); }
        catch (std::bad_alloc const&) { report.backpressured = true; return; }
        if (sent) {
            if (pending_reset_) (void)table_.hold_reset(*pending_id_, false);
            pending_.reset(); pending_id_.reset(); pending_reset_ = false; report.delivered = true; return;
        }
        if (sent.error() == packet::DeviceError::queue_full) { report.backpressured = true; return; }
        report.output_error = sent.error();
        if (sent.error() == packet::DeviceError::packet_too_large) {
            if (pending_reset_) (void)table_.hold_reset(*pending_id_, false);
            pending_.reset(); pending_id_.reset(); pending_reset_ = false;
        }
    }
    auto MemoryEngine::step(std::uint64_t now, std::uint32_t iss)
        -> std::expected<EngineStep, std::variant<EngineError, packet::DeviceError>> {
        if (initialized_ && now < now_) return std::unexpected(std::variant<EngineError, packet::DeviceError>{EngineError::time_reversed});
        initialized_ = true; now_ = now;
        EngineStep report;
        if (pending_) { flush(report); return report; }
        if (!incoming_) {
            auto incoming = link_.receive(packet::Side::second);
            if (!incoming) return std::unexpected(std::variant<EngineError, packet::DeviceError>{incoming.error()});
            if (!*incoming) return report;
            incoming_ = std::move(**incoming); incoming_iss_ = iss;
        }
        report.input = true;
        auto result = dispatch_routed(table_, policy_, *incoming_, incoming_iss_, now, mtu_);
        incoming_.reset();
        if (!result) { report.rejected = result.error(); return report; }
        report.id = result->id; report.opened = result->opened; report.input_error = result->input_error;
        if (result->reply) {
            pending_ = std::move(*result->reply); pending_id_ = result->id;
            try { flush(report); }
            catch (...) {
                if (result->opened) {
                    (void)table_.abort(result->id);
                    pending_.reset(); pending_id_.reset(); pending_reset_ = false;
                }
                throw;
            }
        }
        return report;
    }
    auto MemoryEngine::transmit(ConnectionId id, std::uint64_t now) -> std::expected<TransmitResult, EngineError> {
        if (initialized_ && now < now_) return std::unexpected(EngineError::time_reversed);
        initialized_ = true; now_ = now;
        auto* flow = table_.get(id);
        if (!flow) return std::unexpected(EngineError::unknown_flow);
        if (mtu_ <= 40) return std::unexpected(EngineError::invalid_mtu);
        TransmitResult result;
        if (pending_) { result.backpressured = true; return result; }
        auto time = flow->send_due(now, 0);
        if (!time) { result.connection_error = time.error(); return result; }
        auto slice = flow->unsent(std::min<std::size_t>(mtu_ - 40, 65535 - 40));
        if (slice.bytes.empty()) return result;
        return emit(*flow, slice, now, Action::data);
    }
    auto MemoryEngine::retransmit(ConnectionId id, std::uint64_t now) -> std::expected<TransmitResult, EngineError> {
        if (initialized_ && now < now_) return std::unexpected(EngineError::time_reversed);
        initialized_ = true; now_ = now;
        auto* flow = table_.get(id);
        if (!flow) return std::unexpected(EngineError::unknown_flow);
        if (mtu_ <= 40) return std::unexpected(EngineError::invalid_mtu);
        TransmitResult result;
        if (pending_) { result.backpressured = true; return result; }
        auto due = flow->send_due(now, std::min<std::size_t>(mtu_ - 40, 65535 - 40));
        if (!due) { result.connection_error = due.error(); return result; }
        if (!*due) return result;
        return emit(*flow, **due, now, Action::retransmit);
    }
    auto MemoryEngine::probe(ConnectionId id, std::uint64_t now) -> std::expected<TransmitResult, EngineError> {
        if (initialized_ && now < now_) return std::unexpected(EngineError::time_reversed);
        initialized_ = true; now_ = now;
        auto* flow = table_.get(id);
        if (!flow) return std::unexpected(EngineError::unknown_flow);
        if (mtu_ < 40) return std::unexpected(EngineError::invalid_mtu);
        TransmitResult result;
        if (pending_) { result.backpressured = true; return result; }
        auto due = flow->probe_due(now);
        if (!due) { result.connection_error = due.error(); return result; }
        if (!*due) return result;
        return emit(*flow, **due, now, Action::probe);
    }
    auto MemoryEngine::send_fin(ConnectionId id, std::uint64_t now, bool retry) -> std::expected<TransmitResult, EngineError> {
        if (initialized_ && now < now_) return std::unexpected(EngineError::time_reversed);
        initialized_ = true; now_ = now;
        auto* flow = table_.get(id);
        if (!flow) return std::unexpected(EngineError::unknown_flow);
        if (mtu_ < 40) return std::unexpected(EngineError::invalid_mtu);
        TransmitResult result;
        if (pending_) { result.backpressured = true; return result; }
        if (retry) {
            auto due = flow->fin_due(now);
            if (!due) { result.connection_error = due.error(); return result; }
            if (!*due) return result;
        } else {
            auto time = flow->send_due(now, 0);
            if (!time) { result.connection_error = time.error(); return result; }
            if (!flow->fin_ready()) return result;
        }
        return emit(*flow, SendSlice{}, now, retry ? Action::fin_retry : Action::fin);
    }
    auto MemoryEngine::emit(PassiveConnection& flow, SendSlice const& slice, std::uint64_t now, Action action)
        -> std::expected<TransmitResult, EngineError> {
        TransmitResult result;
        auto view = action == Action::fin || action == Action::fin_retry ? flow.fin() : flow.ack();
        if (action != Action::fin && action != Action::fin_retry) { view.sequence = slice.sequence; view.payload = slice.bytes; }
        auto bytes = packet::make_tcp4(view, mtu_);
        if (!bytes) return std::unexpected(EngineError::invalid_mtu);
        auto sent = link_.send(packet::Side::second, *bytes);
        if (!sent) {
            if (sent.error() == packet::DeviceError::queue_full) result.backpressured = true;
            else result.output_error = sent.error();
            return result;
        }
        result.bytes = slice.bytes.size(); result.delivered = true;
        auto committed = [&]() -> std::expected<void, ConnectionError> {
            switch (action) {
                case Action::data: return flow.sent(result.bytes, now);
                case Action::retransmit: return flow.send_retransmitted(now);
                case Action::probe: return flow.probe_sent(now);
                case Action::fin: return flow.fin_sent(now);
                case Action::fin_retry: return flow.fin_retransmitted(now);
            }
            return std::unexpected(ConnectionError::unsupported);
        }();
        if (!committed) result.connection_error = committed.error();
        return result;
    }
}
