module nexus.tcp.engine;
import std;

namespace nexus::tcp {
    auto MemoryEngine::service(std::uint64_t now) -> std::expected<ServiceResult, EngineError> {
        if (initialized_ && now < now_) return std::unexpected(EngineError::time_reversed);
        initialized_ = true; now_ = now;
        ServiceResult report;
        if (pending_) { report.output.backpressured = true; return report; }
        auto id = table_.next(cursor_);
        if (!id) return report;
        cursor_ = *id; report.id = *id;
        auto* flow = table_.get(*id);
        if (flow->state() == ConnectionState::handshake) {
            auto event = flow->poll(now);
            if (!event) { report.output.connection_error = event.error(); return report; }
            if (*event == HandshakeTimerEvent::waiting) return report;
            if (*event == HandshakeTimerEvent::expired) {
                auto reaped = table_.reclaim(*id, now);
                if (!reaped) report.table_error = reaped.error();
                else if (*reaped) report.action = ServiceAction::reclaimed;
                return report;
            }
            if (mtu_ < 40) return std::unexpected(EngineError::invalid_mtu);
            auto bytes = packet::make_tcp4(flow->syn_ack(), mtu_);
            if (!bytes) return std::unexpected(EngineError::invalid_mtu);
            report.action = ServiceAction::syn_ack;
            auto sent = link_.send(packet::Side::second, *bytes);
            if (!sent) {
                if (sent.error() == packet::DeviceError::queue_full) report.output.backpressured = true;
                else report.output.output_error = sent.error();
                return report;
            }
            report.output.delivered = true;
            auto committed = flow->retransmitted(now);
            if (!committed) report.output.connection_error = committed.error();
            return report;
        }
        auto reaped = table_.reclaim(*id, now);
        if (!reaped) { report.table_error = reaped.error(); return report; }
        if (*reaped) { report.action = ServiceAction::reclaimed; return report; }
        auto attempt = [&](ServiceAction action, std::expected<TransmitResult, EngineError> result)
            -> std::expected<bool, EngineError> {
            if (!result) return std::unexpected(result.error());
            if (!result->delivered && !result->backpressured && !result->output_error && !result->connection_error) return false;
            report.action = action; report.output = std::move(*result); return true;
        };
        auto done = attempt(ServiceAction::retransmit, retransmit(*id, now));
        if (!done) return std::unexpected(done.error());
        if (*done) return report;
        done = attempt(ServiceAction::probe, probe(*id, now));
        if (!done) return std::unexpected(done.error());
        if (*done) return report;
        if (flow->fin_ready() || flow->fin_pending()) {
            bool retry = flow->fin_pending();
            done = attempt(retry ? ServiceAction::fin_retry : ServiceAction::fin, send_fin(*id, now, retry));
            if (!done) return std::unexpected(done.error());
            if (*done) return report;
        }
        done = attempt(ServiceAction::data, transmit(*id, now));
        if (!done) return std::unexpected(done.error());
        return report;
    }
}
