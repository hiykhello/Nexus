module tcp.engine;
import std;

namespace tcp {
    namespace {
        struct SynAckOptions {
            std::array<std::uint8_t, 12> bytes{};
            std::size_t length = 0;
            [[nodiscard]] auto span() const noexcept -> std::span<std::uint8_t const> { return {bytes.data(), length}; }
        };
        auto build_syn_ack_options(std::size_t mtu, std::size_t overhead, std::span<std::uint8_t const> existing) noexcept -> SynAckOptions {
            SynAckOptions out;
            auto mss = static_cast<std::uint16_t>(std::min<std::size_t>(mtu - overhead, 65535 - overhead));
            out.bytes[0] = 2; out.bytes[1] = 4;
            out.bytes[2] = static_cast<std::uint8_t>(mss >> 8); out.bytes[3] = static_cast<std::uint8_t>(mss);
            out.length = 4;
            auto extra = std::min(existing.size(), out.bytes.size() - out.length);
            extra -= extra % 4;
            std::copy_n(existing.data(), extra, out.bytes.data() + out.length);
            out.length += extra;
            return out;
        }
    }
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
            if (mtu_ < 44) return std::unexpected(EngineError::invalid_mtu);
            auto view = flow->syn_ack();
            auto options = build_syn_ack_options(mtu_, 40, view.options);
            view.options = options.span();
            auto bytes = packet::make_tcp4(view, mtu_);
            if (!bytes) return std::unexpected(EngineError::invalid_mtu);
            report.action = ServiceAction::syn_ack;
            auto sent = link_.send(packet::Side::second, *bytes, packet::PacketKind::ordinary, 0, watch(*bytes));
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
    auto MemoryEngine6::service(std::uint64_t now) -> std::expected<ServiceResult, EngineError> {
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
            if (mtu_ < 64) return std::unexpected(EngineError::invalid_mtu);
            auto view = flow->syn_ack();
            auto options = build_syn_ack_options(mtu_, 60, view.options);
            view.options = options.span();
            auto bytes = packet::make_tcp6(view, mtu_);
            if (!bytes) return std::unexpected(EngineError::invalid_mtu);
            report.action = ServiceAction::syn_ack;
            auto sent = link_.send(packet::Side::second, *bytes, packet::PacketKind::ordinary, 0, watch(*bytes));
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
