module tcp.engine;
import std;

namespace tcp {
    auto MemoryEngine::watch(std::span<std::uint8_t const> bytes) -> std::shared_ptr<packet::TcpGeneration> {
        auto view=packet::parse_tcp4(bytes);
        if (!view) return {};
        std::swap(view->source,view->destination); std::swap(view->source_port,view->destination_port);
        return table_.watch(*view);
    }
    MemoryEngine::~MemoryEngine() {
        discard();
    }
    auto MemoryEngine::discard() noexcept -> void {
        if (pending_reset_ && pending_id_) (void)table_.hold_reset(*pending_id_, false);
        incoming_.reset(); pending_.reset(); pending_generation_.reset(); pending_id_.reset();
        pending_reset_=false; pending_reply_reset_=false;
    }
    auto MemoryEngine::flush(EngineStep& report) -> void {
        bool stale=pending_generation_ && !pending_generation_->valid;
        if (pending_id_) {
            auto* flow = table_.get(*pending_id_);
            stale = stale || !flow || (flow->state() == ConnectionState::reset && !pending_reset_) || flow->state() == ConnectionState::expired;
        } else {
            auto reverse=packet::parse_tcp4(*pending_);
            if (reverse) { std::swap(reverse->source,reverse->destination); std::swap(reverse->source_port,reverse->destination_port); stale=stale || table_.find(*reverse).has_value(); }
        }
        if (stale) { if (pending_id_) report.id = pending_id_; pending_.reset(); pending_generation_.reset(); pending_id_.reset(); pending_reset_ = false; pending_reply_reset_ = false; report.stale_reply = true; return; }
        std::expected<void, packet::DeviceError> sent;
        auto kind = !pending_id_ ? packet::PacketKind::stateless_tcp_reset :
                    (pending_reset_ || pending_reply_reset_) ? packet::PacketKind::stateful_tcp_reset : packet::PacketKind::ordinary;
        try {
            if (!pending_generation_) pending_generation_=watch(*pending_);
            sent = link_.send_owned(packet::Side::second, std::move(*pending_), kind, pending_id_.value_or(0), pending_generation_);
        }
        catch (std::bad_alloc const&) { report.backpressured = true; return; }
        if (sent) {
            if (pending_reset_) (void)table_.hold_reset(*pending_id_, false);
            if (pending_id_) report.id = pending_id_; pending_.reset(); pending_generation_.reset(); pending_id_.reset(); pending_reset_ = false; pending_reply_reset_ = false; report.delivered = true; return;
        }
        if (sent.error() == packet::DeviceError::queue_full) { report.backpressured = true; return; }
        report.output_error = sent.error();
        if (sent.error() == packet::DeviceError::packet_too_large) {
            if (pending_reset_) (void)table_.hold_reset(*pending_id_, false);
            pending_.reset(); pending_generation_.reset(); pending_id_.reset(); pending_reset_ = false; pending_reply_reset_ = false;
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
        if (result->id) report.id = result->id;
        report.opened = result->opened; report.input_error = result->input_error;
        report.challenge_suppressed = result->challenge_suppressed;
        report.reset_suppressed = result->reset_suppressed;
        if (result->reply) {
            pending_ = std::move(*result->reply); pending_id_ = result->id ? std::optional{result->id} : std::nullopt;
            pending_reply_reset_ = result->reply_reset;
            try { flush(report); }
            catch (...) {
                if (result->opened) {
                    (void)table_.abort(result->id);
                    pending_.reset(); pending_generation_.reset(); pending_id_.reset(); pending_reset_ = false; pending_reply_reset_ = false;
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
        auto max_opts = std::min<std::size_t>(28, mtu_ - 41);
        auto opt_len = flow->ack(max_opts).options.size();
        auto slice = flow->unsent(std::min<std::size_t>(mtu_ - 40 - opt_len, 65535 - 40 - opt_len));
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
        auto max_opts = std::min<std::size_t>(28, mtu_ - 41);
        auto opt_len = flow->ack(max_opts).options.size();
        auto due = flow->send_due(now, std::min<std::size_t>(mtu_ - 40 - opt_len, 65535 - 40 - opt_len));
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
        bool is_fin = action == Action::fin || action == Action::fin_retry;
        auto payload_len = is_fin ? std::size_t{0} : slice.bytes.size();
        auto max_opts = mtu_ > 40 + payload_len ? std::min<std::size_t>(28, mtu_ - 40 - payload_len) : 0;
        auto view = is_fin ? flow.fin(max_opts) : flow.ack(max_opts);
        if (!is_fin) { view.sequence = slice.sequence; view.payload = slice.bytes; }
        auto bytes = packet::make_tcp4(view, mtu_);
        if (!bytes) return std::unexpected(EngineError::invalid_mtu);
        auto rev = view;
        std::swap(rev.source, rev.destination);
        std::swap(rev.source_port, rev.destination_port);
        auto gen = table_.watch(rev);
        auto sent = link_.send_owned(packet::Side::second, std::move(*bytes), packet::PacketKind::ordinary, 0, std::move(gen));
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
    auto MemoryEngine6::watch(std::span<std::uint8_t const> bytes) -> std::shared_ptr<packet::TcpGeneration> {
        auto view=packet::parse_tcp6(bytes);
        if (!view) return {};
        std::swap(view->source,view->destination); std::swap(view->source_port,view->destination_port);
        return table_.watch(*view);
    }
    MemoryEngine6::~MemoryEngine6() {
        discard();
    }
    auto MemoryEngine6::discard() noexcept -> void {
        if (pending_reset_ && pending_id_) (void)table_.hold_reset(*pending_id_, false);
        incoming_.reset(); pending_.reset(); pending_generation_.reset(); pending_id_.reset();
        pending_reset_=false; pending_reply_reset_=false;
    }
    auto MemoryEngine6::flush(EngineStep& report) -> void {
        bool stale=pending_generation_ && !pending_generation_->valid;
        if (pending_id_) {
            auto* flow = table_.get(*pending_id_);
            stale = stale || !flow || (flow->state() == ConnectionState::reset && !pending_reset_) || flow->state() == ConnectionState::expired;
        } else {
            auto reverse=packet::parse_tcp6(*pending_);
            if (reverse) { std::swap(reverse->source,reverse->destination); std::swap(reverse->source_port,reverse->destination_port); stale=stale || table_.find(*reverse).has_value(); }
        }
        if (stale) { if (pending_id_) report.id = pending_id_; pending_.reset(); pending_generation_.reset(); pending_id_.reset(); pending_reset_ = false; pending_reply_reset_ = false; report.stale_reply = true; return; }
        std::expected<void, packet::DeviceError> sent;
        auto kind = !pending_id_ ? packet::PacketKind::stateless_tcp_reset :
                    (pending_reset_ || pending_reply_reset_) ? packet::PacketKind::stateful_tcp_reset : packet::PacketKind::ordinary;
        try {
            if (!pending_generation_) pending_generation_=watch(*pending_);
            sent = link_.send_owned(packet::Side::second, std::move(*pending_), kind, pending_id_.value_or(0), pending_generation_);
        }
        catch (std::bad_alloc const&) { report.backpressured = true; return; }
        if (sent) {
            if (pending_reset_) (void)table_.hold_reset(*pending_id_, false);
            if (pending_id_) report.id = pending_id_; pending_.reset(); pending_generation_.reset(); pending_id_.reset(); pending_reset_ = false; pending_reply_reset_ = false; report.delivered = true; return;
        }
        if (sent.error() == packet::DeviceError::queue_full) { report.backpressured = true; return; }
        report.output_error = sent.error();
        if (sent.error() == packet::DeviceError::packet_too_large) {
            if (pending_reset_) (void)table_.hold_reset(*pending_id_, false);
            pending_.reset(); pending_generation_.reset(); pending_id_.reset(); pending_reset_ = false; pending_reply_reset_ = false;
        }
    }
    auto MemoryEngine6::step(std::uint64_t now, std::uint32_t iss)
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
        if (result->id) report.id = result->id;
        report.opened = result->opened; report.input_error = result->input_error;
        report.challenge_suppressed = result->challenge_suppressed;
        report.reset_suppressed = result->reset_suppressed;
        if (result->reply) {
            pending_ = std::move(*result->reply); pending_id_ = result->id ? std::optional{result->id} : std::nullopt;
            pending_reply_reset_ = result->reply_reset;
            try { flush(report); }
            catch (...) {
                if (result->opened) {
                    (void)table_.abort(result->id);
                    pending_.reset(); pending_generation_.reset(); pending_id_.reset(); pending_reset_ = false; pending_reply_reset_ = false;
                }
                throw;
            }
        }
        return report;
    }
    auto MemoryEngine6::transmit(ConnectionId id, std::uint64_t now) -> std::expected<TransmitResult, EngineError> {
        if (initialized_ && now < now_) return std::unexpected(EngineError::time_reversed);
        initialized_ = true; now_ = now;
        auto* flow = table_.get(id);
        if (!flow) return std::unexpected(EngineError::unknown_flow);
        if (mtu_ <= 60) return std::unexpected(EngineError::invalid_mtu);
        TransmitResult result;
        if (pending_) { result.backpressured = true; return result; }
        auto time = flow->send_due(now, 0);
        if (!time) { result.connection_error = time.error(); return result; }
        auto max_opts = std::min<std::size_t>(28, mtu_ - 61);
        auto opt_len = flow->ack(max_opts).options.size();
        auto slice = flow->unsent(std::min<std::size_t>(mtu_ - 60 - opt_len, 65535 - 20 - opt_len));
        if (slice.bytes.empty()) return result;
        return emit(*flow, slice, now, Action::data);
    }
    auto MemoryEngine6::retransmit(ConnectionId id, std::uint64_t now) -> std::expected<TransmitResult, EngineError> {
        if (initialized_ && now < now_) return std::unexpected(EngineError::time_reversed);
        initialized_ = true; now_ = now;
        auto* flow = table_.get(id);
        if (!flow) return std::unexpected(EngineError::unknown_flow);
        if (mtu_ <= 60) return std::unexpected(EngineError::invalid_mtu);
        TransmitResult result;
        if (pending_) { result.backpressured = true; return result; }
        auto max_opts = std::min<std::size_t>(28, mtu_ - 61);
        auto opt_len = flow->ack(max_opts).options.size();
        auto due = flow->send_due(now, std::min<std::size_t>(mtu_ - 60 - opt_len, 65535 - 20 - opt_len));
        if (!due) { result.connection_error = due.error(); return result; }
        if (!*due) return result;
        return emit(*flow, **due, now, Action::retransmit);
    }
    auto MemoryEngine6::probe(ConnectionId id, std::uint64_t now) -> std::expected<TransmitResult, EngineError> {
        if (initialized_ && now < now_) return std::unexpected(EngineError::time_reversed);
        initialized_ = true; now_ = now;
        auto* flow = table_.get(id);
        if (!flow) return std::unexpected(EngineError::unknown_flow);
        if (mtu_ < 60) return std::unexpected(EngineError::invalid_mtu);
        TransmitResult result;
        if (pending_) { result.backpressured = true; return result; }
        auto due = flow->probe_due(now);
        if (!due) { result.connection_error = due.error(); return result; }
        if (!*due) return result;
        return emit(*flow, **due, now, Action::probe);
    }
    auto MemoryEngine6::send_fin(ConnectionId id, std::uint64_t now, bool retry) -> std::expected<TransmitResult, EngineError> {
        if (initialized_ && now < now_) return std::unexpected(EngineError::time_reversed);
        initialized_ = true; now_ = now;
        auto* flow = table_.get(id);
        if (!flow) return std::unexpected(EngineError::unknown_flow);
        if (mtu_ < 60) return std::unexpected(EngineError::invalid_mtu);
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
    auto MemoryEngine6::emit(PassiveConnection6& flow, SendSlice const& slice, std::uint64_t now, Action action)
        -> std::expected<TransmitResult, EngineError> {
        TransmitResult result;
        bool is_fin = action == Action::fin || action == Action::fin_retry;
        auto payload_len = is_fin ? std::size_t{0} : slice.bytes.size();
        auto max_opts = mtu_ > 60 + payload_len ? std::min<std::size_t>(28, mtu_ - 60 - payload_len) : 0;
        auto view = is_fin ? flow.fin(max_opts) : flow.ack(max_opts);
        if (!is_fin) { view.sequence = slice.sequence; view.payload = slice.bytes; }
        auto bytes = packet::make_tcp6(view, mtu_);
        if (!bytes) return std::unexpected(EngineError::invalid_mtu);
        auto rev = view;
        std::swap(rev.source, rev.destination);
        std::swap(rev.source_port, rev.destination_port);
        auto gen = table_.watch(rev);
        auto sent = link_.send_owned(packet::Side::second, std::move(*bytes), packet::PacketKind::ordinary, 0, std::move(gen));
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
