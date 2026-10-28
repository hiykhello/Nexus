module nexus.tcp.stack;
import std;

namespace nexus::tcp {
    MemoryDirect4::MemoryDirect4(packet::MemoryLink& link, ConnectionTable& table, rules::Matcher policy,
                                 std::size_t direct_limit, std::size_t mtu)
        : table_(table), engine_(link,table,policy,mtu), direct_(table,engine_,std::move(policy),direct_limit) {}
    MemoryDirect4::~MemoryDirect4() { stop(); }
    auto MemoryDirect4::stop() noexcept -> void {
        if (stopped_) return;
        stopped_ = true;
        for (auto const& [id, unused] : started_) { (void)unused; (void)direct_.close(id); }
        for (auto id : owned_) (void)table_.abort(id);
        started_.clear(); owned_.clear();
    }
    auto MemoryDirect4::step(std::uint64_t now, std::uint32_t iss) -> std::expected<StackStep, StackError> {
        if (stopped_) return std::unexpected(StackError{StackStopped::stopped});
        StackStep report;
        auto input = engine_.step(now, iss);
        if (!input) return std::unexpected(std::visit([](auto error) -> StackError { return error; }, input.error()));
        report.input = std::move(*input);
        if (report.input.opened && report.input.id) {
            try { owned_.insert(*report.input.id); }
            catch (...) { (void)table_.abort(*report.input.id); throw; }
        }
        std::erase_if(owned_, [&](auto id) { return !table_.get(id); });
        for (auto it = started_.begin(); it != started_.end();) {
            if (!table_.get(it->first)) { (void)direct_.close(it->first); it = started_.erase(it); }
            else ++it;
        }
        if (report.input.id) {
            auto id = *report.input.id;
            auto* flow = table_.get(id);
            if (flow && (flow->state() == ConnectionState::established || flow->state() == ConnectionState::peer_closed)
                && !started_.contains(id)) {
                try {
                    auto [it, inserted] = started_.emplace(id, false);
                    (void)inserted;
                    auto started = direct_.start(id, now);
                    if (!started) {
                        report.start_error = started.error();
                        // Socket failures have already been retained by Direct4 for reset.
                        it->second = !std::holds_alternative<std::error_code>(started.error());
                    }
                } catch (...) {
                    (void)direct_.close(id);
                    started_.erase(id); owned_.erase(id); (void)table_.abort(id);
                    throw;
                }
            }
        }
        for (auto& [id, needs_reset] : started_) {
            if (!needs_reset) continue;
            auto* flow = table_.get(id);
            if (!flow || flow->state() == ConnectionState::reset || flow->state() == ConnectionState::expired) {
                needs_reset = false; continue;
            }
            auto reset = engine_.reset(id, now);
            if (!reset) return std::unexpected(StackError{reset.error()});
            report.reset = std::move(*reset);
            if (report.reset->connection_error || flow->state() == ConnectionState::reset) needs_reset = false;
            break;
        }
        auto direct = direct_.step(now);
        if (!direct) return std::unexpected(StackError{direct.error()});
        report.direct = std::move(*direct);
        auto service = engine_.service(now);
        if (!service) return std::unexpected(StackError{service.error()});
        report.service = std::move(*service);
        return report;
    }
}
