module nexus.udp.engine;
import nexus.rules;
import std;

namespace nexus::udp {
    MemoryEngine::MemoryEngine(packet::MemoryLink& link, rules::Matcher policy, Mapping mapping, Filtering filtering,
                               Limits limits, std::size_t mtu, std::optional<std::uint32_t> socket_mark)
        : link_(link), ipv4_(policy,mapping,filtering,limits,mtu,socket_mark),
          ipv6_(std::move(policy),mapping,filtering,limits,mtu,socket_mark) {}
    MemoryEngine::~MemoryEngine() = default;
    auto MemoryEngine::step(std::uint64_t now) -> std::expected<EngineStep, EngineError> {
        if (initialized_ && now < last_time_) return std::unexpected(EngineError{Error::time_reversed});
        initialized_ = true; last_time_ = now;
        EngineStep report;
        auto expired4 = ipv4_.expire(now);
        if (!expired4) return std::unexpected(EngineError{expired4.error()});
        auto expired6 = ipv6_.expire(now);
        if (!expired6) return std::unexpected(EngineError{expired6.error()});
        report.expired = *expired4 + *expired6;
        auto deliver = [&] {
            std::expected<void, packet::DeviceError> sent;
            try { sent = link_.send(packet::Side::second, pending_[pending_begin_]); }
            catch (std::bad_alloc const&) { report.backpressured = true; return; }
            if (!sent) {
                if (sent.error() == packet::DeviceError::queue_full) { report.backpressured = true; return; }
                if (sent.error() == packet::DeviceError::packet_too_large) pending_[pending_begin_++] = packet::Bytes{};
                report.output_error = sent.error(); return;
            }
            pending_[pending_begin_++] = packet::Bytes{}; report.delivered = true;
        };
        // Drain old replies before reading more sockets or device packets.
        if (pending_begin_ != pending_end_) {
            deliver();
            return report;
        }
        pending_begin_ = pending_end_ = 0;
        if (!incoming_) {
            auto incoming = link_.receive(packet::Side::second);
            if (!incoming) return std::unexpected(EngineError{incoming.error()});
            if (*incoming) incoming_ = std::move(**incoming);
        }
        if (incoming_) {
            report.input = true;
            auto& bytes = *incoming_;
            if (bytes.empty()) return std::unexpected(EngineError{packet::DeviceError::empty_packet});
            auto version = bytes[0] >> 4;
            if (version == 4 || version == 6) {
                try {
                    auto result = version == 4 ? ipv4_.submit(bytes, now) : ipv6_.submit(bytes, now);
                    if (!result) {
                        auto const* error = std::get_if<std::error_code>(&result.error());
                        if (error && (*error == std::errc::resource_unavailable_try_again || *error == std::errc::interrupted))
                            report.input_backpressured = true;
                        else report.rejected = result.error();
                    }
                } catch (std::bad_alloc const&) { report.input_allocation_failed = true; }
            } else {
                report.rejected = DirectError{RoutedError{RouteError::invalid_packet}};
            }
            if (!report.input_allocation_failed && !report.input_backpressured) incoming_.reset();
        }
        auto collect = [&](auto& direct, std::optional<DirectError>& error, bool& allocation_failed) {
            try {
                auto result = direct.poll(now);
                if (!result) { error = result.error(); return; }
                for (auto& item : *result) pending_[pending_end_++] = std::move(item);
            } catch (std::bad_alloc const&) { allocation_failed = true; }
        };
        collect(ipv4_, report.ipv4_error, report.ipv4_allocation_failed);
        collect(ipv6_, report.ipv6_error, report.ipv6_allocation_failed);
        if (pending_begin_ != pending_end_) deliver();
        return report;
    }
    auto MemoryEngine::stop(std::uint64_t now) -> std::expected<void, Error> {
        if (initialized_ && now < last_time_) return std::unexpected(Error::time_reversed);
        initialized_ = true; last_time_ = now;
        if (auto result = ipv4_.stop(now); !result) return result;
        if (auto result = ipv6_.stop(now); !result) return result;
        for (auto& packet : pending_) packet = packet::Bytes{};
        pending_begin_ = pending_end_ = 0;
        incoming_.reset();
        return {};
    }
}
