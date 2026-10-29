module nexus.transport.memory;
import std;

namespace nexus::transport {
    MemoryEngine::MemoryEngine(packet::MemoryLink& link, tcp::ConnectionTable& table, rules::Matcher policy,
                               std::size_t tcp_limit, udp::Mapping mapping, udp::Filtering filtering,
                               udp::Limits udp_limits, std::size_t mtu, packet::DeviceLimits internal_limits,
                               std::optional<std::uint32_t> socket_mark)
        : tcp_link_(internal_limits), udp_link_(internal_limits), tcp6_link_(internal_limits), device_(link,tcp_link_,udp_link_),
          tcp_(tcp_link_,table,policy,tcp_limit,mtu,socket_mark), udp_(udp_link_,std::move(policy),mapping,filtering,udp_limits,mtu,socket_mark) {}
    MemoryEngine::MemoryEngine(packet::MemoryLink& link, tcp::ConnectionTable& table, tcp::ConnectionTable6& table6,
                               rules::Matcher policy, std::size_t flow_limit, std::size_t tcp_limit,
                               udp::Mapping mapping, udp::Filtering filtering, udp::Limits udp_limits,
                               std::size_t mtu, packet::DeviceLimits internal_limits, std::optional<std::uint32_t> socket_mark)
        : tcp_link_(internal_limits), udp_link_(internal_limits), tcp6_link_(internal_limits),
          device_(link,tcp_link_,udp_link_,tcp6_link_), tcp_(tcp_link_,table,policy,tcp_limit,mtu,socket_mark),
          udp_(udp_link_,policy,mapping,filtering,udp_limits,mtu,socket_mark), table4_(&table), table6_(&table6),
          tcp6_(std::in_place,tcp6_link_,table6,std::move(policy),tcp_limit,mtu,socket_mark),
          flow_limit_(flow_limit), direct_limit_(tcp_limit) {}
    MemoryEngine::~MemoryEngine() {
        if (tcp6_) {
            table4_->admission_limit(std::numeric_limits<std::size_t>::max());
            table6_->admission_limit(std::numeric_limits<std::size_t>::max());
        }
    }
    auto MemoryEngine::stop(std::uint64_t now) -> std::expected<void, MemoryError> {
        if (stopped_) return {};
        if (initialized_ && now < now_) return std::unexpected(MemoryError{MemoryClockError::time_reversed});
        auto stopped = udp_.stop(now);
        if (!stopped) return std::unexpected(MemoryError{udp::EngineError{stopped.error()}});
        tcp_.stop();
        if (tcp6_) {
            tcp6_->stop();
            table4_->admission_limit(std::numeric_limits<std::size_t>::max());
            table6_->admission_limit(std::numeric_limits<std::size_t>::max());
        }
        device_.discard();
        tcp_link_.close(packet::Side::first); tcp_link_.close(packet::Side::second);
        tcp6_link_.close(packet::Side::first); tcp6_link_.close(packet::Side::second);
        udp_link_.close(packet::Side::first); udp_link_.close(packet::Side::second);
        now_ = now; initialized_ = true; stopped_ = true;
        return {};
    }
    auto MemoryEngine::step(std::uint64_t now, std::uint32_t iss) -> std::expected<MemoryStep, MemoryError> {
        if (stopped_) return std::unexpected(MemoryError{MemoryClockError::stopped});
        if (initialized_ && now < now_) return std::unexpected(MemoryError{MemoryClockError::time_reversed});
        initialized_ = true; now_ = now;
        auto device=device_.step();
        if (!device) return std::unexpected(MemoryError{device.error()});
        if (tcp6_) {
            table4_->admission_limit(flow_limit_ > table6_->size() ? flow_limit_ - table6_->size() : 0);
            tcp_.direct_limit(direct_limit_ > tcp6_->direct_size() ? direct_limit_ - tcp6_->direct_size() : 0);
        }
        auto tcp=tcp_.step(now,iss);
        if (!tcp) return std::unexpected(MemoryError{tcp.error()});
        std::optional<tcp::StackStep> tcp6;
        if (tcp6_) {
            table6_->admission_limit(flow_limit_ > table4_->size() ? flow_limit_ - table4_->size() : 0);
            tcp6_->direct_limit(direct_limit_ > tcp_.direct_size() ? direct_limit_ - tcp_.direct_size() : 0);
            auto result=tcp6_->step(now,iss);
            if (!result) return std::unexpected(MemoryError{result.error()});
            tcp6=std::move(*result);
        }
        auto udp=udp_.step(now);
        if (!udp) return std::unexpected(MemoryError{udp.error()});
        return MemoryStep{std::move(*device),std::move(*tcp),std::move(*udp),std::move(tcp6)};
    }
}
