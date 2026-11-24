module;
#include <boost/capy/task.hpp>
module relay;
import std;

namespace relay {
    auto SplicePipePool::acquire() noexcept -> Pipe { return {}; }
    auto SplicePipePool::release(Pipe, bool, std::size_t, Clock::time_point) noexcept -> void {}
    auto SplicePipePool::reap(Clock::time_point) noexcept -> void {}
    auto SplicePipePool::clear() noexcept -> void {}
    auto Server::set_tcp_splice_pipes(std::size_t maximum) -> bool {
        if (running || (listener && listener->is_open()) || !workers.empty() || quota.used() != 0) return false;
        if (maximum) return false;
        splice_pipes.reset();
        return true;
    }
    auto relay_splice(Session&, bool, bool) -> capy::task<std::optional<bool>> { co_return std::nullopt; }
}
