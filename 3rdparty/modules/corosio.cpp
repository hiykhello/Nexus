module;
#include <coroutine>
#include <tuple>
#include <utility>
#include <vector>

module nexus.thirdparty.corosio;
import nexus.thirdparty.capy;

namespace nex::corosio {
    auto connect_candidates(tcp_socket& socket, std::vector<endpoint> endpoints)
        -> connect_task {
        auto result = co_await connect(socket, std::move(endpoints));
        // Keep the ownership contract stable for callers: a failed or
        // canceled candidate sequence never leaves its last socket open.
        if (std::get<0>(result)) socket.close();
        co_return result;
    }
}
