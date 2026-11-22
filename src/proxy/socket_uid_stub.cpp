module;
#include <boost/corosio/endpoint.hpp>
module proxy;
import std;
import rules;

namespace proxy {
    auto Session::inspect_source_owner(rules::RouteMatcher const&, std::optional<io::endpoint>) -> void {}
}
