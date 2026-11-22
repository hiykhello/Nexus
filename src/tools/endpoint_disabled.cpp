module cli.endpoint;
import std;
#ifndef MCPP_FEATURE_WIREGUARD_ENDPOINT
namespace cli::endpoint {
    auto run(int,char**) -> int { std::cerr << "endpoint support is unavailable in this build\n"; return 1; }
}
#endif
