module cli.tailscale_endpoint;
import std;

namespace cli::tailscale_endpoint {
    auto parse(std::string_view) -> std::expected<std::optional<Config>,std::string> { return std::nullopt; }
    auto run(Config const&, bool, bool) -> int { return 1; }
}
