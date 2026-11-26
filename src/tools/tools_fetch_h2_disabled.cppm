// Disabled HTTP/2 stub for `nexus tools fetch` when http-client-h2 is not enabled.
export module cli.tools_fetch_h2;
import std;
import capy;
import cli.tools_fetch;

export namespace cli::fetch {
    inline constexpr bool h2_available = false;

    template<class Lower>
    auto exchange_h2(Lower&, std::string_view, std::string_view, std::string_view,
        std::span<FetchHeader const>, std::string_view,
        std::chrono::steady_clock::time_point, std::chrono::steady_clock::time_point,
        std::size_t, FetchResult&) -> capy::task<std::expected<void, std::string>> {
        co_return std::unexpected("HTTP/2 is unavailable in this build");
    }
}
