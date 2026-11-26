// Disabled HTTP/3 stub for `nexus tools fetch` when http-client-h3 is not enabled.
export module cli.tools_fetch_h3;
import std;
import capy;
import corosio;
import cli.tools_fetch;
import http.rule_fetch_connection;
import relay;
import tls.profiles;

export namespace cli::fetch {
    inline constexpr bool h3_available = false;

    inline auto exchange_h3(corosio::io_context&, relay::Server*, std::size_t,
        http::detail::Resolver&, tls::ShapedClientProfile const&,
        ParsedFetchUrl const&, FetchOptions const&,
        std::chrono::steady_clock::time_point, std::chrono::steady_clock::time_point,
        FetchResult&) -> capy::task<std::expected<void, std::string>> {
        co_return std::unexpected("HTTP/3 is unavailable in this build");
    }
}
