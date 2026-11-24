export module cli.rule_fetch_h2;
import std;
import cli.rule_fetch_response;
import http.header;
import capy;
import corosio;

export namespace cli::rule_fetch {
    inline constexpr bool http2_enabled=false;

    class Http2Pool {
    public:
        auto stop() noexcept -> void {}
        auto request(corosio::io_context&,Transfer,Http2Stream={})
            -> capy::task<std::optional<TransferResult>> {
            co_return std::nullopt;
        }
    };
}
