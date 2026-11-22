export module cli.rule_fetch_h2;
import std;
import cli.rule_fetch_response;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

export namespace cli::rule_fetch {
    inline constexpr bool http2_enabled=true;

    class Http2Pool {
        struct Impl;
        std::unique_ptr<Impl> impl_;
    public:
        Http2Pool();
        ~Http2Pool();
        Http2Pool(Http2Pool const&)=delete;
        auto operator=(Http2Pool const&) -> Http2Pool& = delete;
        auto stop() noexcept -> void;
        auto request(nex::corosio::io_context&,Transfer,Http2Stream={})
            -> nex::capy::task<std::optional<TransferResult>>;
    };
}
