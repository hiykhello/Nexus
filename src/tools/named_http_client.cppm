export module http.named_client;
import std;
import functional;
import config;
import http.header;
import capy;
import corosio;

export namespace http {
    using HttpDeadline=std::chrono::steady_clock::time_point;
    using HttpBodyConsumer=functional::function_ref<capy::task<bool>(std::string_view,HttpDeadline)>;
    using HttpHeaderConsumer=functional::function_ref<void(std::string_view,std::string_view)>;

    struct NamedHttpRequest {
        std::string_view target;
        std::span<HeaderField const> headers;
        HttpDeadline deadline;
        std::optional<std::uint16_t> alternative_port;
        std::optional<HttpDeadline> started;
        bool allow_not_modified=false;
        bool allow_redirect=false;
    };

    // Runs on its executor. The caller joins requests before destroying the
    // client. Request views and the consumers remain valid through completion.
    // The body is provisional until the result confirms a complete response.
    class NamedHttpClient {
        struct Impl;
        std::unique_ptr<Impl> impl_;
        explicit NamedHttpClient(std::unique_ptr<Impl>) noexcept;
    public:
        ~NamedHttpClient();
        NamedHttpClient(NamedHttpClient const&)=delete;
        auto operator=(NamedHttpClient const&) -> NamedHttpClient& = delete;

        [[nodiscard]] static auto create(config::Config config,std::string_view name,std::string_view authority)
            -> std::expected<std::unique_ptr<NamedHttpClient>,std::string>;

        [[nodiscard]] auto executor() noexcept -> corosio::io_context&;
        [[nodiscard]] auto settings() const noexcept -> config::NamedHttpClient const&;
        [[nodiscard]] auto allows_http3_alternative() const noexcept -> bool;

        auto get(NamedHttpRequest request,HttpBodyConsumer body,std::optional<HttpHeaderConsumer> headers={})
            -> capy::task<std::expected<unsigned,std::string>>;
    };
}
