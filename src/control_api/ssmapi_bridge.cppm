export module control_api.ssmapi_bridge;
import std;
import relay;

export namespace control_api {
    class SsmApiBridge {
        struct Impl;
        std::unique_ptr<Impl> impl_;
    public:
        SsmApiBridge();
        ~SsmApiBridge();
        SsmApiBridge(SsmApiBridge&&) noexcept;
        auto operator=(SsmApiBridge&&) noexcept -> SsmApiBridge&;
        auto attach_users(std::shared_ptr<relay::ShadowsocksUserDirectory> users) noexcept -> void;
        [[nodiscard]] auto dispatch(std::string_view prefix, std::string_view method,
            std::string_view target, std::string_view body) -> std::optional<std::pair<int, std::string>>;
    };

    [[nodiscard]] auto ssmapi_available() noexcept -> bool;
}
