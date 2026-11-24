module control_api.ssmapi_bridge;
import std;
import relay;

namespace control_api {
    struct SsmApiBridge::Impl {};
    SsmApiBridge::SsmApiBridge() = default;
    SsmApiBridge::~SsmApiBridge() = default;
    SsmApiBridge::SsmApiBridge(SsmApiBridge&&) noexcept = default;
    auto SsmApiBridge::operator=(SsmApiBridge&&) noexcept -> SsmApiBridge& = default;
    auto SsmApiBridge::attach_users(std::shared_ptr<relay::ShadowsocksUserDirectory>) noexcept -> void {}

    auto SsmApiBridge::dispatch(std::string_view, std::string_view,
        std::string_view, std::string_view) -> std::optional<std::pair<int, std::string>> {
        return std::nullopt;
    }

    auto ssmapi_available() noexcept -> bool { return false; }
}
