export module tailscale.derp_info;
import std;

export namespace tailscale::derp {
    enum class InfoError { size,json,version,rate };
    struct ServerSettings {
        std::uint32_t version=2;
        // Zero is unspecified, matching DERP. Values remain integer bytes.
        // Token-bucket arithmetic and enforcing a rate belong to the owner.
        std::uint64_t bytes_per_second=0,burst=0;
        auto operator==(ServerSettings const&) const -> bool = default;
    };
    inline constexpr std::size_t max_info_plaintext=4096;
    inline constexpr std::string_view regular_client_info=R"({"version":2,"CanAckPings":true})";
    auto parse_server_settings(std::span<std::uint8_t const>) -> std::expected<ServerSettings,InfoError>;
}

