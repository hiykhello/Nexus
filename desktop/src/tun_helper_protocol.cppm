export module desktop.tun_helper_protocol;

import std;

export namespace desktop {
    inline constexpr std::size_t kTunHelperMaxRequestBytes = 256;
    inline constexpr std::size_t kTunHelperMaxReplyBytes = 1024;

    inline constexpr std::string_view kWinTunHelperServiceName = "NexusTunHelper";
    inline constexpr std::string_view kWinTunHelperPipeName = R"(\\.\pipe\nexus-tun-helper)";
    inline constexpr std::string_view kWinTunHelperRegSubkey = R"(SOFTWARE\Nexus\TunHelper)";
    inline constexpr std::string_view kWinTunHelperStageDirSddl = "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)";

    inline constexpr std::string_view kMacTunHelperLabel = "io.nexus.tun-helper";
    inline constexpr std::string_view kMacTunHelperPlistPath = "/Library/LaunchDaemons/io.nexus.tun-helper.plist";
    inline constexpr std::string_view kMacTunHelperConfigPath = "/Library/Application Support/Nexus/tun-helper.conf";
    inline constexpr std::string_view kMacTunHelperBinDir = "/Library/Application Support/Nexus/bin";
    inline constexpr std::string_view kMacTunHelperSocketPath = "/var/run/nexus-tun-helper.sock";
    inline constexpr std::string_view kMacTunHelperLogPath = "/var/log/nexus-tun-helper.log";

    enum class TunHelperCommand {
        ping,
        status,
        start,
        stop,
    };

    struct TunHelperReply {
        bool ok = false;
        bool running = false;
        std::uint64_t pid = 0;
        std::string detail;
    };

    struct TunHelperPinnedConfig {
        std::string binary;
        std::string sha256;
        std::string config;
        std::string workdir;
        std::string owner;
        std::string staged_binary;
    };

    [[nodiscard]] auto parse_tun_helper_request(std::string_view raw) noexcept -> std::optional<TunHelperCommand>;
    [[nodiscard]] auto format_tun_helper_request(TunHelperCommand cmd) noexcept -> std::string_view;

    [[nodiscard]] auto format_tun_helper_reply(TunHelperReply const& reply) -> std::string;
    [[nodiscard]] auto parse_tun_helper_reply(std::string_view raw) -> TunHelperReply;

    [[nodiscard]] auto is_valid_sha256_hex(std::string_view hex) noexcept -> bool;
    [[nodiscard]] auto sha256_bytes(std::span<std::byte const> data) -> std::string;
    [[nodiscard]] auto sha256_bytes(std::string_view data) -> std::string;
    [[nodiscard]] auto sha256_file(std::filesystem::path const& path) -> std::expected<std::string, std::string>;

    [[nodiscard]] auto validate_windows_sid(std::string_view sid) noexcept -> bool;
    [[nodiscard]] auto build_win_helper_pipe_sddl(std::string_view owner_sid) -> std::expected<std::string, std::string>;

    [[nodiscard]] auto escape_xml_text(std::string_view text) -> std::string;
    [[nodiscard]] auto render_macos_tun_helper_plist(
        std::string_view helper_binary,
        std::string_view label = kMacTunHelperLabel,
        std::string_view log_path = kMacTunHelperLogPath) -> std::expected<std::string, std::string>;

    [[nodiscard]] auto quote_posix_sh_arg(std::string_view arg) -> std::expected<std::string, std::string>;
    [[nodiscard]] auto escape_applescript_string(std::string_view text) -> std::expected<std::string, std::string>;
    [[nodiscard]] auto build_macos_osascript_admin_script(std::span<std::string_view const> argv)
        -> std::expected<std::string, std::string>;

    [[nodiscard]] auto serialize_tun_helper_config(TunHelperPinnedConfig const& cfg) -> std::expected<std::string, std::string>;
    [[nodiscard]] auto parse_tun_helper_config(std::string_view text) -> std::expected<TunHelperPinnedConfig, std::string>;
}
