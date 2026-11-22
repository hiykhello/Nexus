export module packet.tun_windows;
import std;

export namespace packet {
    enum class WintunError { invalid_name, dll_missing, symbol_missing, invalid_state, unsupported };
    using WintunFailure = std::variant<WintunError, std::error_code>;

    struct WintunConfig {
        std::string name = "Nexus";
        std::string tunnel_type = "Nexus";
        std::uint32_t ring_capacity = 0x400000; // 4 MiB valid Wintun ring size
    };

    class WindowsTun {
        struct Impl;
        std::unique_ptr<Impl> impl_;
        explicit WindowsTun(std::unique_ptr<Impl>) noexcept;
    public:
        ~WindowsTun();
        WindowsTun(WindowsTun const&) = delete;
        auto operator=(WindowsTun const&) -> WindowsTun& = delete;
        WindowsTun(WindowsTun&&) noexcept;
        auto operator=(WindowsTun&&) noexcept -> WindowsTun&;

        [[nodiscard]] static auto open(WintunConfig const& cfg = {})
            -> std::expected<WindowsTun, WintunFailure>;
        [[nodiscard]] auto adapter_name() const noexcept -> std::string_view;
        [[nodiscard]] auto read_packet(std::span<std::uint8_t> out)
            -> std::expected<std::optional<std::size_t>, WintunFailure>;
        [[nodiscard]] auto write_packet(std::span<std::uint8_t const> ip_packet)
            -> std::expected<void, WintunFailure>;
        auto close() noexcept -> void;
    };
}
