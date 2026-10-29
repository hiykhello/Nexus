export module nexus.packet.tun_linux;
import std;

export namespace nexus::packet {
    enum class TunError { invalid_name };
    using TunFailure = std::variant<TunError, std::error_code>;
    // Owns one nonpersistent Linux TUN device, created exclusively in the
    // caller's current network namespace. No addresses, routes or MTU are set.
    // A descriptor borrower must finish all I/O before this owner is closed or moved.
    class LinuxTun {
        int fd_=-1;
        std::array<char,16> name_{};
        LinuxTun(int fd, std::array<char,16> name) noexcept : fd_(fd), name_(name) {}
    public:
        LinuxTun(LinuxTun const&)=delete;
        auto operator=(LinuxTun const&) -> LinuxTun& = delete;
        LinuxTun(LinuxTun&& other) noexcept;
        auto operator=(LinuxTun&& other) noexcept -> LinuxTun&;
        ~LinuxTun();
        // Empty selects a kernel-generated name; '%' templates are rejected.
        [[nodiscard]] static auto create(std::string_view name={}) -> std::expected<LinuxTun,TunFailure>;
        [[nodiscard]] auto native_handle() const noexcept -> int { return fd_; }
        [[nodiscard]] auto name() const noexcept -> std::string_view;
        auto close() noexcept -> void;
    };
}
