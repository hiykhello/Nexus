export module control_api.http_socket;

import std;
import platform.ip_address;

export namespace control_api {
    enum class SocketIoStatus { ok, would_block, closed };

    class Fd {
    public:
        static constexpr std::uintptr_t kInvalidHandle = ~std::uintptr_t{0};

        explicit Fd(std::uintptr_t raw = kInvalidHandle) noexcept : handle_(raw) {}
        ~Fd() { close(); }
        Fd(Fd const&) = delete;
        auto operator=(Fd const&) -> Fd& = delete;
        Fd(Fd&& other) noexcept : handle_(std::exchange(other.handle_, kInvalidHandle)) {}
        auto operator=(Fd&& other) noexcept -> Fd& {
            if (this != &other) {
                close();
                handle_ = std::exchange(other.handle_, kInvalidHandle);
            }
            return *this;
        }

        [[nodiscard]] auto valid() const noexcept -> bool { return handle_ != kInvalidHandle; }
        [[nodiscard]] auto native() const noexcept -> std::uintptr_t { return handle_; }
        auto close() noexcept -> void;
    private:
        std::uintptr_t handle_ = kInvalidHandle;
    };

    [[nodiscard]] auto create_listen_socket(bool ipv6, platform::IpAddress const& parsed_ip, std::uint16_t port)
        -> std::expected<Fd, std::string>;
    [[nodiscard]] auto accept_nonblocking(Fd const& listen_fd) noexcept -> Fd;
    [[nodiscard]] auto recv_nonblocking(Fd const& fd, std::span<char> out, std::size_t& received) noexcept
        -> SocketIoStatus;
    [[nodiscard]] auto send_nonblocking(Fd const& fd, std::span<char const> in, std::size_t& sent) noexcept
        -> SocketIoStatus;
}
