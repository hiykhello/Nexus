export module packet.tun_darwin;
import std;

export namespace packet {
    enum class DarwinTunError { invalid_name, invalid_device, unsupported };
    enum class DarwinTunFdOwnership { borrow, adopt };
    using DarwinTunFailure = std::variant<DarwinTunError, std::error_code>;

    struct DarwinTunConfig {
        std::string name; // empty = auto ("utunN"), or explicit "utun<num>"
        std::size_t mtu = 1500;
    };

    class DarwinTun {
        int fd_ = -1;
        std::string name_;
        bool has_af_header_ = true;
        std::optional<int> restore_flags_;
        DarwinTun(int fd, std::string name, bool has_af_header = true,
            std::optional<int> restore_flags = std::nullopt) noexcept
            : fd_(fd), name_(std::move(name)), has_af_header_(has_af_header), restore_flags_(restore_flags) {}
    public:
        DarwinTun(DarwinTun const&) = delete;
        auto operator=(DarwinTun const&) -> DarwinTun& = delete;
        DarwinTun(DarwinTun&& other) noexcept
            : fd_(std::exchange(other.fd_, -1)), name_(std::move(other.name_)),
              has_af_header_(other.has_af_header_),
              restore_flags_(std::exchange(other.restore_flags_, std::nullopt)) {}
        auto operator=(DarwinTun&& other) noexcept -> DarwinTun& {
            if (this != &other) {
                close();
                fd_ = std::exchange(other.fd_, -1);
                name_ = std::move(other.name_);
                has_af_header_ = other.has_af_header_;
                restore_flags_ = std::exchange(other.restore_flags_, std::nullopt);
            }
            return *this;
        }
        ~DarwinTun() { close(); }

        [[nodiscard]] static auto open(DarwinTunConfig const& cfg = {})
            -> std::expected<DarwinTun, DarwinTunFailure>;
        [[nodiscard]] static auto attach(int fd, DarwinTunFdOwnership ownership,
            bool has_af_header = true) -> std::expected<DarwinTun, DarwinTunFailure>;
        [[nodiscard]] auto native_handle() const noexcept -> int { return fd_; }
        [[nodiscard]] auto device_name() const noexcept -> std::string_view { return name_; }
        [[nodiscard]] auto read_packet(std::span<std::uint8_t> out)
            -> std::expected<std::optional<std::size_t>, DarwinTunFailure>;
        [[nodiscard]] auto write_packet(std::span<std::uint8_t const> ip_packet)
            -> std::expected<void, DarwinTunFailure>;
        auto close() noexcept -> void;
    };
}
