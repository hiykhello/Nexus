export module naive.padding;
import std;
import crypto;
import http.connect;
import http.header;
import socks5;

export namespace naive {
    inline constexpr std::uint8_t kFirstPaddings = 8;
    inline constexpr std::size_t kMaxPaddingPayload = 65535;
    inline constexpr std::size_t kPaddingThreshold = 100;

    struct UserCredential {
        std::string name;
        std::string username;
        std::string password;

        ~UserCredential();
        UserCredential() = default;
        UserCredential(std::string n, std::string u, std::string p)
            : name(std::move(n)), username(std::move(u)), password(std::move(p)) {}
        UserCredential(UserCredential const&) = default;
        UserCredential(UserCredential&&) noexcept = default;
        auto operator=(UserCredential const&) -> UserCredential& = default;
        auto operator=(UserCredential&&) noexcept -> UserCredential& = default;
    };

    // Generates a 16..32 byte printable ASCII value using non-Huffman-compressible header chars.
    [[nodiscard]] auto generate_padding_header() -> std::string;

    // Builds "Basic <base64(user:pass)>".
    [[nodiscard]] auto make_basic_auth(std::string_view user, std::string_view pass) -> std::string;

    // Constant-time verification of Proxy-Authorization Basic header against credentials.
    // Returns matched credential's config name on success.
    [[nodiscard]] auto verify_basic_auth(std::string_view header, std::span<UserCredential const> users)
        -> std::optional<std::string_view>;

    [[nodiscard]] auto parse_padding_type_request(std::string_view value) noexcept -> bool;
    [[nodiscard]] auto parse_padding_type_reply(std::string_view value) noexcept -> bool;

    // Parses host:port / ipv4:port / [ipv6]:port via shared http.connect authority validator.
    [[nodiscard]] auto parse_connect_authority(std::string_view authority) -> std::optional<socks5::Request>;

    [[nodiscard]] auto decoy_html_body(std::uint16_t status) noexcept -> std::string_view;

    [[nodiscard]] inline auto header_ci_equal(std::string_view a, std::string_view b) noexcept -> bool {
        if (a.size() != b.size()) return false;
        for (std::size_t i = 0; i < a.size(); ++i) {
            auto ca = static_cast<unsigned char>(a[i]);
            auto cb = static_cast<unsigned char>(b[i]);
            if (ca >= 'A' && ca <= 'Z') ca = static_cast<unsigned char>(ca - 'A' + 'a');
            if (cb >= 'A' && cb <= 'Z') cb = static_cast<unsigned char>(cb - 'A' + 'a');
            if (ca != cb) return false;
        }
        return true;
    }

    class PaddingEncoder {
        bool enabled_ = true;
        std::uint8_t frames_sent_ = 0;

    public:
        explicit PaddingEncoder(bool enabled = true) noexcept : enabled_(enabled) {}
        [[nodiscard]] auto enabled() const noexcept -> bool { return enabled_; }
        [[nodiscard]] auto frames_sent() const noexcept -> std::uint8_t { return frames_sent_; }
        [[nodiscard]] auto in_passthrough() const noexcept -> bool {
            return !enabled_ || frames_sent_ >= kFirstPaddings;
        }

        // Encodes payload (chunked <= 65535 per frame) for first 8 frames, then passes raw.
        auto encode(std::span<std::uint8_t const> payload, std::vector<std::uint8_t>& out) -> bool;

        // Deterministic pad-length overload for unit tests (uses explicit pad_len on each chunk while < 8 frames).
        auto encode_with_pad_len(std::span<std::uint8_t const> payload, std::uint8_t pad_len,
                                 std::vector<std::uint8_t>& out) -> bool;
    };

    class PaddingDecoder {
        enum class State : std::uint8_t {
            header_hi,
            header_lo,
            pad_len,
            payload,
            padding,
            passthrough
        };
        State state_ = State::passthrough;
        bool enabled_ = true;
        std::uint8_t frames_received_ = 0;
        std::uint8_t hi_ = 0;
        std::size_t remaining_payload_ = 0;
        std::size_t remaining_pad_ = 0;

        auto finish_frame() noexcept -> void;

    public:
        explicit PaddingDecoder(bool enabled = true) noexcept
            : state_(enabled ? State::header_hi : State::passthrough), enabled_(enabled) {}

        [[nodiscard]] auto enabled() const noexcept -> bool { return enabled_; }
        [[nodiscard]] auto frames_received() const noexcept -> std::uint8_t { return frames_received_; }
        [[nodiscard]] auto in_passthrough() const noexcept -> bool { return state_ == State::passthrough; }

        // Feeds arbitrary chunk sizes (including 1 byte at a time) and appends decoded plaintext to out.
        auto feed(std::span<std::uint8_t const> in, std::vector<std::uint8_t>& out) -> bool;
    };
}
