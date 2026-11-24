// Wire codecs and 16-chunk padding adapter for sing-mux v0/v1 (big-endian).
export module mux.sing_wire;
import std;
import capy;
import net.datagram_frame;
import platform.ip_address;

export namespace mux::sing {
    inline constexpr std::string_view magic_domain = "sp.mux.sing-box.arpa";
    inline constexpr std::uint16_t magic_port = 444;
    inline constexpr std::uint8_t version_0 = 0;
    inline constexpr std::uint8_t version_1 = 1;
    inline constexpr std::uint8_t proto_smux = 0;
    inline constexpr std::uint8_t proto_yamux = 1;
    inline constexpr std::uint8_t proto_h2mux = 2;
    inline constexpr std::uint16_t flag_udp = 1;
    inline constexpr std::uint16_t flag_addr = 2;
    inline constexpr std::uint8_t status_success = 0;
    inline constexpr std::uint8_t status_error = 1;
    inline constexpr std::size_t first_paddings = 16;

    [[nodiscard]] inline auto is_mux_destination(std::string_view host, std::uint16_t port) noexcept -> bool {
        if (port != magic_port || host.size() != magic_domain.size()) return false;
        for (std::size_t i = 0; i < magic_domain.size(); ++i) {
            unsigned char c = static_cast<unsigned char>(host[i]);
            if (c >= 'A' && c <= 'Z') c = static_cast<unsigned char>(c - 'A' + 'a');
            if (static_cast<char>(c) != magic_domain[i]) return false;
        }
        return true;
    }

    [[nodiscard]] inline auto magic_proxy_address() noexcept -> net::ProxyAddress {
        net::ProxyAddress addr{net::ProxyAddressFamily::domain, {}, static_cast<std::uint8_t>(magic_domain.size()), magic_port};
        std::ranges::copy(magic_domain, addr.bytes.begin());
        return addr;
    }

    inline auto next_padding_len(std::optional<std::uint16_t> explicit_len) noexcept -> std::uint16_t {
        if (explicit_len) return *explicit_len;
        static std::atomic<std::uint64_t> seq{0};
        thread_local std::mt19937_64 rng([] {
            std::random_device rd;
            return (static_cast<std::uint64_t>(rd()) << 32) ^ rd() ^
                   (seq.fetch_add(1, std::memory_order_relaxed) * 0x9e3779b97f4a7c15ULL);
        }());
        return static_cast<std::uint16_t>(256u + (rng() % 512u));
    }

    struct SessionRequest {
        std::uint8_t version = version_1;
        std::uint8_t protocol = proto_smux;
        bool padding = false;
        auto operator==(SessionRequest const&) const -> bool = default;
    };

    struct StreamRequest {
        bool udp = false;
        bool packet_addr = false;
        net::ProxyAddress destination{};
        auto operator==(StreamRequest const&) const -> bool = default;
    };

    struct StreamResponse {
        std::uint8_t status = status_success;
        std::string message;
        auto operator==(StreamResponse const&) const -> bool = default;
    };

    [[nodiscard]] inline auto encode_session_request(SessionRequest const& req,
        std::optional<std::uint16_t> pad_len = std::nullopt) -> std::vector<std::uint8_t> {
        std::vector<std::uint8_t> out;
        out.push_back(req.version);
        out.push_back(req.protocol);
        if (req.version == version_1) {
            out.push_back(req.padding ? 1 : 0);
            if (req.padding) {
                auto n = next_padding_len(pad_len);
                out.push_back(static_cast<std::uint8_t>(n >> 8));
                out.push_back(static_cast<std::uint8_t>(n));
                out.resize(out.size() + n, 0);
            }
        }
        return out;
    }

    [[nodiscard]] inline auto decode_session_request(std::span<std::uint8_t const> wire)
        -> std::expected<std::optional<std::pair<SessionRequest, std::size_t>>, std::string> {
        if (wire.size() < 2) return std::nullopt;
        std::uint8_t ver = wire[0], proto = wire[1];
        if (ver > version_1) return std::unexpected("unsupported sing-mux version");
        if (proto > proto_h2mux) return std::unexpected("unsupported sing-mux inner protocol");
        if (ver == version_0) return std::pair{SessionRequest{ver, proto, false}, std::size_t{2}};
        if (wire.size() < 3) return std::nullopt;
        if (wire[2] > 1) return std::unexpected("invalid sing-mux padding flag");
        bool padded = wire[2] != 0;
        if (!padded) return std::pair{SessionRequest{ver, proto, false}, std::size_t{3}};
        if (wire.size() < 5) return std::nullopt;
        std::size_t plen = (static_cast<std::size_t>(wire[3]) << 8) | wire[4];
        if (wire.size() - 5 < plen) return std::nullopt;
        return std::pair{SessionRequest{ver, proto, true}, std::size_t{5 + plen}};
    }

    [[nodiscard]] inline auto encode_stream_request(StreamRequest const& req)
        -> std::expected<std::vector<std::uint8_t>, std::string> {
        std::uint16_t flags = 0;
        if (req.udp) flags |= flag_udp;
        if (req.packet_addr) flags |= flag_addr;
        auto dest = req.destination;
        if (req.packet_addr && !net::valid_proxy_address(dest)) dest = magic_proxy_address();
        std::vector<std::uint8_t> out;
        out.reserve(32);
        out.push_back(static_cast<std::uint8_t>(flags >> 8));
        out.push_back(static_cast<std::uint8_t>(flags));
        if (!net::append_proxy_address(out, dest, net::AddressWire::socks))
            return std::unexpected("invalid sing-mux stream destination");
        return out;
    }

    [[nodiscard]] inline auto decode_stream_request(std::span<std::uint8_t const> wire)
        -> std::expected<std::optional<std::pair<StreamRequest, std::size_t>>, std::string> {
        if (wire.size() < 2) return std::nullopt;
        std::uint16_t flags = (static_cast<std::uint16_t>(wire[0]) << 8) | wire[1];
        auto addr = net::parse_proxy_address(wire.subspan(2), net::AddressWire::socks);
        if (addr.status == net::DatagramStatus::incomplete) return std::nullopt;
        if (addr.status != net::DatagramStatus::accepted)
            return std::unexpected("invalid sing-mux stream destination");
        bool udp = (flags & flag_udp) != 0;
        bool paddr = udp && (flags & flag_addr) != 0;
        return std::pair{StreamRequest{udp, paddr, addr.address}, std::size_t{2 + addr.consumed}};
    }

    [[nodiscard]] inline auto encode_stream_response(StreamResponse const& resp) -> std::vector<std::uint8_t> {
        std::vector<std::uint8_t> out;
        out.push_back(resp.status);
        if (resp.status == status_error) {
            std::size_t len = resp.message.size();
            do {
                std::uint8_t b = static_cast<std::uint8_t>(len & 0x7f);
                len >>= 7;
                if (len > 0) b |= 0x80;
                out.push_back(b);
            } while (len > 0);
            out.insert(out.end(), resp.message.begin(), resp.message.end());
        }
        return out;
    }

    [[nodiscard]] inline auto decode_stream_response(std::span<std::uint8_t const> wire)
        -> std::expected<std::optional<std::pair<StreamResponse, std::size_t>>, std::string> {
        if (wire.empty()) return std::nullopt;
        std::uint8_t st = wire[0];
        if (st > status_error) return std::unexpected("invalid sing-mux stream status");
        if (st == status_success) return std::pair{StreamResponse{status_success, {}}, std::size_t{1}};
        std::size_t len = 0, shift = 0, pos = 1;
        while (pos < wire.size()) {
            std::uint8_t b = wire[pos++];
            len |= static_cast<std::size_t>(b & 0x7f) << shift;
            if ((b & 0x80) == 0) break;
            shift += 7;
            if (shift > 28) return std::unexpected("invalid sing-mux response message varint");
            if (pos == wire.size()) return std::nullopt;
        }
        if (pos == 1 || (wire[pos - 1] & 0x80) != 0) return std::nullopt;
        if (len > 4096) return std::unexpected("sing-mux response error message too large");
        if (wire.size() - pos < len) return std::nullopt;
        std::string msg(reinterpret_cast<char const*>(wire.data() + pos), len);
        return std::pair{StreamResponse{status_error, std::move(msg)}, pos + len};
    }

    [[nodiscard]] inline auto encode_padding_chunk(std::span<std::uint8_t const> data,
        std::optional<std::uint16_t> pad_len = std::nullopt) -> std::vector<std::uint8_t> {
        auto plen = next_padding_len(pad_len);
        std::size_t orig = std::min<std::size_t>(data.size(), 65535);
        std::vector<std::uint8_t> out;
        out.reserve(4 + orig + plen);
        out.push_back(static_cast<std::uint8_t>(orig >> 8));
        out.push_back(static_cast<std::uint8_t>(orig));
        out.push_back(static_cast<std::uint8_t>(plen >> 8));
        out.push_back(static_cast<std::uint8_t>(plen));
        out.insert(out.end(), data.begin(), data.begin() + orig);
        out.resize(out.size() + plen, 0);
        return out;
    }

    template<class Stream>
    auto read_exact(Stream& s, std::span<std::uint8_t> dst) -> capy::task<bool> {
        while (!dst.empty()) {
            auto r = co_await s.read(dst);
            if (!r || *r == 0 || *r > dst.size()) co_return false;
            dst = dst.subspan(*r);
        }
        co_return true;
    }

    template<class Lower>
    class PaddingStream {
        Lower& lower_;
        std::size_t read_chunks_{0}, write_chunks_{0};
        std::size_t read_remaining_{0}, padding_remaining_{0};

        auto skip_padding() -> capy::task<bool> {
            std::array<std::uint8_t, 512> scratch{};
            while (padding_remaining_ > 0) {
                auto want = std::min(padding_remaining_, scratch.size());
                auto r = co_await lower_.read(std::span(scratch).first(want));
                if (!r || *r == 0 || *r > want) co_return false;
                padding_remaining_ -= *r;
            }
            co_return true;
        }
    public:
        explicit PaddingStream(Lower& lower) noexcept : lower_(lower) {}

        auto read(std::span<std::uint8_t> out) -> capy::task<std::expected<std::size_t, std::string>> {
            for (;;) {
                if (read_remaining_ > 0) {
                    auto want = std::min(out.size(), read_remaining_);
                    auto r = co_await lower_.read(out.first(want));
                    if (!r || *r == 0 || *r > want) co_return std::unexpected(std::string("padded stream EOF"));
                    read_remaining_ -= *r;
                    co_return *r;
                }
                if (padding_remaining_ > 0) {
                    if (!co_await skip_padding()) co_return std::unexpected(std::string("padded skip EOF"));
                }
                if (read_chunks_ < first_paddings) {
                    std::array<std::uint8_t, 4> hdr{};
                    std::size_t got = 0;
                    while (got < hdr.size()) {
                        auto r = co_await lower_.read(std::span(hdr).subspan(got));
                        if (!r) co_return std::unexpected(std::string("padded header read error"));
                        if (*r == 0) {
                            if (got == 0) co_return std::size_t{0};
                            co_return std::unexpected(std::string("truncated padded header"));
                        }
                        got += *r;
                    }
                    read_remaining_ = (static_cast<std::size_t>(hdr[0]) << 8) | hdr[1];
                    padding_remaining_ = (static_cast<std::size_t>(hdr[2]) << 8) | hdr[3];
                    ++read_chunks_;
                    continue;
                }
                auto r = co_await lower_.read(out);
                if (!r) co_return std::unexpected(std::string("mux lower read failed"));
                co_return *r;
            }
        }

        auto send(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
            while (!bytes.empty()) {
                if (write_chunks_ < first_paddings) {
                    auto chunk = bytes.first(std::min<std::size_t>(bytes.size(), 65535));
                    auto wire = encode_padding_chunk(chunk);
                    if (!co_await lower_.send(wire)) co_return false;
                    ++write_chunks_;
                    bytes = bytes.subspan(chunk.size());
                } else {
                    if (!co_await lower_.send(bytes)) co_return false;
                    break;
                }
            }
            co_return true;
        }

        auto close_output() -> capy::task<bool> { co_return co_await lower_.close_output(); }
        auto cancel() noexcept -> void { lower_.cancel(); }
    };
}
