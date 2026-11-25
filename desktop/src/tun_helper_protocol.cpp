module desktop.tun_helper_protocol;

import std;

namespace desktop {
    namespace {
        constexpr std::array<std::uint32_t, 64> kSha256K = {
            0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
            0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
            0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
            0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
            0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
            0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
            0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
            0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffaU, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
        };

        class Sha256State {
            std::array<std::uint32_t, 8> h_{
                0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
            };
            std::array<std::uint8_t, 64> block_{};
            std::size_t block_len_ = 0;
            std::uint64_t total_bits_ = 0;

            static constexpr auto rotr(std::uint32_t x, unsigned n) noexcept -> std::uint32_t {
                return (x >> n) | (x << (32u - n));
            }

            auto compress(std::uint8_t const* p) noexcept -> void {
                std::array<std::uint32_t, 64> w{};
                for (std::size_t i = 0; i < 16; ++i) {
                    w[i] = (static_cast<std::uint32_t>(p[i * 4]) << 24)
                         | (static_cast<std::uint32_t>(p[i * 4 + 1]) << 16)
                         | (static_cast<std::uint32_t>(p[i * 4 + 2]) << 8)
                         | static_cast<std::uint32_t>(p[i * 4 + 3]);
                }
                for (std::size_t i = 16; i < 64; ++i) {
                    std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
                    std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
                    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
                }
                auto [a, b, c, d, e, f, g, h] = h_;
                for (std::size_t i = 0; i < 64; ++i) {
                    std::uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
                    std::uint32_t ch = (e & f) ^ ((~e) & g);
                    std::uint32_t t1 = h + s1 + ch + kSha256K[i] + w[i];
                    std::uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
                    std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
                    std::uint32_t t2 = s0 + maj;
                    h = g; g = f; f = e; e = d + t1;
                    d = c; c = b; b = a; a = t1 + t2;
                }
                h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d;
                h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += h;
            }

        public:
            auto update(std::uint8_t const* data, std::size_t len) noexcept -> void {
                total_bits_ += static_cast<std::uint64_t>(len) * 8ULL;
                std::size_t pos = 0;
                if (block_len_ > 0) {
                    std::size_t take = std::min(64 - block_len_, len);
                    std::memcpy(block_.data() + block_len_, data, take);
                    block_len_ += take;
                    pos += take;
                    if (block_len_ == 64) { compress(block_.data()); block_len_ = 0; }
                }
                while (len - pos >= 64) { compress(data + pos); pos += 64; }
                if (pos < len) {
                    std::size_t rem = len - pos;
                    std::memcpy(block_.data(), data + pos, rem);
                    block_len_ = rem;
                }
            }

            auto finalize_hex() -> std::string {
                block_[block_len_++] = 0x80u;
                if (block_len_ > 56) {
                    std::fill(block_.begin() + static_cast<std::ptrdiff_t>(block_len_), block_.end(), std::uint8_t{0});
                    compress(block_.data());
                    block_len_ = 0;
                }
                std::fill(block_.begin() + static_cast<std::ptrdiff_t>(block_len_), block_.begin() + 56, std::uint8_t{0});
                for (int i = 0; i < 8; ++i) {
                    block_[56 + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>((total_bits_ >> (56 - i * 8)) & 0xFFu);
                }
                compress(block_.data());
                static constexpr char kHex[] = "0123456789abcdef";
                std::string out(64, '0');
                for (std::size_t i = 0; i < 8; ++i) {
                    for (int n = 0; n < 8; ++n) {
                        out[i * 8 + static_cast<std::size_t>(n)] = kHex[(h_[i] >> (28 - n * 4)) & 0xFu];
                    }
                }
                return out;
            }
        };

        auto has_any_control_char(std::string_view sv) noexcept -> bool {
            for (unsigned char c : sv) if (c < 0x20 || c == 0x7F) return true;
            return false;
        }

        auto sanitize_single_line(std::string_view sv, std::size_t max_len) -> std::string {
            std::string out;
            out.reserve(std::min(sv.size(), max_len));
            for (unsigned char c : sv) {
                if (out.size() >= max_len) break;
                out.push_back((c < 0x20 || c == 0x7F) ? ' ' : static_cast<char>(c));
            }
            while (!out.empty() && out.back() == ' ') out.pop_back();
            return out;
        }

        auto is_safe_label(std::string_view label) noexcept -> bool {
            if (label.empty() || label.size() > 128) return false;
            for (char c : label) {
                bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                          (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
                if (!ok) return false;
            }
            return true;
        }
    }

    auto parse_tun_helper_request(std::string_view raw) noexcept -> std::optional<TunHelperCommand> {
        if (raw.empty() || raw.size() > kTunHelperMaxRequestBytes) return std::nullopt;
        if (has_any_control_char(raw)) return std::nullopt;
        if (raw == "PING") return TunHelperCommand::ping;
        if (raw == "STATUS") return TunHelperCommand::status;
        if (raw == "START") return TunHelperCommand::start;
        if (raw == "STOP") return TunHelperCommand::stop;
        return std::nullopt;
    }

    auto format_tun_helper_request(TunHelperCommand cmd) noexcept -> std::string_view {
        switch (cmd) {
        case TunHelperCommand::ping: return "PING";
        case TunHelperCommand::status: return "STATUS";
        case TunHelperCommand::start: return "START";
        case TunHelperCommand::stop: return "STOP";
        }
        return "PING";
    }

    auto format_tun_helper_reply(TunHelperReply const& reply) -> std::string {
        if (!reply.ok) {
            auto msg = sanitize_single_line(reply.detail.empty() ? "helper error" : reply.detail, kTunHelperMaxReplyBytes - 5);
            return "ERR " + msg;
        }
        if (reply.running) {
            return std::format("OK RUNNING {}", reply.pid);
        }
        if (reply.detail.empty()) return "OK STOPPED";
        auto msg = sanitize_single_line(reply.detail, kTunHelperMaxReplyBytes - 4);
        return "OK " + msg;
    }

    auto parse_tun_helper_reply(std::string_view raw) -> TunHelperReply {
        TunHelperReply out{};
        if (raw.empty() || raw.size() > kTunHelperMaxReplyBytes) {
            out.detail = "empty or oversized helper reply";
            return out;
        }
        while (!raw.empty() && (raw.back() == '\n' || raw.back() == '\r')) raw.remove_suffix(1);
        if (raw.empty() || has_any_control_char(raw)) {
            out.detail = "malformed helper reply";
            return out;
        }
        if (raw == "OK STOPPED") { out.ok = true; out.running = false; out.detail = "STOPPED"; return out; }
        if (raw == "OK PONG") { out.ok = true; out.detail = "PONG"; return out; }
        if (raw.starts_with("OK RUNNING ")) {
            auto pid_sv = raw.substr(11);
            std::uint64_t pid = 0;
            auto [ptr, ec] = std::from_chars(pid_sv.data(), pid_sv.data() + pid_sv.size(), pid, 10);
            if (ec == std::errc{} && ptr == pid_sv.data() + pid_sv.size() && pid > 0) {
                out.ok = true; out.running = true; out.pid = pid; out.detail = "RUNNING";
                return out;
            }
            out.detail = "invalid PID in helper reply";
            return out;
        }
        if (raw.starts_with("OK ")) {
            out.ok = true;
            out.detail = std::string(raw.substr(3));
            return out;
        }
        if (raw.starts_with("ERR ")) {
            out.ok = false;
            out.detail = std::string(raw.substr(4));
            return out;
        }
        out.detail = "unrecognized helper reply";
        return out;
    }

    auto is_valid_sha256_hex(std::string_view hex) noexcept -> bool {
        if (hex.size() != 64) return false;
        for (char c : hex) {
            bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!ok) return false;
        }
        return true;
    }

    auto sha256_bytes(std::span<std::byte const> data) -> std::string {
        Sha256State st;
        if (!data.empty()) st.update(reinterpret_cast<std::uint8_t const*>(data.data()), data.size());
        return st.finalize_hex();
    }

    auto sha256_bytes(std::string_view data) -> std::string {
        Sha256State st;
        if (!data.empty()) st.update(reinterpret_cast<std::uint8_t const*>(data.data()), data.size());
        return st.finalize_hex();
    }

    auto sha256_file(std::filesystem::path const& path) -> std::expected<std::string, std::string> {
        std::error_code ec;
        if (path.empty() || !std::filesystem::is_regular_file(path, ec)) {
            return std::unexpected("target file does not exist or is not a regular file");
        }
        std::ifstream in(path, std::ios::binary);
        if (!in) return std::unexpected("failed to open target file for SHA-256 verification");
        Sha256State st;
        std::array<std::uint8_t, 65536> buf{};
        while (in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size())) || in.gcount() > 0) {
            st.update(buf.data(), static_cast<std::size_t>(in.gcount()));
            if (in.eof()) break;
        }
        if (in.bad()) return std::unexpected("I/O error reading target file for SHA-256");
        return st.finalize_hex();
    }

    auto validate_windows_sid(std::string_view sid) noexcept -> bool {
        if (sid.size() < 7 || sid.size() > 184 || !sid.starts_with("S-1-")) return false;
        std::string_view rem = sid.substr(4);
        std::size_t parts = 0;
        while (!rem.empty()) {
            auto dash = rem.find('-');
            auto tok = dash == std::string_view::npos ? rem : rem.substr(0, dash);
            if (tok.empty() || tok.size() > 10) return false;
            if (tok.size() > 1 && tok.front() == '0') return false;
            std::uint64_t val = 0;
            auto [ptr, ec] = std::from_chars(tok.data(), tok.data() + tok.size(), val, 10);
            if (ec != std::errc{} || ptr != tok.data() + tok.size()) return false;
            if (parts == 0) {
                if (val > 281474976710655ULL) return false;
            } else if (val > 0xFFFFFFFFULL) {
                return false;
            }
            ++parts;
            if (dash == std::string_view::npos) break;
            rem = rem.substr(dash + 1);
            if (rem.empty()) return false;
        }
        return parts >= 2 && parts <= 16;
    }

    auto build_win_helper_pipe_sddl(std::string_view owner_sid) -> std::expected<std::string, std::string> {
        if (!validate_windows_sid(owner_sid)) return std::unexpected("invalid Windows owner SID");
        return std::format("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{})", owner_sid);
    }

    auto escape_xml_text(std::string_view text) -> std::string {
        std::string out;
        out.reserve(text.size() + 16);
        for (char c : text) {
            switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&apos;"; break;
            default: out.push_back(c); break;
            }
        }
        return out;
    }

    auto render_macos_tun_helper_plist(
        std::string_view helper_binary,
        std::string_view label,
        std::string_view log_path) -> std::expected<std::string, std::string> {
        if (helper_binary.empty() || helper_binary.front() != '/' || has_any_control_char(helper_binary)) {
            return std::unexpected("helper binary must be an absolute path without control characters");
        }
        if (!is_safe_label(label)) return std::unexpected("invalid LaunchDaemon label");
        if (log_path.empty() || log_path.front() != '/' || has_any_control_char(log_path)) {
            return std::unexpected("log path must be an absolute path without control characters");
        }
        auto const esc_label = escape_xml_text(label);
        auto const esc_bin = escape_xml_text(helper_binary);
        auto const esc_log = escape_xml_text(log_path);
        return std::format(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
            "<plist version=\"1.0\">\n"
            "<dict>\n"
            "    <key>Label</key>\n"
            "    <string>{}</string>\n"
            "    <key>ProgramArguments</key>\n"
            "    <array>\n"
            "        <string>{}</string>\n"
            "        <string>--daemon</string>\n"
            "    </array>\n"
            "    <key>RunAtLoad</key>\n"
            "    <true/>\n"
            "    <key>KeepAlive</key>\n"
            "    <true/>\n"
            "    <key>StandardOutPath</key>\n"
            "    <string>{}</string>\n"
            "    <key>StandardErrorPath</key>\n"
            "    <string>{}</string>\n"
            "</dict>\n"
            "</plist>\n",
            esc_label, esc_bin, esc_log, esc_log);
    }

    auto quote_posix_sh_arg(std::string_view arg) -> std::expected<std::string, std::string> {
        if (arg.contains('\0')) return std::unexpected("shell argument contains embedded NUL byte");
        std::string out;
        out.reserve(arg.size() + 8);
        out.push_back('\'');
        for (char c : arg) {
            if (c == '\'') out += "'\\''";
            else out.push_back(c);
        }
        out.push_back('\'');
        return out;
    }

    auto escape_applescript_string(std::string_view text) -> std::expected<std::string, std::string> {
        if (has_any_control_char(text)) return std::unexpected("AppleScript string contains control characters");
        std::string out;
        out.reserve(text.size() + 8);
        for (char c : text) {
            if (c == '\\' || c == '"') out.push_back('\\');
            out.push_back(c);
        }
        return out;
    }

    auto build_macos_osascript_admin_script(std::span<std::string_view const> argv)
        -> std::expected<std::string, std::string> {
        if (argv.empty()) return std::unexpected("osascript argv cannot be empty");
        std::string shell_cmd;
        for (std::size_t i = 0; i < argv.size(); ++i) {
            if (has_any_control_char(argv[i])) return std::unexpected("argv element contains control characters");
            auto quoted = quote_posix_sh_arg(argv[i]);
            if (!quoted) return std::unexpected(quoted.error());
            if (i > 0) shell_cmd.push_back(' ');
            shell_cmd += *quoted;
        }
        auto escaped = escape_applescript_string(shell_cmd);
        if (!escaped) return std::unexpected(escaped.error());
        return std::format("do shell script \"{}\" with administrator privileges", *escaped);
    }

    auto serialize_tun_helper_config(TunHelperPinnedConfig const& cfg) -> std::expected<std::string, std::string> {
        if (cfg.binary.empty() || cfg.config.empty() || cfg.owner.empty()) {
            return std::unexpected("binary, config, and owner are required in pinned config");
        }
        if (!is_valid_sha256_hex(cfg.sha256)) return std::unexpected("invalid SHA-256 hex digest");
        if (has_any_control_char(cfg.binary) || has_any_control_char(cfg.config) ||
            has_any_control_char(cfg.workdir) || has_any_control_char(cfg.owner) ||
            has_any_control_char(cfg.staged_binary)) {
            return std::unexpected("pinned config fields cannot contain control characters");
        }
        std::string lower_sha(cfg.sha256);
        for (char& c : lower_sha) if (c >= 'A' && c <= 'F') c = static_cast<char>(c - 'A' + 'a');
        auto out = std::format("binary={}\nsha256={}\nconfig={}\nworkdir={}\nowner={}\n",
            cfg.binary, lower_sha, cfg.config, cfg.workdir, cfg.owner);
        if (!cfg.staged_binary.empty()) out += std::format("staged_binary={}\n", cfg.staged_binary);
        return out;
    }

    auto parse_tun_helper_config(std::string_view text) -> std::expected<TunHelperPinnedConfig, std::string> {
        TunHelperPinnedConfig cfg{};
        bool has_bin = false, has_sha = false, has_cfg = false, has_wd = false, has_own = false, has_staged = false;
        while (!text.empty()) {
            auto nl = text.find('\n');
            auto line = nl == std::string_view::npos ? text : text.substr(0, nl);
            text = nl == std::string_view::npos ? std::string_view{} : text.substr(nl + 1);
            if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
            if (line.empty()) continue;
            if (has_any_control_char(line)) return std::unexpected("control character in pinned config");
            auto eq = line.find('=');
            if (eq == std::string_view::npos || eq == 0) return std::unexpected("malformed line in pinned config");
            auto key = line.substr(0, eq);
            auto val = line.substr(eq + 1);
            if (key == "binary") { if (has_bin) return std::unexpected("duplicate binary key"); cfg.binary = std::string(val); has_bin = true; }
            else if (key == "sha256") {
                if (has_sha) return std::unexpected("duplicate sha256 key");
                if (!is_valid_sha256_hex(val)) return std::unexpected("invalid sha256 value");
                cfg.sha256 = std::string(val);
                for (char& c : cfg.sha256) if (c >= 'A' && c <= 'F') c = static_cast<char>(c - 'A' + 'a');
                has_sha = true;
            }
            else if (key == "config") { if (has_cfg) return std::unexpected("duplicate config key"); cfg.config = std::string(val); has_cfg = true; }
            else if (key == "workdir") { if (has_wd) return std::unexpected("duplicate workdir key"); cfg.workdir = std::string(val); has_wd = true; }
            else if (key == "owner") { if (has_own) return std::unexpected("duplicate owner key"); cfg.owner = std::string(val); has_own = true; }
            else if (key == "staged_binary") { if (has_staged) return std::unexpected("duplicate staged_binary key"); cfg.staged_binary = std::string(val); has_staged = true; }
            else return std::unexpected("unknown key in pinned config");
        }
        if (!has_bin || !has_sha || !has_cfg || !has_own || cfg.binary.empty() || cfg.config.empty() || cfg.owner.empty()) {
            return std::unexpected("missing required field in pinned config");
        }
        return cfg;
    }
}
