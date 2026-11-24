module;
#include <cerrno>

export module platform.dbus_wire;
import std;

export namespace platform::dbus {
    inline constexpr std::uint8_t kLittleEndian = 'l';
    inline constexpr std::uint8_t kBigEndian = 'B';
    inline constexpr std::uint8_t kProtocolVersion = 1;
    inline constexpr std::uint8_t kTypeMethodCall = 1, kTypeMethodReturn = 2, kTypeError = 3, kTypeSignal = 4;
    inline constexpr std::uint8_t kFieldPath = 1, kFieldInterface = 2, kFieldMember = 3, kFieldErrorName = 4;
    inline constexpr std::uint8_t kFieldReplySerial = 5, kFieldDestination = 6, kFieldSender = 7;
    inline constexpr std::uint8_t kFieldSignature = 8, kFieldUnixFds = 9;
    inline constexpr std::size_t kMaxMessageBytes = 65536, kMaxRequestBytes = 8192;
    inline constexpr unsigned kMaxDepth = 32;

    [[nodiscard]] constexpr auto align_up(std::size_t n, std::size_t a) noexcept -> std::size_t {
        return (n + a - 1) & ~(a - 1);
    }

    [[nodiscard]] constexpr auto type_alignment(char c) noexcept -> std::size_t {
        switch (c) {
            case 'y': case 'g': case 'v': return 1;
            case 'n': case 'q': return 2;
            case 'b': case 'i': case 'u': case 'h': case 's': case 'o': case 'a': return 4;
            case 'x': case 't': case 'd': case '(': case '{': return 8;
            default: return 0;
        }
    }

    [[nodiscard]] constexpr auto is_basic_type(char c) noexcept -> bool {
        switch (c) {
            case 'y': case 'b': case 'n': case 'q': case 'i': case 'u':
            case 'x': case 't': case 'd': case 's': case 'o': case 'g': case 'h': return true;
            default: return false;
        }
    }

    [[nodiscard]] constexpr auto complete_type_len(std::string_view sig, unsigned depth = 0) noexcept -> std::size_t {
        if (sig.empty() || depth > kMaxDepth) return 0;
        char const head = sig.front();
        if (is_basic_type(head) || head == 'v') return 1;
        if (head == 'a') {
            auto elem = complete_type_len(sig.substr(1), depth + 1);
            return elem ? 1 + elem : 0;
        }
        if (head == '(' || head == '{') {
            char const close = head == '(' ? ')' : '}';
            std::size_t pos = 1;
            unsigned fields = 0;
            while (pos < sig.size() && sig[pos] != close) {
                auto part = complete_type_len(sig.substr(pos), depth + 1);
                if (!part) return 0;
                pos += part;
                ++fields;
            }
            if (pos >= sig.size() || sig[pos] != close) return 0;
            if ((head == '(' && !fields) || (head == '{' && (fields != 2 || !is_basic_type(sig[1])))) return 0;
            return pos + 1;
        }
        return 0;
    }

    template<class T>
    [[nodiscard]] inline auto read_raw_uint(std::uint8_t const* p, bool big_endian) noexcept -> T {
        T v = 0;
        for (std::size_t i = 0; i < sizeof(T); ++i) {
            if (big_endian) v = static_cast<T>((v << 8) | p[i]);
            else v = static_cast<T>(v | (T(p[i]) << (i * 8)));
        }
        return v;
    }

    struct BodyWriter {
        std::span<std::uint8_t> buf;
        std::size_t pos = 0;
        bool ok = true;
        struct ArrayScope { std::size_t len_pos = 0, start_pos = 0; };

        auto align(std::size_t a) noexcept -> bool {
            if (!ok) return false;
            auto const target = align_up(pos, a);
            if (target > buf.size()) { ok = false; return false; }
            while (pos < target) buf[pos++] = 0;
            return true;
        }

        template<class T> auto write_uint(T v) noexcept -> bool {
            if (!align(sizeof(T)) || buf.size() - pos < sizeof(T)) { ok = false; return false; }
            for (std::size_t i = 0; i < sizeof(T); ++i) {
                buf[pos++] = static_cast<std::uint8_t>((v >> (i * 8)) & 0xFFu);
            }
            return true;
        }

        auto write_u8(std::uint8_t v) noexcept -> bool { return write_uint(v); }
        auto write_u16(std::uint16_t v) noexcept -> bool { return write_uint(v); }
        auto write_u32(std::uint32_t v) noexcept -> bool { return write_uint(v); }
        auto write_i32(std::int32_t v) noexcept -> bool { return write_uint(static_cast<std::uint32_t>(v)); }
        auto write_bool(bool v) noexcept -> bool { return write_uint(std::uint32_t{v ? 1u : 0u}); }

        auto write_string(std::string_view s) noexcept -> bool {
            if (s.find('\0') != s.npos || s.size() > 0xFFFFFFFFu) { ok = false; return false; }
            if (!write_u32(static_cast<std::uint32_t>(s.size())) || buf.size() - pos < s.size() + 1) {
                ok = false;
                return false;
            }
            if (!s.empty()) std::memcpy(buf.data() + pos, s.data(), s.size());
            pos += s.size();
            buf[pos++] = 0;
            return true;
        }

        auto write_signature(std::string_view s) noexcept -> bool {
            if (s.size() > 255 || s.find('\0') != s.npos || buf.size() - pos < 2 + s.size()) {
                ok = false;
                return false;
            }
            buf[pos++] = static_cast<std::uint8_t>(s.size());
            if (!s.empty()) std::memcpy(buf.data() + pos, s.data(), s.size());
            pos += s.size();
            buf[pos++] = 0;
            return true;
        }

        auto write_byte_array(std::span<std::uint8_t const> bytes) noexcept -> bool {
            if (bytes.size() > 0xFFFFFFFFu || !write_u32(static_cast<std::uint32_t>(bytes.size())) ||
                buf.size() - pos < bytes.size()) {
                ok = false;
                return false;
            }
            if (!bytes.empty()) std::memcpy(buf.data() + pos, bytes.data(), bytes.size());
            pos += bytes.size();
            return true;
        }

        auto begin_array(std::size_t elem_align, ArrayScope& scope) noexcept -> bool {
            if (!elem_align || !align(4)) { ok = false; return false; }
            scope.len_pos = pos;
            if (!write_u32(0) || !align(elem_align)) return false;
            scope.start_pos = pos;
            return true;
        }

        auto end_array(ArrayScope const& scope) noexcept -> bool {
            if (!ok || pos < scope.start_pos || scope.len_pos + 4 > buf.size()) { ok = false; return false; }
            auto const byte_len = static_cast<std::uint32_t>(pos - scope.start_pos);
            for (unsigned i = 0; i < 4; ++i) buf[scope.len_pos + i] = static_cast<std::uint8_t>((byte_len >> (i * 8)) & 0xFFu);
            return true;
        }

        auto begin_struct() noexcept -> bool { return align(8); }
    };

    struct Request {
        std::array<char, 64> destination{};
        std::array<char, 128> path{};
        std::array<char, 64> interface{};
        std::array<char, 64> member{};
        std::array<char, 64> signature{};
        std::size_t sig_len = 0, body_len = 0;
        std::array<std::uint8_t, 4096> body{};
        bool valid = false;

        template<std::size_t N>
        static auto copy_text(std::string_view src, std::array<char, N>& dst) noexcept -> bool {
            if (src.size() >= N || src.find('\0') != src.npos) return false;
            dst.fill(0);
            if (!src.empty()) std::memcpy(dst.data(), src.data(), src.size());
            return true;
        }

        auto init(std::string_view dst, std::string_view obj_path,
            std::string_view iface, std::string_view mem) noexcept -> bool {
            valid = false; body_len = 0; sig_len = 0; signature.fill(0);
            if (obj_path.empty() || obj_path.front() != '/' || mem.empty()) return false;
            valid = copy_text(dst, destination) && copy_text(obj_path, path) &&
                    copy_text(iface, interface) && copy_text(mem, member);
            return valid;
        }

        auto append_sig(std::string_view part) noexcept -> bool {
            if (!valid || sig_len + part.size() >= signature.size() || part.find('\0') != part.npos) return false;
            std::memcpy(signature.data() + sig_len, part.data(), part.size());
            sig_len += part.size();
            signature[sig_len] = 0;
            return true;
        }

        auto body_writer() noexcept -> BodyWriter { return BodyWriter{body, body_len, valid}; }
        auto commit_body(BodyWriter const& w, std::string_view sig) noexcept -> bool {
            if (!valid || !w.ok || !append_sig(sig)) return false;
            body_len = w.pos;
            return true;
        }
        auto append_string(std::string_view s) noexcept -> bool {
            auto w = body_writer(); return w.write_string(s) && commit_body(w, "s");
        }
        auto append_i32(std::int32_t v) noexcept -> bool {
            auto w = body_writer(); return w.write_i32(v) && commit_body(w, "i");
        }

        [[nodiscard]] auto encode(std::uint32_t serial, std::span<std::uint8_t> out) const noexcept -> std::size_t {
            if (!valid || !serial || out.size() < 16) return 0;
            out[0] = kLittleEndian; out[1] = kTypeMethodCall; out[2] = 0; out[3] = kProtocolVersion;
            BodyWriter hw{out, 4, true};
            if (!hw.write_u32(static_cast<std::uint32_t>(body_len)) || !hw.write_u32(serial)) return 0;
            BodyWriter::ArrayScope fields;
            if (!hw.begin_array(8, fields)) return 0;
            auto add_field = [&](std::uint8_t code, char tc, std::string_view val) noexcept -> bool {
                char sb[2]{tc, 0};
                return hw.align(8) && hw.write_u8(code) && hw.write_signature({sb, 1}) &&
                       (tc == 'g' ? hw.write_signature(val) : hw.write_string(val));
            };
            if (!add_field(kFieldPath, 'o', path.data())) return 0;
            if (interface[0] && !add_field(kFieldInterface, 's', interface.data())) return 0;
            if (!add_field(kFieldMember, 's', member.data())) return 0;
            if (destination[0] && !add_field(kFieldDestination, 's', destination.data())) return 0;
            if (sig_len && !add_field(kFieldSignature, 'g', {signature.data(), sig_len})) return 0;
            if (!hw.end_array(fields) || !hw.align(8)) return 0;
            if (hw.pos > kMaxRequestBytes || body_len > kMaxRequestBytes - hw.pos || hw.pos + body_len > out.size()) return 0;
            if (body_len) std::memcpy(out.data() + hw.pos, body.data(), body_len);
            return hw.pos + body_len;
        }
    };

    struct Reader {
        std::span<std::uint8_t const> buf;
        std::size_t pos = 0, end = 0;
        bool big_endian = false;

        [[nodiscard]] auto at_end() const noexcept -> bool { return pos == end; }
        auto align(std::size_t a) noexcept -> bool {
            auto target = align_up(pos, a);
            if (target > end) return false;
            pos = target;
            return true;
        }
        template<class T> auto read_uint(T& out) noexcept -> bool {
            if (!align(sizeof(T)) || end - pos < sizeof(T)) return false;
            out = read_raw_uint<T>(buf.data() + pos, big_endian);
            pos += sizeof(T);
            return true;
        }
        auto read_u8(std::uint8_t& out) noexcept -> bool { return read_uint(out); }
        auto read_u16(std::uint16_t& out) noexcept -> bool { return read_uint(out); }
        auto read_u32(std::uint32_t& out) noexcept -> bool { return read_uint(out); }
        auto read_u64(std::uint64_t& out) noexcept -> bool { return read_uint(out); }
        auto read_i32(std::int32_t& out) noexcept -> bool {
            std::uint32_t raw = 0;
            if (!read_uint(raw)) return false;
            out = static_cast<std::int32_t>(raw);
            return true;
        }
        auto read_bool(bool& out) noexcept -> bool {
            std::uint32_t raw = 0;
            if (!read_uint(raw) || raw > 1) return false;
            out = raw == 1;
            return true;
        }
        template<class Len> auto read_cstr(std::string_view& out) noexcept -> bool {
            Len len = 0;
            if (!read_uint(len) || end - pos < std::size_t{len} + 1) return false;
            auto const* ptr = reinterpret_cast<char const*>(buf.data() + pos);
            std::string_view sv(ptr, len);
            if (ptr[len] != '\0' || sv.find('\0') != sv.npos) return false;
            pos += std::size_t{len} + 1;
            out = sv;
            return true;
        }
        auto read_string(std::string_view& out) noexcept -> bool { return read_cstr<std::uint32_t>(out); }
        auto read_object_path(std::string_view& out) noexcept -> bool { return read_cstr<std::uint32_t>(out) && !out.empty() && out.front() == '/'; }
        auto read_signature(std::string_view& out) noexcept -> bool { return read_cstr<std::uint8_t>(out); }
        auto read_byte_array(std::span<std::uint8_t const>& out) noexcept -> bool {
            std::uint32_t len = 0;
            if (!read_u32(len) || end - pos < len) return false;
            out = buf.subspan(pos, len);
            pos += len;
            return true;
        }
        auto enter_array(std::size_t elem_align, std::size_t& array_end) noexcept -> bool {
            std::uint32_t byte_len = 0;
            if (!elem_align || !read_u32(byte_len) || !align(elem_align) || byte_len > end - pos) return false;
            array_end = pos + byte_len;
            return true;
        }
        auto enter_struct() noexcept -> bool { return align(8); }

        auto skip_variant(unsigned depth = 0) noexcept -> bool {
            std::string_view inner;
            if (depth > kMaxDepth || !read_signature(inner) || inner.empty()) return false;
            return complete_type_len(inner, depth + 1) == inner.size() && skip_type(inner, depth + 1) && inner.empty();
        }
        auto skip_type(std::string_view& sig, unsigned depth = 0) noexcept -> bool {
            if (sig.empty() || depth > kMaxDepth) return false;
            switch (char const head = sig.front()) {
                case 'y': { std::uint8_t v = 0; sig.remove_prefix(1); return read_u8(v); }
                case 'b': { bool v = false; sig.remove_prefix(1); return read_bool(v); }
                case 'n': case 'q': { std::uint16_t v = 0; sig.remove_prefix(1); return read_u16(v); }
                case 'i': case 'u': case 'h': { std::uint32_t v = 0; sig.remove_prefix(1); return read_u32(v); }
                case 'x': case 't': case 'd': { std::uint64_t v = 0; sig.remove_prefix(1); return read_u64(v); }
                case 's': { std::string_view v; sig.remove_prefix(1); return read_string(v); }
                case 'o': { std::string_view v; sig.remove_prefix(1); return read_object_path(v); }
                case 'g': { std::string_view v; sig.remove_prefix(1); return read_signature(v); }
                case 'v': { sig.remove_prefix(1); return skip_variant(depth + 1); }
                case '(': case '{': {
                    auto const len = complete_type_len(sig, depth);
                    if (len < 3 || !align(8)) return false;
                    auto inside = sig.substr(1, len - 2);
                    sig.remove_prefix(len);
                    while (!inside.empty()) if (!skip_type(inside, depth + 1)) return false;
                    return true;
                }
                case 'a': {
                    auto const elen = complete_type_len(sig.substr(1), depth + 1);
                    if (!elen) return false;
                    auto const esig = sig.substr(1, elen);
                    sig.remove_prefix(1 + elen);
                    if (esig == "y") { std::span<std::uint8_t const> b; return read_byte_array(b); }
                    std::size_t arr_end = 0;
                    if (!enter_array(type_alignment(esig.front()), arr_end)) return false;
                    auto const saved = std::exchange(end, arr_end);
                    bool ok = true;
                    while (ok && pos < arr_end) {
                        auto item = esig;
                        ok = skip_type(item, depth + 1) && item.empty();
                    }
                    ok = ok && pos == arr_end;
                    end = saved;
                    return ok;
                }
                default: return false;
            }
        }
    };

    struct Header {
        bool big_endian = false;
        std::uint8_t type = 0;
        std::uint32_t body_len = 0, serial = 0, reply_serial = 0;
        std::size_t body_offset = 0;
        std::string_view path, interface, member, error_name, destination, sender, signature;
    };

    enum class FrameStatus { incomplete, ok, too_large, invalid };

    [[nodiscard]] inline auto peek_frame_size(std::span<std::uint8_t const> buf, std::size_t& total_len) noexcept
        -> FrameStatus {
        if (buf.size() < 16) return FrameStatus::incomplete;
        if ((buf[0] != kLittleEndian && buf[0] != kBigEndian) || buf[3] != kProtocolVersion) return FrameStatus::invalid;
        bool const be = buf[0] == kBigEndian;
        auto const body_len = read_raw_uint<std::uint32_t>(buf.data() + 4, be);
        auto const serial = read_raw_uint<std::uint32_t>(buf.data() + 8, be);
        auto const fields_len = read_raw_uint<std::uint32_t>(buf.data() + 12, be);
        if (!serial) return FrameStatus::invalid;
        if (fields_len > kMaxMessageBytes - 16 || body_len > kMaxMessageBytes) return FrameStatus::too_large;
        auto const body_offset = align_up(16 + std::size_t{fields_len}, 8);
        if (body_offset > kMaxMessageBytes || std::size_t{body_len} > kMaxMessageBytes - body_offset) return FrameStatus::too_large;
        total_len = body_offset + std::size_t{body_len};
        return buf.size() >= total_len ? FrameStatus::ok : FrameStatus::incomplete;
    }

    [[nodiscard]] inline auto parse_header(std::span<std::uint8_t const> frame, Header& out) noexcept -> bool {
        if (frame.size() < 16 || (frame[0] != kLittleEndian && frame[0] != kBigEndian) || frame[3] != kProtocolVersion) return false;
        out = {};
        out.big_endian = frame[0] == kBigEndian;
        out.type = frame[1];
        out.body_len = read_raw_uint<std::uint32_t>(frame.data() + 4, out.big_endian);
        out.serial = read_raw_uint<std::uint32_t>(frame.data() + 8, out.big_endian);
        auto const fields_len = read_raw_uint<std::uint32_t>(frame.data() + 12, out.big_endian);
        if (!out.serial || out.type < kTypeMethodCall || out.type > kTypeSignal) return false;
        auto const fields_end = 16 + std::size_t{fields_len};
        auto const body_offset = align_up(fields_end, 8);
        if (fields_end > frame.size() || body_offset > frame.size() || std::size_t{out.body_len} != frame.size() - body_offset) return false;
        out.body_offset = body_offset;
        Reader r{frame, 16, fields_end, out.big_endian};
        std::uint32_t unix_fds = 0;
        while (r.pos < fields_end) {
            std::uint8_t code = 0;
            std::string_view vsig;
            if (!r.align(8) || r.pos >= fields_end || !r.read_u8(code) || !r.read_signature(vsig) ||
                vsig.empty() || complete_type_len(vsig) != vsig.size()) return false;
            bool ok = false;
            switch (code) {
                case kFieldPath: ok = (vsig == "o") && r.read_object_path(out.path); break;
                case kFieldInterface: ok = (vsig == "s") && r.read_string(out.interface); break;
                case kFieldMember: ok = (vsig == "s") && r.read_string(out.member); break;
                case kFieldErrorName: ok = (vsig == "s") && r.read_string(out.error_name); break;
                case kFieldReplySerial: ok = (vsig == "u") && r.read_u32(out.reply_serial); break;
                case kFieldDestination: ok = (vsig == "s") && r.read_string(out.destination); break;
                case kFieldSender: ok = (vsig == "s") && r.read_string(out.sender); break;
                case kFieldSignature: ok = (vsig == "g") && r.read_signature(out.signature); break;
                case kFieldUnixFds: ok = (vsig == "u") && r.read_u32(unix_fds); break;
                default: ok = r.skip_type(vsig); break;
            }
            if (!ok || r.pos > fields_end) return false;
        }
        return r.pos == fields_end && unix_fds == 0;
    }

    [[nodiscard]] inline auto map_error_name(std::string_view name) noexcept -> int {
        using Entry = std::pair<std::string_view, int>;
        constexpr std::array kErrors{
            Entry{"org.freedesktop.resolve1.NoSuchLink", ENXIO},
            Entry{"org.freedesktop.resolve1.LinkBusy", EBUSY},
            Entry{"org.freedesktop.DBus.Error.UnknownObject", ENOENT},
            Entry{"org.freedesktop.DBus.Error.AccessDenied", EACCES},
            Entry{"org.freedesktop.DBus.Error.InvalidArgs", EINVAL},
            Entry{"org.freedesktop.DBus.Error.NoReply", ETIMEDOUT},
            Entry{"org.freedesktop.DBus.Error.Timeout", ETIMEDOUT},
            Entry{"org.freedesktop.DBus.Error.Disconnected", ECONNRESET},
            Entry{"org.freedesktop.DBus.Error.NoMemory", ENOMEM},
            Entry{"org.freedesktop.DBus.Error.ServiceUnknown", EHOSTUNREACH},
            Entry{"org.freedesktop.DBus.Error.NameHasNoOwner", EHOSTUNREACH},
        };
        for (auto const& [k, v] : kErrors) if (name == k) return v;
        if (name.starts_with("System.Error.")) {
            auto const e = name.substr(13);
            constexpr std::array kSys{
                Entry{"ENXIO", ENXIO}, Entry{"ENODEV", ENODEV}, Entry{"EINVAL", EINVAL}, Entry{"EPERM", EPERM},
                Entry{"EACCES", EACCES}, Entry{"EBUSY", EBUSY}, Entry{"ENOENT", ENOENT}, Entry{"ENOMEM", ENOMEM},
                Entry{"EAGAIN", EAGAIN}, Entry{"EWOULDBLOCK", EAGAIN}, Entry{"ETIMEDOUT", ETIMEDOUT},
            };
            for (auto const& [k, v] : kSys) if (e == k) return v;
        }
        return EIO;
    }
}
