module openvpn.wire;
import std;
import crypto;
import encoding.endian;
import platform.ip_address;

namespace openvpn {
    namespace {
        auto write_be16(std::vector<std::uint8_t>& out, std::uint16_t v) -> void { encoding::append_be16(out, v); }
        auto write_be32(std::vector<std::uint8_t>& out, std::uint32_t v) -> void { encoding::append_be32(out, v); }
        auto write_be64(std::vector<std::uint8_t>& out, std::uint64_t v) -> void { encoding::append_be64(out, v); }
        [[nodiscard]] auto read_be16(std::span<std::uint8_t const> s) noexcept -> std::uint16_t { return encoding::read_be16(s.first<2>()); }
        [[nodiscard]] auto read_be32(std::span<std::uint8_t const> s) noexcept -> std::uint32_t { return encoding::read_be32(s.first<4>()); }
        [[nodiscard]] auto read_be64(std::span<std::uint8_t const> s) noexcept -> std::uint64_t { return encoding::read_be64(s.first<8>()); }

        [[nodiscard]] auto valid_control_opcode(std::uint8_t raw) noexcept -> std::optional<Opcode> {
            switch (raw) {
            case 3: return Opcode::control_soft_reset_v1;
            case 4: return Opcode::control_v1;
            case 5: return Opcode::ack_v1;
            case 7: return Opcode::control_hard_reset_client_v2;
            case 8: return Opcode::control_hard_reset_server_v2;
            default: return std::nullopt;
            }
        }

        auto write_km_string(std::vector<std::uint8_t>& out, std::string_view s) -> std::expected<void, std::string> {
            if (s.empty()) { write_be16(out, 0); return {}; }
            if (s.size() > 65534) return std::unexpected("OpenVPN key-method2 string exceeds 65534 bytes");
            write_be16(out, static_cast<std::uint16_t>(s.size() + 1));
            out.insert(out.end(), s.begin(), s.end());
            out.push_back(0);
            return {};
        }

        auto read_km_string(std::span<std::uint8_t const> wire, std::size_t& off) -> std::expected<std::string, std::string> {
            if (wire.size() - off < 2) return std::unexpected("truncated OpenVPN key-method2 string length");
            std::size_t n = read_be16(wire.subspan(off, 2));
            off += 2;
            if (wire.size() - off < n) return std::unexpected("truncated OpenVPN key-method2 string payload");
            std::string s(reinterpret_cast<char const*>(wire.data() + off), n);
            off += n;
            while (!s.empty() && s.back() == '\0') s.pop_back();
            return s;
        }

        auto hmac_md5(std::span<std::uint8_t const> key, std::span<std::uint8_t const> msg)
            -> std::expected<std::array<std::uint8_t, 16>, std::string> {
            std::array<std::uint8_t, 64> k0{};
            std::vector<std::uint8_t> inner_in(64 + msg.size()), outer_in(64 + 16);
            struct Wipe {
                std::array<std::uint8_t, 64>& k; std::vector<std::uint8_t>& in; std::vector<std::uint8_t>& out;
                ~Wipe() { crypto::cleanse(k); crypto::cleanse(in); crypto::cleanse(out); }
            } wipe{k0, inner_in, outer_in};
            if (key.size() > 64) {
                auto h = crypto::md5_fingerprint(key);
                if (!h) return std::unexpected("md5 key digest failed");
                std::ranges::copy(*h, k0.begin());
                crypto::cleanse(*h);
            } else {
                std::ranges::copy(key, k0.begin());
            }
            for (std::size_t i = 0; i < 64; ++i) {
                inner_in[i] = static_cast<std::uint8_t>(k0[i] ^ 0x36u);
                outer_in[i] = static_cast<std::uint8_t>(k0[i] ^ 0x5cu);
            }
            std::ranges::copy(msg, inner_in.begin() + 64);
            auto inner = crypto::md5_fingerprint(inner_in);
            if (!inner) return std::unexpected("hmac_md5 inner failed");
            std::ranges::copy(*inner, outer_in.begin() + 64);
            crypto::cleanse(*inner);
            auto outer = crypto::md5_fingerprint(outer_in);
            if (!outer) return std::unexpected("hmac_md5 outer failed");
            return *outer;
        }

        auto hmac_sha1(std::span<std::uint8_t const> key, std::span<std::uint8_t const> msg)
            -> std::expected<std::array<std::uint8_t, 20>, std::string> {
            auto ctx = crypto::HmacSha1Context::create(key);
            if (!ctx || !ctx->update(msg)) return std::unexpected("hmac_sha1 failed");
            auto snap = ctx->snapshot();
            if (!snap) return std::unexpected("hmac_sha1 snapshot failed");
            return *snap;
        }

        template<class HmacFn>
        auto p_hash(HmacFn&& hmac_fn, std::span<std::uint8_t const> secret, std::span<std::uint8_t const> seed, std::size_t out_len)
            -> std::expected<std::vector<std::uint8_t>, std::string> {
            std::vector<std::uint8_t> a(seed.begin(), seed.end());
            std::vector<std::uint8_t> out;
            out.reserve(out_len + 20);
            std::vector<std::uint8_t> buf;
            bool ok = false;
            struct Wipe {
                std::vector<std::uint8_t>& a; std::vector<std::uint8_t>& b; std::vector<std::uint8_t>& o; bool& ok;
                ~Wipe() { crypto::cleanse(a); crypto::cleanse(b); if (!ok) crypto::cleanse(o); }
            } wipe{a, buf, out, ok};
            while (out.size() < out_len) {
                auto next_a = hmac_fn(secret, a);
                if (!next_a) return std::unexpected(next_a.error());
                a.assign(next_a->begin(), next_a->end());
                crypto::cleanse(*next_a);
                buf.clear();
                buf.insert(buf.end(), a.begin(), a.end());
                buf.insert(buf.end(), seed.begin(), seed.end());
                auto chunk = hmac_fn(secret, buf);
                if (!chunk) return std::unexpected(chunk.error());
                out.insert(out.end(), chunk->begin(), chunk->end());
                crypto::cleanse(*chunk);
            }
            out.resize(out_len);
            ok = true;
            return out;
        }

        auto tls10_prf(std::span<std::uint8_t const> secret, std::string_view label,
                       std::span<std::uint8_t const> seed, std::size_t out_len)
            -> std::expected<std::vector<std::uint8_t>, std::string> {
            std::size_t half = (secret.size() + 1) / 2;
            auto s1 = secret.first(half);
            auto s2 = secret.subspan(secret.size() / 2);
            std::vector<std::uint8_t> lseed;
            lseed.reserve(label.size() + seed.size());
            lseed.insert(lseed.end(), label.begin(), label.end());
            lseed.insert(lseed.end(), seed.begin(), seed.end());
            struct SeedWipe { std::vector<std::uint8_t>& v; ~SeedWipe() { crypto::cleanse(v); } } sw{lseed};
            auto md5_part = p_hash(hmac_md5, s1, lseed, out_len);
            if (!md5_part) return std::unexpected(md5_part.error());
            auto sha1_part = p_hash(hmac_sha1, s2, lseed, out_len);
            if (!sha1_part) { crypto::cleanse(*md5_part); return std::unexpected(sha1_part.error()); }
            for (std::size_t i = 0; i < out_len; ++i) (*md5_part)[i] ^= (*sha1_part)[i];
            crypto::cleanse(*sha1_part);
            return *md5_part;
        }

        auto eq_icase(std::string_view a, std::string_view b) noexcept -> bool {
            if (a.size() != b.size()) return false;
            for (std::size_t i = 0; i < a.size(); ++i) {
                auto ca = static_cast<unsigned char>(a[i]), cb = static_cast<unsigned char>(b[i]);
                if (ca >= 'A' && ca <= 'Z') ca = static_cast<unsigned char>(ca - 'A' + 'a');
                if (cb >= 'A' && cb <= 'Z') cb = static_cast<unsigned char>(cb - 'A' + 'a');
                if (ca != cb) return false;
            }
            return true;
        }

        auto split_ws(std::string_view s) -> std::vector<std::string_view> {
            std::vector<std::string_view> parts;
            std::size_t i = 0;
            while (i < s.size()) {
                while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
                if (i >= s.size()) break;
                std::size_t j = i;
                while (j < s.size() && s[j] != ' ' && s[j] != '\t') ++j;
                parts.push_back(s.substr(i, j - i));
                i = j;
            }
            return parts;
        }
    }

    auto ReplayWindow::check_and_accept(std::uint32_t packet_id) noexcept -> bool {
        if (packet_id == 0) return false;
        if (!initialized_) { initialized_ = true; highest_ = packet_id; bitmap_ = 1ull; return true; }
        if (packet_id > highest_) {
            auto diff = packet_id - highest_;
            bitmap_ = (diff >= 64) ? 1ull : ((bitmap_ << diff) | 1ull);
            highest_ = packet_id;
            return true;
        }
        auto diff = highest_ - packet_id;
        if (diff >= 64) return false;
        auto mask = 1ull << diff;
        if ((bitmap_ & mask) != 0) return false;
        bitmap_ |= mask;
        return true;
    }

    auto encode_control_packet(ControlPacket const& pkt) -> std::expected<std::vector<std::uint8_t>, std::string> {
        if (pkt.opcode == Opcode::data_v2) return std::unexpected("data_v2 cannot use control encoder");
        if (pkt.key_id > 7) return std::unexpected("invalid OpenVPN key_id");
        if (pkt.acks.size() > 255) return std::unexpected("too many OpenVPN ACKs");
        if (pkt.opcode != Opcode::ack_v1 && !pkt.packet_id.has_value())
            return std::unexpected("control packet requires packet_id");
        std::vector<std::uint8_t> out;
        out.reserve(16 + pkt.acks.size() * 4 + pkt.payload.size());
        out.push_back(static_cast<std::uint8_t>((static_cast<std::uint8_t>(pkt.opcode) << 3) | (pkt.key_id & 0x07)));
        write_be64(out, pkt.session_id);
        out.push_back(static_cast<std::uint8_t>(pkt.acks.size()));
        for (auto ack : pkt.acks) write_be32(out, ack);
        if (!pkt.acks.empty()) write_be64(out, pkt.remote_session_id);
        if (pkt.opcode != Opcode::ack_v1) {
            write_be32(out, *pkt.packet_id);
            out.insert(out.end(), pkt.payload.begin(), pkt.payload.end());
        }
        return out;
    }

    auto decode_control_packet(std::span<std::uint8_t const> wire) -> std::expected<ControlPacket, std::string> {
        if (wire.size() < 10) return std::unexpected("truncated OpenVPN packet");
        auto op = valid_control_opcode(static_cast<std::uint8_t>((wire[0] >> 3) & 0x1f));
        if (!op) return std::unexpected("unsupported OpenVPN control opcode");
        ControlPacket pkt{.opcode = *op, .key_id = static_cast<std::uint8_t>(wire[0] & 0x07), .session_id = read_be64(wire.subspan(1, 8))};
        std::size_t const ack_count = wire[9];
        std::size_t off = 10;
        if (wire.size() < off + ack_count * 4 + (ack_count > 0 ? 8 : 0))
            return std::unexpected("truncated OpenVPN ACK block");
        pkt.acks.reserve(ack_count);
        for (std::size_t i = 0; i < ack_count; ++i, off += 4) pkt.acks.push_back(read_be32(wire.subspan(off, 4)));
        if (ack_count > 0) { pkt.remote_session_id = read_be64(wire.subspan(off, 8)); off += 8; }
        if (*op == Opcode::ack_v1) {
            if (off != wire.size()) return std::unexpected("unexpected trailing bytes in ack_v1");
            return pkt;
        }
        if (wire.size() < off + 4) return std::unexpected("missing control message packet_id");
        pkt.packet_id = read_be32(wire.subspan(off, 4));
        pkt.payload.assign(wire.begin() + static_cast<std::ptrdiff_t>(off + 4), wire.end());
        return pkt;
    }

    auto encode_tcp_frame(std::span<std::uint8_t const> packet) -> std::expected<std::vector<std::uint8_t>, std::string> {
        if (packet.empty() || packet.size() > 65535) return std::unexpected("invalid OpenVPN TCP packet length");
        std::vector<std::uint8_t> out;
        out.reserve(2 + packet.size());
        write_be16(out, static_cast<std::uint16_t>(packet.size()));
        out.insert(out.end(), packet.begin(), packet.end());
        return out;
    }

    auto decode_tcp_frame(std::span<std::uint8_t const> stream)
        -> std::expected<std::optional<std::pair<std::vector<std::uint8_t>, std::size_t>>, std::string> {
        if (stream.size() < 2) return std::nullopt;
        std::size_t len = read_be16(stream.first(2));
        if (len == 0) return std::unexpected("zero-length OpenVPN TCP frame");
        if (stream.size() - 2 < len) return std::nullopt;
        return std::pair{std::vector<std::uint8_t>(stream.begin() + 2, stream.begin() + static_cast<std::ptrdiff_t>(2 + len)), 2 + len};
    }

    auto encode_key_method2_client(KeyMethod2Client const& km) -> std::expected<std::vector<std::uint8_t>, std::string> {
        std::vector<std::uint8_t> out{0, 0, 0, 0, 2};
        out.insert(out.end(), km.pre_master.begin(), km.pre_master.end());
        out.insert(out.end(), km.random1.begin(), km.random1.end());
        out.insert(out.end(), km.random2.begin(), km.random2.end());
        for (std::string_view s : {std::string_view(km.options), std::string_view(km.username),
                                   std::string_view(km.password), std::string_view(km.peer_info)}) {
            if (auto ok = write_km_string(out, s); !ok) { crypto::cleanse(out); return std::unexpected(ok.error()); }
        }
        return out;
    }

    auto decode_key_method2_client(std::span<std::uint8_t const> wire) -> std::expected<KeyMethod2Client, std::string> {
        if (wire.size() < 5 + 48 + 32 + 32) return std::unexpected("truncated OpenVPN key-method2 client packet");
        if (wire[4] != 2) return std::unexpected("unsupported OpenVPN key method");
        KeyMethod2Client km;
        std::size_t off = 5;
        std::copy_n(wire.begin() + off, 48, km.pre_master.begin()); off += 48;
        std::copy_n(wire.begin() + off, 32, km.random1.begin()); off += 32;
        std::copy_n(wire.begin() + off, 32, km.random2.begin()); off += 32;
        for (auto* dst : {&km.options, &km.username, &km.password, &km.peer_info}) {
            auto s = read_km_string(wire, off);
            if (!s) return std::unexpected(s.error());
            *dst = std::move(*s);
        }
        return km;
    }

    auto encode_key_method2_server(KeyMethod2Server const& km) -> std::expected<std::vector<std::uint8_t>, std::string> {
        std::vector<std::uint8_t> out{0, 0, 0, 0, 2};
        out.insert(out.end(), km.random1.begin(), km.random1.end());
        out.insert(out.end(), km.random2.begin(), km.random2.end());
        if (auto ok = write_km_string(out, km.options); !ok) return std::unexpected(ok.error());
        write_be16(out, 0);
        write_be16(out, 0);
        return out;
    }

    auto decode_key_method2_server(std::span<std::uint8_t const> wire) -> std::expected<KeyMethod2Server, std::string> {
        if (wire.size() < 5 + 32 + 32) return std::unexpected("truncated OpenVPN key-method2 server packet");
        if (wire[4] != 2) return std::unexpected("unsupported OpenVPN key method");
        KeyMethod2Server km;
        std::size_t off = 5;
        std::copy_n(wire.begin() + off, 32, km.random1.begin()); off += 32;
        std::copy_n(wire.begin() + off, 32, km.random2.begin()); off += 32;
        auto opts = read_km_string(wire, off);
        if (!opts) return std::unexpected(opts.error());
        km.options = std::move(*opts);
        return km;
    }

    auto derive_data_keys(std::span<std::uint8_t const> master_secret, std::span<std::uint8_t const> client_random,
                          std::span<std::uint8_t const> server_random, bool server_role) -> std::expected<KeyMaterial, std::string> {
        if (master_secret.empty() || client_random.empty() || server_random.empty())
            return std::unexpected("empty key derivation input");
        std::vector<std::uint8_t> salt;
        salt.reserve(client_random.size() + server_random.size());
        salt.insert(salt.end(), client_random.begin(), client_random.end());
        salt.insert(salt.end(), server_random.begin(), server_random.end());
        auto prk = crypto::hkdf_extract(crypto::Hash::sha256, salt, master_secret);
        if (!prk) return std::unexpected("hkdf_extract failed");
        struct VecWipe { std::vector<std::uint8_t>& v; ~VecWipe() { crypto::cleanse(v); } } prk_wipe{*prk};
        constexpr std::string_view kInfo = "Nexus OpenVPN v2 data keys";
        auto expanded = crypto::hkdf_expand(
            crypto::Hash::sha256, *prk, std::span(reinterpret_cast<std::uint8_t const*>(kInfo.data()), kInfo.size()), 80);
        if (!expanded || expanded->size() != 80) {
            if (expanded) crypto::cleanse(*expanded);
            return std::unexpected("hkdf_expand failed");
        }
        VecWipe exp_wipe{*expanded};
        KeyMaterial km;
        auto const& b = *expanded;
        std::copy_n(b.begin() + (server_role ? 32 : 0), 32, km.tx_key.begin());
        std::copy_n(b.begin() + (server_role ? 0 : 32), 32, km.rx_key.begin());
        std::copy_n(b.begin() + (server_role ? 72 : 64), 8, km.tx_iv.begin());
        std::copy_n(b.begin() + (server_role ? 64 : 72), 8, km.rx_iv.begin());
        return km;
    }

    auto derive_key_method2_keys(
        std::span<std::uint8_t const, 48> pre_master,
        std::span<std::uint8_t const, 32> client_random1, std::span<std::uint8_t const, 32> server_random1,
        std::span<std::uint8_t const, 32> client_random2, std::span<std::uint8_t const, 32> server_random2,
        std::uint64_t client_session_id, std::uint64_t server_session_id, bool server_role)
        -> std::expected<KeyMaterial, std::string> {
        struct VecWipe { std::vector<std::uint8_t>& v; ~VecWipe() { crypto::cleanse(v); } };
        std::vector<std::uint8_t> seed1;
        seed1.reserve(64);
        seed1.insert(seed1.end(), client_random1.begin(), client_random1.end());
        seed1.insert(seed1.end(), server_random1.begin(), server_random1.end());
        auto master = tls10_prf(pre_master, "OpenVPN master secret", seed1, 48);
        if (!master) return std::unexpected(master.error());
        VecWipe master_wipe{*master};

        std::vector<std::uint8_t> seed2;
        seed2.reserve(80);
        seed2.insert(seed2.end(), client_random2.begin(), client_random2.end());
        seed2.insert(seed2.end(), server_random2.begin(), server_random2.end());
        write_be64(seed2, client_session_id);
        write_be64(seed2, server_session_id);
        auto key2 = tls10_prf(*master, "OpenVPN key expansion", seed2, 256);
        if (!key2) return std::unexpected(key2.error());
        VecWipe key2_wipe{*key2};

        KeyMaterial km;
        auto const& b = *key2;
        std::copy_n(b.begin() + (server_role ? 128 : 0), 32, km.tx_key.begin());
        std::copy_n(b.begin() + (server_role ? 0 : 128), 32, km.rx_key.begin());
        std::copy_n(b.begin() + (server_role ? 192 : 64), 8, km.tx_iv.begin());
        std::copy_n(b.begin() + (server_role ? 64 : 192), 8, km.rx_iv.begin());
        return km;
    }

    auto parse_push_reply(std::string_view text) -> std::expected<PushConfig, std::string> {
        while (!text.empty() && (text.back() == '\0' || text.back() == '\r' || text.back() == '\n' || text.back() == ' '))
            text.remove_suffix(1);
        if (!text.starts_with("PUSH_REPLY")) return std::unexpected("expected PUSH_REPLY");
        PushConfig cfg;
        std::size_t pos = 10;
        while (pos < text.size()) {
            if (text[pos] == ',') ++pos;
            auto next = text.find(',', pos);
            auto item = (next == std::string_view::npos) ? text.substr(pos) : text.substr(pos, next - pos);
            pos = (next == std::string_view::npos) ? text.size() : next;
            auto toks = split_ws(item);
            if (toks.empty()) continue;
            if (toks[0] == "ifconfig" && toks.size() >= 3) {
                auto ip = platform::parse_ip_address(toks[1]);
                if (!ip || ip->size != 4) return std::unexpected("invalid PUSH_REPLY IPv4 address");
                std::array<std::uint8_t, 4> v4{};
                std::ranges::copy(ip->view(), v4.begin());
                cfg.local_v4 = v4;
            } else if (toks[0] == "ifconfig-ipv6" && toks.size() >= 2) {
                auto addr = toks[1];
                if (auto slash = addr.find('/'); slash != std::string_view::npos) addr = addr.substr(0, slash);
                auto ip = platform::parse_ip_address(addr);
                if (!ip || ip->size != 16) return std::unexpected("invalid PUSH_REPLY IPv6 address");
                std::array<std::uint8_t, 16> v6{};
                std::ranges::copy(ip->view(), v6.begin());
                cfg.local_v6 = v6;
            } else if (toks[0] == "peer-id" && toks.size() >= 2) {
                std::uint32_t pid = 0;
                auto [end, ec] = std::from_chars(toks[1].data(), toks[1].data() + toks[1].size(), pid);
                if (ec != std::errc{} || end != toks[1].data() + toks[1].size() || pid > 0xffffffu)
                    return std::unexpected("invalid PUSH_REPLY peer-id");
                cfg.peer_id = pid;
            } else if (toks[0] == "cipher" && toks.size() >= 2) {
                if (eq_icase(toks[1], "AES-256-GCM")) cfg.cipher = Cipher::aes_256_gcm;
                else if (eq_icase(toks[1], "CHACHA20-POLY1305")) cfg.cipher = Cipher::chacha20_poly1305;
                else return std::unexpected("unsupported PUSH_REPLY cipher");
            } else if (toks[0] == "tun-mtu" && toks.size() >= 2) {
                unsigned mtu = 0;
                auto [end, ec] = std::from_chars(toks[1].data(), toks[1].data() + toks[1].size(), mtu);
                if (ec != std::errc{} || end != toks[1].data() + toks[1].size() || mtu < 576 || mtu > 9000)
                    return std::unexpected("invalid PUSH_REPLY tun-mtu");
                cfg.mtu = static_cast<std::uint16_t>(mtu);
            } else if (toks[0] == "ping" && toks.size() >= 2) {
                unsigned v = 0;
                auto [end, ec] = std::from_chars(toks[1].data(), toks[1].data() + toks[1].size(), v);
                if (ec == std::errc{} && end == toks[1].data() + toks[1].size() && v <= 65535)
                    cfg.ping_s = static_cast<std::uint16_t>(v);
            } else if (toks[0] == "ping-restart" && toks.size() >= 2) {
                unsigned v = 0;
                auto [end, ec] = std::from_chars(toks[1].data(), toks[1].data() + toks[1].size(), v);
                if (ec == std::errc{} && end == toks[1].data() + toks[1].size() && v <= 65535)
                    cfg.ping_restart_s = static_cast<std::uint16_t>(v);
            }
        }
        return cfg;
    }
}
