module dns.mdns;
import std;
import platform.ip_address;

namespace dns::mdns {
    namespace {
        auto ascii_lower(std::string_view in) -> std::string {
            std::string out(in);
            for (char& c : out) {
                if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
            }
            return out;
        }

        auto ascii_ci_eq(std::string_view a, std::string_view b) noexcept -> bool {
            if (a.size() != b.size()) return false;
            for (std::size_t i = 0; i < a.size(); ++i) {
                auto lo = [](char c) noexcept {
                    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c;
                };
                if (lo(a[i]) != lo(b[i])) return false;
            }
            return true;
        }

        auto strip_trailing_dot(std::string_view s) noexcept -> std::string_view {
            while (s.ends_with('.')) s.remove_suffix(1);
            return s;
        }

        auto read16(std::span<std::uint8_t const> b, std::size_t off) noexcept -> std::uint16_t {
            return static_cast<std::uint16_t>((std::uint16_t(b[off]) << 8) | b[off + 1]);
        }

        auto read32(std::span<std::uint8_t const> b, std::size_t off) noexcept -> std::uint32_t {
            return (std::uint32_t(b[off]) << 24) | (std::uint32_t(b[off + 1]) << 16) |
                   (std::uint32_t(b[off + 2]) << 8) | b[off + 3];
        }

        auto decode_name(std::span<std::uint8_t const> wire, std::size_t& pos) -> std::expected<std::string, std::string> {
            std::string out;
            std::size_t cur = pos;
            bool jumped = false;
            std::size_t hops = 0;
            while (cur < wire.size()) {
                std::uint8_t len = wire[cur];
                if (len == 0) {
                    if (!jumped) pos = cur + 1;
                    return out.empty() ? std::string(".") : out;
                }
                if ((len & 0xc0u) == 0xc0u) {
                    if (cur + 1 >= wire.size() || ++hops > 32) return std::unexpected("mDNS invalid compression pointer");
                    std::size_t target = (std::size_t(len & 0x3fu) << 8) | wire[cur + 1];
                    if (target >= wire.size()) return std::unexpected("mDNS pointer out of bounds");
                    if (!jumped) pos = cur + 2;
                    jumped = true;
                    cur = target;
                    continue;
                }
                if (len > 63 || cur + 1 + len > wire.size()) return std::unexpected("mDNS invalid label");
                if (!out.empty()) out.push_back('.');
                if (out.size() + len > 253) return std::unexpected("mDNS name too long");
                for (std::size_t i = 0; i < len; ++i) {
                    char ch = static_cast<char>(wire[cur + 1 + i]);
                    out.push_back((ch >= 'A' && ch <= 'Z') ? static_cast<char>(ch + ('a' - 'A')) : ch);
                }
                cur += 1 + len;
            }
            return std::unexpected("mDNS truncated name");
        }
    }

    auto is_mdns_name(std::string_view name) noexcept -> bool {
        name = strip_trailing_dot(name);
        if (name.empty() || name.size() > 253) return false;
        if (ascii_ci_eq(name, "local")) return false;
        if (name.size() <= 6) return false;
        return ascii_ci_eq(name.substr(name.size() - 6), ".local");
    }

    auto make_mdns_query(std::string_view name, RecordType type, bool unicast_response)
        -> std::expected<std::vector<std::uint8_t>, std::string> {
        name = strip_trailing_dot(name);
        if (!is_mdns_name(name)) return std::unexpected("mDNS queries must target a .local name");
        std::vector<std::uint8_t> wire(12, 0); // RFC 6762 §18.1: ID must be 0, Flags 0x0000
        wire[5] = 1; // QDCOUNT = 1

        std::size_t pos = 0;
        while (pos < name.size()) {
            auto dot = name.find('.', pos);
            auto lbl = (dot == std::string_view::npos) ? name.substr(pos) : name.substr(pos, dot - pos);
            if (lbl.empty() || lbl.size() > 63) return std::unexpected("mDNS invalid DNS label");
            wire.push_back(static_cast<std::uint8_t>(lbl.size()));
            for (char c : lbl) wire.push_back(static_cast<std::uint8_t>(c));
            if (dot == std::string_view::npos) break;
            pos = dot + 1;
        }
        wire.push_back(0);
        auto qt = static_cast<std::uint16_t>(type);
        std::uint16_t qc = unicast_response ? 0x8001u : 0x0001u;
        wire.push_back(static_cast<std::uint8_t>(qt >> 8));
        wire.push_back(static_cast<std::uint8_t>(qt & 0xffu));
        wire.push_back(static_cast<std::uint8_t>(qc >> 8));
        wire.push_back(static_cast<std::uint8_t>(qc & 0xffu));
        return wire;
    }

    auto parse_mdns_response(std::span<std::uint8_t const> wire) -> std::expected<std::vector<MdnsRecord>, std::string> {
        if (wire.size() < 12) return std::unexpected("mDNS packet shorter than header");
        std::uint16_t flags = read16(wire, 2);
        if ((flags & 0x8000u) == 0 || (flags & 0x000fu) != 0)
            return std::unexpected("mDNS packet is not a valid response");
        std::uint16_t qd = read16(wire, 4);
        std::uint32_t total_rr = static_cast<std::uint32_t>(read16(wire, 6)) + read16(wire, 8) + read16(wire, 10);
        if (qd > 64 || total_rr > 256) return std::unexpected("mDNS too many resource records");
        std::size_t pos = 12;

        for (std::uint16_t i = 0; i < qd; ++i) {
            auto qname = decode_name(wire, pos);
            if (!qname) return std::unexpected(qname.error());
            if (pos + 4 > wire.size()) return std::unexpected("mDNS truncated question");
            pos += 4;
        }

        std::vector<MdnsRecord> records;
        for (std::uint32_t i = 0; i < total_rr && pos < wire.size(); ++i) {
            auto rname = decode_name(wire, pos);
            if (!rname) return std::unexpected(rname.error());
            if (pos + 10 > wire.size()) return std::unexpected("mDNS truncated RR header");
            MdnsRecord rec{};
            rec.name = std::move(*rname);
            rec.type = read16(wire, pos);
            std::uint16_t raw_class = read16(wire, pos + 2);
            rec.cache_flush = (raw_class & 0x8000u) != 0;
            rec.klass = static_cast<std::uint16_t>(raw_class & 0x7fffu);
            rec.ttl = read32(wire, pos + 4);
            std::uint16_t rdlen = read16(wire, pos + 8);
            pos += 10;
            if (pos + rdlen > wire.size()) return std::unexpected("mDNS truncated RDATA");
            std::size_t rdata_end = pos + rdlen;

            if (rec.type == 1 && rdlen == 4) {
                platform::IpAddress ip{.size = 4};
                std::copy_n(wire.begin() + pos, 4, ip.bytes.begin());
                rec.address = ip;
            } else if (rec.type == 28 && rdlen == 16) {
                platform::IpAddress ip{.size = 16};
                std::copy_n(wire.begin() + pos, 16, ip.bytes.begin());
                rec.address = ip;
            } else if (rec.type == 12) {
                std::size_t tmp = pos;
                auto ptr = decode_name(wire, tmp);
                if (!ptr || tmp > rdata_end) return std::unexpected("mDNS invalid PTR target");
                rec.target = std::move(*ptr);
            } else if (rec.type == 33 && rdlen >= 6) {
                rec.srv_priority = read16(wire, pos);
                rec.srv_weight = read16(wire, pos + 2);
                rec.srv_port = read16(wire, pos + 4);
                std::size_t tmp = pos + 6;
                auto tgt = decode_name(wire, tmp);
                if (!tgt || tmp > rdata_end) return std::unexpected("mDNS invalid SRV target");
                rec.target = std::move(*tgt);
            } else if (rec.type == 16) {
                std::size_t cur = pos;
                while (cur < rdata_end) {
                    std::uint8_t slen = wire[cur++];
                    if (cur + slen > rdata_end) break;
                    rec.txt_strings.emplace_back(reinterpret_cast<char const*>(wire.data() + cur), slen);
                    cur += slen;
                }
            }
            pos = rdata_end;
            records.push_back(std::move(rec));
        }
        return records;
    }

    auto MdnsCache::ingest(std::span<MdnsRecord const> records, std::uint64_t now_sec) -> void {
        std::lock_guard lock(mutex_);
        for (auto const& r : records) {
            std::string key_name = ascii_lower(r.name);
            if (r.cache_flush) {
                std::erase_if(entries_, [&](Entry const& e) {
                    return e.record.type == r.type && ascii_ci_eq(e.record.name, key_name);
                });
            } else {
                std::erase_if(entries_, [&](Entry const& e) {
                    return e.record.type == r.type && ascii_ci_eq(e.record.name, key_name) &&
                           e.record.target == r.target && e.record.address.has_value() == r.address.has_value() &&
                           (!r.address || (e.record.address->size == r.address->size &&
                                           std::ranges::equal(e.record.address->view(), r.address->view())));
                });
            }
            if (r.ttl == 0) continue;
            std::uint64_t exp = now_sec + r.ttl;
            if (entries_.size() >= max_entries_ && !entries_.empty()) entries_.erase(entries_.begin());
            MdnsRecord copy = r;
            copy.name = std::move(key_name);
            entries_.push_back({std::move(copy), exp});
        }
    }

    auto MdnsCache::lookup(std::string_view name, std::uint16_t type, std::uint64_t now_sec) const
        -> std::vector<MdnsRecord> {
        std::lock_guard lock(mutex_);
        std::vector<MdnsRecord> out;
        for (auto const& e : entries_) {
            if (e.expires_at_sec <= now_sec) continue;
            if (!ascii_ci_eq(e.record.name, strip_trailing_dot(name))) continue;
            if (type == 255 || e.record.type == type) out.push_back(e.record);
        }
        return out;
    }

    auto MdnsCache::prune_expired(std::uint64_t now_sec) -> std::size_t {
        std::lock_guard lock(mutex_);
        return std::erase_if(entries_, [&](Entry const& e) { return e.expires_at_sec <= now_sec; });
    }

    auto MdnsCache::size() const noexcept -> std::size_t {
        std::lock_guard lock(mutex_);
        return entries_.size();
    }
}
