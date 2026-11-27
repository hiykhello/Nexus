module rules;
import std;
import rulefile;
import platform.ip_address;
import rules.any_index;

namespace rules {
    namespace {
        constexpr std::string_view kNxmmMagic{"NXMM\0\0\0\1", 8};
        constexpr std::size_t kNxmmHeaderSize = 64;

        auto read_u32(std::uint8_t const* p) noexcept -> std::uint32_t {
            std::uint32_t v = 0;
            std::memcpy(&v, p, sizeof(v));
            return v;
        }
        auto read_u64(std::uint8_t const* p) noexcept -> std::uint64_t {
            std::uint64_t v = 0;
            std::memcpy(&v, p, sizeof(v));
            return v;
        }
        auto write_u32(std::string& out, std::uint32_t v) -> void {
            char buf[4];
            std::memcpy(buf, &v, 4);
            out.append(buf, 4);
        }
        auto write_u64(std::string& out, std::uint64_t v) -> void {
            char buf[8];
            std::memcpy(buf, &v, 8);
            out.append(buf, 8);
        }
        auto fnv1a64(std::span<std::uint8_t const> data) noexcept -> std::uint64_t {
            std::uint64_t h = 14695981039346656037ull;
            for (std::uint8_t b : data) { h ^= b; h *= 1099511628211ull; }
            return h;
        }

        auto append_v4_cidrs(std::uint32_t lo, std::uint32_t hi, bool match_source, std::vector<Rule>& out) -> void {
            std::uint64_t cur = lo, end = hi;
            std::string type = match_source ? "source-ip-cidr" : "ip-cidr";
            while (cur <= end) {
                unsigned tz = cur == 0 ? 32u : static_cast<unsigned>(std::countr_zero(cur));
                std::uint64_t rem = end - cur + 1;
                unsigned max_k = rem >= (std::uint64_t{1} << 32) ? 32u : static_cast<unsigned>(63 - std::countl_zero(rem));
                unsigned k = std::min(tz, max_k);
                unsigned prefix = 32u - k;
                auto a = static_cast<std::uint8_t>((cur >> 24) & 0xffu);
                auto b = static_cast<std::uint8_t>((cur >> 16) & 0xffu);
                auto c = static_cast<std::uint8_t>((cur >> 8) & 0xffu);
                auto d = static_cast<std::uint8_t>(cur & 0xffu);
                out.push_back({type, std::format("{}.{}.{}.{}/{}", a, b, c, d, prefix), {}});
                cur += (std::uint64_t{1} << k);
            }
        }

        using V6Bytes = std::array<std::uint8_t, 16>;
        auto v6_ctz(V6Bytes const& v) noexcept -> unsigned {
            for (int i = 15; i >= 0; --i) {
                std::uint8_t b = v[static_cast<std::size_t>(i)];
                if (b != 0) return static_cast<unsigned>((15 - i) * 8 + std::countr_zero(b));
            }
            return 128u;
        }
        auto v6_fits_block(V6Bytes const& cur, V6Bytes const& end, unsigned k) noexcept -> bool {
            if (k == 128) return cur == V6Bytes{} && end == V6Bytes{255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255};
            V6Bytes top = cur;
            unsigned byte_idx = 15 - (k / 8);
            unsigned bit_rem = k % 8;
            if (bit_rem) top[byte_idx] |= static_cast<std::uint8_t>((1u << bit_rem) - 1u);
            for (std::size_t i = byte_idx + 1; i < 16; ++i) top[i] = 0xffu;
            return top <= end;
        }
        auto v6_add_pow2(V6Bytes cur, unsigned k, bool& wrapped) noexcept -> V6Bytes {
            wrapped = false;
            if (k >= 128) { wrapped = true; return V6Bytes{}; }
            std::size_t byte_idx = 15 - (k / 8);
            unsigned carry = 1u << (k % 8);
            for (int i = static_cast<int>(byte_idx); i >= 0 && carry; --i) {
                unsigned s = static_cast<unsigned>(cur[static_cast<std::size_t>(i)]) + carry;
                cur[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(s & 0xffu);
                carry = s >> 8;
            }
            wrapped = carry != 0;
            return cur;
        }
        auto append_v6_cidrs(V6Bytes cur, V6Bytes const& end, bool match_source, std::vector<Rule>& out) -> void {
            std::string type = match_source ? "source-ip-cidr" : "ip-cidr";
            for (;;) {
                unsigned k = v6_ctz(cur);
                while (k > 0 && !v6_fits_block(cur, end, k)) --k;
                unsigned prefix = 128u - k;
                auto txt = platform::format_ip_address(cur);
                out.push_back({type, std::format("{}/{}", *txt, prefix), {}});
                bool wrapped = false;
                cur = v6_add_pow2(cur, k, wrapped);
                if (wrapped || cur > end) break;
            }
        }
    }

    auto MmapMatcher::read_span(std::size_t table_off, std::size_t idx) const noexcept -> std::string_view {
        if (table_off > buf_.size() || idx >= (buf_.size() - table_off) / 8) return {};
        auto* p = buf_.data() + table_off + idx * 8;
        std::uint32_t off = read_u32(p), len = read_u32(p + 4);
        if (arena_off_ > buf_.size() || off > arena_bytes_ || len > arena_bytes_ - off ||
            arena_off_ + off + len > buf_.size()) return {};
        return {reinterpret_cast<char const*>(buf_.data() + arena_off_ + off), len};
    }

    auto MmapMatcher::v4_at(std::size_t i) const noexcept -> std::pair<std::uint32_t, std::uint32_t> {
        if (v4_off_ > buf_.size() || i >= (buf_.size() - v4_off_) / 8) return {1u, 0u};
        auto* p = buf_.data() + v4_off_ + i * 8;
        return {read_u32(p), read_u32(p + 4)};
    }

    auto MmapMatcher::v6_at(std::size_t i) const noexcept -> std::pair<V6Bytes, V6Bytes> {
        if (v6_off_ > buf_.size() || i >= (buf_.size() - v6_off_) / 32) { V6Bytes a{}, b{}; a[0] = 1; return {a, b}; }
        auto* p = buf_.data() + v6_off_ + i * 32;
        V6Bytes a{}, b{};
        std::memcpy(a.data(), p, 16);
        std::memcpy(b.data(), p + 16, 16);
        return {a, b};
    }

    auto MmapMatcher::init_and_validate(std::size_t max_bytes, std::uint32_t max_rule_count) -> std::expected<void, std::string> {
        static_assert(max_rules == 4000000u && max_input_bytes == 268435456u);
        auto limit_bytes = max_bytes == 0 ? std::size_t(max_input_bytes)
            : std::min<std::size_t>(max_bytes, std::numeric_limits<std::uint32_t>::max());
        auto limit_rules = max_rule_count == 0 ? std::uint32_t(max_rules) : max_rule_count;
        if (buf_.size() < kNxmmHeaderSize || buf_.size() > limit_bytes)
            return std::unexpected("invalid NXMM file size");
        if (std::string_view(reinterpret_cast<char const*>(buf_.data()), 8) != kNxmmMagic)
            return std::unexpected("invalid NXMM magic header");
        auto* h = buf_.data();
        if (read_u32(h + 8) != 1u) return std::unexpected("unsupported NXMM version");
        std::uint32_t flags = read_u32(h + 12);
        if (flags > nxmm_flag_ip_cidr_source) return std::unexpected("unsupported NXMM flags");
        ip_cidr_match_source_ = (flags & nxmm_flag_ip_cidr_source) != 0;
        std::uint64_t total_size = read_u64(h + 16);
        if (total_size != buf_.size()) return std::unexpected("NXMM total size mismatch");
        exact_count_ = read_u32(h + 24);
        suffix_count_ = read_u32(h + 28);
        v4_count_ = read_u32(h + 32);
        v6_count_ = read_u32(h + 36);
        arena_bytes_ = read_u32(h + 40);
        tail_beve_bytes_ = read_u32(h + 44);
        std::uint64_t expected_crc = read_u64(h + 48);
        if (read_u64(h + 56) != 0) return std::unexpected("invalid NXMM reserved field");

        std::uint64_t exact_bytes = std::uint64_t(exact_count_) * 8u;
        std::uint64_t suffix_bytes = std::uint64_t(suffix_count_) * 8u;
        std::uint64_t v4_bytes = std::uint64_t(v4_count_) * 8u;
        std::uint64_t v6_bytes = std::uint64_t(v6_count_) * 32u;
        std::uint64_t total = std::uint64_t(kNxmmHeaderSize) + exact_bytes + suffix_bytes + v4_bytes + v6_bytes +
            arena_bytes_ + tail_beve_bytes_;
        if (total != total_size || std::uint64_t(exact_count_) + suffix_count_ + v4_count_ + v6_count_ > limit_rules)
            return std::unexpected("corrupt NXMM section bounds");
        if (fnv1a64(buf_.subspan(kNxmmHeaderSize)) != expected_crc)
            return std::unexpected("NXMM checksum verification failed");

        exact_off_ = kNxmmHeaderSize;
        suffix_off_ = exact_off_ + static_cast<std::size_t>(exact_bytes);
        v4_off_ = suffix_off_ + static_cast<std::size_t>(suffix_bytes);
        v6_off_ = v4_off_ + static_cast<std::size_t>(v4_bytes);
        arena_off_ = v6_off_ + static_cast<std::size_t>(v6_bytes);
        tail_off_ = arena_off_ + static_cast<std::size_t>(arena_bytes_);

        auto check_domains = [&](std::size_t off, std::uint32_t count) -> std::expected<void, std::string> {
            std::string_view prev;
            for (std::uint32_t i = 0; i < count; ++i) {
                auto* p = buf_.data() + off + static_cast<std::size_t>(i) * 8u;
                std::uint32_t soff = read_u32(p), slen = read_u32(p + 4);
                if (slen == 0 || slen > 253 || std::uint64_t(soff) + slen > arena_bytes_)
                    return std::unexpected("invalid NXMM domain span");
                std::string_view cur(reinterpret_cast<char const*>(buf_.data() + arena_off_ + soff), slen);
                if (!valid_domain(cur) || std::ranges::any_of(cur, [](char c) { return c >= 'A' && c <= 'Z'; }))
                    return std::unexpected("invalid NXMM domain name");
                if (i > 0 && !(prev < cur)) return std::unexpected("NXMM domain table not sorted");
                prev = cur;
            }
            return {};
        };
        if (auto ok = check_domains(exact_off_, exact_count_); !ok) return ok;
        if (auto ok = check_domains(suffix_off_, suffix_count_); !ok) return ok;

        std::uint32_t prev_v4_hi = 0;
        for (std::uint32_t i = 0; i < v4_count_; ++i) {
            auto [lo, hi] = v4_at(i);
            if (lo > hi || (i > 0 && lo <= prev_v4_hi)) return std::unexpected("NXMM IPv4 table invalid or unsorted");
            prev_v4_hi = hi;
        }
        V6Bytes prev_v6_hi{};
        for (std::uint32_t i = 0; i < v6_count_; ++i) {
            auto [lo, hi] = v6_at(i);
            if (lo > hi || (i > 0 && lo <= prev_v6_hi)) return std::unexpected("NXMM IPv6 table invalid or unsorted");
            prev_v6_hi = hi;
        }
        return {};
    }

    auto MmapMatcher::from_mapped(std::shared_ptr<rulefile::MappedFile const> mapped,
        std::size_t max_bytes, std::uint32_t max_rule_count) -> std::expected<MmapMatcher, std::string> {
        if (!mapped || mapped->empty()) return std::unexpected("empty mapped file");
        MmapMatcher out;
        out.buf_ = mapped->bytes();
        out.owner_ = std::move(mapped);
        if (auto ok = out.init_and_validate(max_bytes, max_rule_count); !ok) return std::unexpected(ok.error());
        return out;
    }

    auto MmapMatcher::open_file(std::string_view path, std::size_t max_bytes,
        std::uint32_t max_rule_count) -> std::expected<MmapMatcher, std::string> {
        if (path.empty() || path.find('\0') != std::string_view::npos)
            return std::unexpected("invalid NXMM path");
        auto limit_bytes = max_bytes == 0 ? std::size_t(max_input_bytes)
            : std::min<std::size_t>(max_bytes, std::numeric_limits<std::uint32_t>::max());
        auto mapped = rulefile::map_regular_file(path, limit_bytes);
        if (!mapped) return std::unexpected(mapped.error());
        if (mapped->size() < kNxmmHeaderSize || mapped->size() > limit_bytes)
            return std::unexpected("invalid NXMM file size");
        return from_mapped(std::make_shared<rulefile::MappedFile>(std::move(*mapped)), limit_bytes, max_rule_count);
    }

    auto MmapMatcher::open_bytes(std::string bytes, std::size_t max_bytes,
        std::uint32_t max_rule_count) -> std::expected<MmapMatcher, std::string> {
        auto owned = std::make_shared<std::string>(std::move(bytes));
        MmapMatcher out;
        out.buf_ = {reinterpret_cast<std::uint8_t const*>(owned->data()), owned->size()};
        out.owner_ = std::move(owned);
        if (auto ok = out.init_and_validate(max_bytes, max_rule_count); !ok) return std::unexpected(ok.error());
        return out;
    }

    auto MmapMatcher::search_domains(std::size_t table_off, std::uint32_t count, std::string_view key) const noexcept -> bool {
        std::uint32_t lo = 0, hi = count;
        while (lo < hi) {
            std::uint32_t mid = lo + (hi - lo) / 2;
            auto cur = read_span(table_off, mid);
            if (cur == key) return true;
            if (cur < key) lo = mid + 1;
            else hi = mid;
        }
        return false;
    }

    auto MmapMatcher::search_v4(std::uint32_t ip) const noexcept -> bool {
        std::uint32_t lo = 0, hi = v4_count_;
        while (lo < hi) {
            std::uint32_t mid = lo + (hi - lo) / 2;
            auto [a, b] = v4_at(mid);
            if (ip < a) hi = mid;
            else if (ip > b) lo = mid + 1;
            else return true;
        }
        return false;
    }

    auto MmapMatcher::search_v6(V6Bytes const& ip) const noexcept -> bool {
        std::uint32_t lo = 0, hi = v6_count_;
        while (lo < hi) {
            std::uint32_t mid = lo + (hi - lo) / 2;
            auto [a, b] = v6_at(mid);
            if (ip < a) hi = mid;
            else if (ip > b) lo = mid + 1;
            else return true;
        }
        return false;
    }

    auto MmapMatcher::match_domain(std::string_view domain) const noexcept -> bool {
        if (domain.ends_with('.')) domain.remove_suffix(1);
        if (domain.empty() || domain.size() > 253 || !has_domain()) return false;
        std::array<char, 253> lowered{};
        for (std::size_t i = 0; i < domain.size(); ++i) {
            char c = domain[i];
            lowered[i] = (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c;
        }
        std::string_view name(lowered.data(), domain.size());
        if (exact_count_ && search_domains(exact_off_, exact_count_, name)) return true;
        if (suffix_count_) {
            for (;;) {
                if (search_domains(suffix_off_, suffix_count_, name)) return true;
                auto dot = name.find('.');
                if (dot == std::string_view::npos) break;
                name.remove_prefix(dot + 1);
            }
        }
        return false;
    }

    auto MmapMatcher::match_ip(V6Bytes const& bytes, unsigned family, bool match_mapped_v4) const noexcept -> bool {
        if (!has_ip()) return false;
        if (family == 4) return v4_count_ && search_v4(any_detail::read_be32(bytes));
        if (family != 6) return false;
        if (v6_count_ && search_v6(bytes)) return true;
        if (match_mapped_v4 && v4_count_ &&
            std::all_of(bytes.begin(), bytes.begin() + 10, [](auto b) { return b == 0; }) &&
            bytes[10] == 0xff && bytes[11] == 0xff) {
            return search_v4(any_detail::read_be32(bytes, 12));
        }
        return false;
    }

    auto compile_nxmm(RuleSet const& set, bool ip_cidr_match_source, std::size_t max_bytes) -> std::expected<std::string, Error> {
        if (set.rules.size() > max_rules)
            return std::unexpected(Error{ErrorCode::limit, "rule nesting or count exceeds limit"});
        auto limit_bytes = max_bytes == 0 ? std::size_t(max_input_bytes)
            : std::min<std::size_t>(max_bytes, std::numeric_limits<std::uint32_t>::max());
        auto normalized = normalize_set(set);
        if (!normalized) return std::unexpected(std::move(normalized.error()));

        std::vector<std::string> exact, suffix;
        struct V4I { std::uint32_t first, last; };
        struct V6I { V6Bytes first, last; };
        std::vector<V4I> v4;
        std::vector<V6I> v6;
        std::vector<Rule> tail_rules;

        auto collect = [&](auto&& self, Rule const& r) -> void {
            if (r.type == "or") {
                for (auto const& c : r.children) self(self, c);
                return;
            }
            if (r.type == "domain") { exact.push_back(r.value); return; }
            if (r.type == "domain-suffix") { suffix.push_back(r.value); return; }
            if (r.type == "ip-cidr" || (ip_cidr_match_source && r.type == "source-ip-cidr")) {
                auto slash = r.value.find('/');
                auto parsed = platform::parse_ip_address(std::string_view(r.value).substr(0, slash));
                unsigned bits = 0;
                auto psv = std::string_view(r.value).substr(slash + 1);
                (void)std::from_chars(psv.data(), psv.data() + psv.size(), bits);
                if (parsed->size == 4) {
                    auto [lo, hi] = any_detail::ipv4_range(parsed->bytes, bits);
                    v4.push_back({lo, hi});
                } else {
                    auto [lo, hi] = any_detail::ipv6_range(parsed->bytes, bits);
                    v6.push_back({lo, hi});
                }
                return;
            }
            tail_rules.push_back(r);
        };
        for (auto const& r : normalized->rules) collect(collect, r);

        std::ranges::sort(exact);
        exact.erase(std::unique(exact.begin(), exact.end()), exact.end());
        std::ranges::sort(suffix);
        suffix.erase(std::unique(suffix.begin(), suffix.end()), suffix.end());
        any_detail::merge_v4(v4);
        any_detail::merge_v6(v6);

        std::string tail_beve;
        if (!tail_rules.empty()) {
            auto encoded = write_beve(RuleSet{std::move(tail_rules), 2});
            if (!encoded) return std::unexpected(std::move(encoded.error()));
            tail_beve = std::move(*encoded);
        }

        std::string arena, body;
        std::vector<std::pair<std::uint32_t, std::uint32_t>> exact_refs, suffix_refs;
        exact_refs.reserve(exact.size());
        suffix_refs.reserve(suffix.size());
        for (auto const& s : exact) {
            if (arena.size() > limit_bytes || s.size() > limit_bytes - arena.size())
                return std::unexpected(Error{ErrorCode::limit, "NXMM output exceeds budget"});
            exact_refs.emplace_back(static_cast<std::uint32_t>(arena.size()), static_cast<std::uint32_t>(s.size()));
            arena.append(s);
        }
        for (auto const& s : suffix) {
            if (arena.size() > limit_bytes || s.size() > limit_bytes - arena.size())
                return std::unexpected(Error{ErrorCode::limit, "NXMM output exceeds budget"});
            suffix_refs.emplace_back(static_cast<std::uint32_t>(arena.size()), static_cast<std::uint32_t>(s.size()));
            arena.append(s);
        }

        for (auto [off, len] : exact_refs) { write_u32(body, off); write_u32(body, len); }
        for (auto [off, len] : suffix_refs) { write_u32(body, off); write_u32(body, len); }
        for (auto const& r : v4) { write_u32(body, r.first); write_u32(body, r.last); }
        for (auto const& r : v6) {
            body.append(reinterpret_cast<char const*>(r.first.data()), 16);
            body.append(reinterpret_cast<char const*>(r.last.data()), 16);
        }
        body.append(arena);
        body.append(tail_beve);

        std::uint64_t total_size = kNxmmHeaderSize + body.size();
        if (total_size > limit_bytes)
            return std::unexpected(Error{ErrorCode::limit, "NXMM output exceeds budget"});
        std::uint64_t crc = fnv1a64({reinterpret_cast<std::uint8_t const*>(body.data()), body.size()});

        std::string out;
        out.reserve(static_cast<std::size_t>(total_size));
        out.append(kNxmmMagic);
        write_u32(out, 1u);
        write_u32(out, ip_cidr_match_source ? nxmm_flag_ip_cidr_source : 0u);
        write_u64(out, total_size);
        write_u32(out, static_cast<std::uint32_t>(exact.size()));
        write_u32(out, static_cast<std::uint32_t>(suffix.size()));
        write_u32(out, static_cast<std::uint32_t>(v4.size()));
        write_u32(out, static_cast<std::uint32_t>(v6.size()));
        write_u32(out, static_cast<std::uint32_t>(arena.size()));
        write_u32(out, static_cast<std::uint32_t>(tail_beve.size()));
        write_u64(out, crc);
        write_u64(out, 0u);
        out.append(body);
        return out;
    }

    auto nxmm_to_ruleset(MmapMatcher const& mm) -> std::expected<RuleSet, Error> {
        RuleSet set{{}, 2};
        std::uint64_t reserve_count = std::uint64_t(mm.exact_count()) + mm.suffix_count() + mm.v4_count() + mm.v6_count();
        set.rules.reserve(static_cast<std::size_t>(reserve_count));
        for (std::uint32_t i = 0; i < mm.exact_count(); ++i)
            set.rules.push_back({"domain", std::string(mm.exact_at(i)), {}});
        for (std::uint32_t i = 0; i < mm.suffix_count(); ++i)
            set.rules.push_back({"domain-suffix", std::string(mm.suffix_at(i)), {}});
        for (std::uint32_t i = 0; i < mm.v4_count(); ++i) {
            auto [lo, hi] = mm.v4_at(i);
            append_v4_cidrs(lo, hi, mm.ip_cidr_match_source(), set.rules);
        }
        for (std::uint32_t i = 0; i < mm.v6_count(); ++i) {
            auto [lo, hi] = mm.v6_at(i);
            append_v6_cidrs(lo, hi, mm.ip_cidr_match_source(), set.rules);
        }
        if (mm.tail_beve_bytes() > 0) {
            auto tail = parse_beve(mm.tail_beve());
            if (!tail) return std::unexpected(std::move(tail.error()));
            for (auto& r : tail->rules) set.rules.push_back(std::move(r));
        }
        return normalize_set(std::move(set));
    }

    auto parse_nxmm(std::string_view input) -> std::expected<RuleSet, Error> {
        auto mm = MmapMatcher::open_bytes(std::string(input));
        if (!mm) return std::unexpected(Error{ErrorCode::schema, std::move(mm.error())});
        return nxmm_to_ruleset(*mm);
    }

    auto Matcher::compile_nxmm(std::shared_ptr<MmapMatcher const> mmap) -> std::expected<Matcher, Error> {
        if (!mmap) return std::unexpected(Error{ErrorCode::invalid_rule, "null mmap matcher"});
        Matcher out;
        if (mmap->tail_beve_bytes() > 0) {
            auto tail = parse_beve(mmap->tail_beve());
            if (!tail) return std::unexpected(std::move(tail.error()));
            auto compiled = Matcher::compile(*tail);
            if (!compiled) return std::unexpected(std::move(compiled.error()));
            out = std::move(*compiled);
        }
        out.mmap_ = std::move(mmap);
        return out;
    }

    auto Matcher::eval_mmap(MmapMatcher const& mmap, Matcher const* tail, Prepared const& input,
                            bool match_source) noexcept -> Truth {
        bool unknown = false;
        if (mmap.has_domain()) {
            if (input.input.domain) {
                if (mmap.match_domain(*input.input.domain)) return Truth::yes;
            } else if (!input.domain_absent) {
                unknown = true;
            }
        }
        if (mmap.has_ip()) {
            if (match_source) {
                if (input.source_family) {
                    if (mmap.match_ip(input.source_address, input.source_family, input.match_mapped_ipv4))
                        return Truth::yes;
                } else {
                    unknown = true;
                }
            } else if (input.candidates) {
                for (auto const& c : *input.candidates) {
                    if (mmap.match_ip(c.bytes, c.size == 4 ? 4u : 6u, input.match_mapped_ipv4)) return Truth::yes;
                }
            } else if (input.input.ip) {
                if (mmap.match_ip(input.address, input.family, input.match_mapped_ipv4)) return Truth::yes;
            } else {
                unknown = true;
            }
        }
        if (tail) {
            for (auto root : tail->roots_) {
                auto v = tail->evaluate(root, input);
                if (v == Truth::yes) return Truth::yes;
                unknown |= (v == Truth::unknown);
            }
        }
        return unknown ? Truth::unknown : Truth::no;
    }
}
