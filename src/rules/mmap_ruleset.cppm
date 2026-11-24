// Read-only memory-mapped binary rule-set (NXMM v1) zero-copy matcher interface.
export module rules:mmap;
import std;
import rulefile;
import rules.any_index;

export namespace rules {
    inline constexpr std::uint32_t nxmm_flag_ip_cidr_source = 1u;

    class MmapMatcher {
        struct SpanRef { std::uint32_t off, len; };
        struct V4Range { std::uint32_t first, last; };
        struct V6Range { std::array<std::uint8_t, 16> first, last; };

        std::shared_ptr<void const> owner_;
        std::span<std::uint8_t const> buf_;
        std::uint32_t exact_count_ = 0, suffix_count_ = 0, v4_count_ = 0, v6_count_ = 0;
        std::uint32_t arena_bytes_ = 0, tail_beve_bytes_ = 0;
        std::size_t exact_off_ = 64, suffix_off_ = 64, v4_off_ = 64, v6_off_ = 64, arena_off_ = 64, tail_off_ = 64;
        bool ip_cidr_match_source_ = false;

        [[nodiscard]] auto init_and_validate() -> std::expected<void, std::string>;
        [[nodiscard]] auto read_span(std::size_t table_off, std::size_t idx) const noexcept -> std::string_view;
        [[nodiscard]] auto search_domains(std::size_t table_off, std::uint32_t count, std::string_view key) const noexcept -> bool;
        [[nodiscard]] auto search_v4(std::uint32_t ip) const noexcept -> bool;
        [[nodiscard]] auto search_v6(std::array<std::uint8_t, 16> const& ip) const noexcept -> bool;

    public:
        MmapMatcher() = default;

        [[nodiscard]] static auto open_file(std::string_view path) -> std::expected<MmapMatcher, std::string>;
        [[nodiscard]] static auto open_bytes(std::string bytes) -> std::expected<MmapMatcher, std::string>;
        [[nodiscard]] static auto from_mapped(std::shared_ptr<rulefile::MappedFile const> mapped)
            -> std::expected<MmapMatcher, std::string>;

        [[nodiscard]] auto exact_count() const noexcept -> std::uint32_t { return exact_count_; }
        [[nodiscard]] auto suffix_count() const noexcept -> std::uint32_t { return suffix_count_; }
        [[nodiscard]] auto v4_count() const noexcept -> std::uint32_t { return v4_count_; }
        [[nodiscard]] auto v6_count() const noexcept -> std::uint32_t { return v6_count_; }
        [[nodiscard]] auto arena_bytes() const noexcept -> std::uint32_t { return arena_bytes_; }
        [[nodiscard]] auto tail_beve_bytes() const noexcept -> std::uint32_t { return tail_beve_bytes_; }
        [[nodiscard]] auto ip_cidr_match_source() const noexcept -> bool { return ip_cidr_match_source_; }
        [[nodiscard]] auto has_domain() const noexcept -> bool { return exact_count_ > 0 || suffix_count_ > 0; }
        [[nodiscard]] auto has_ip() const noexcept -> bool { return v4_count_ > 0 || v6_count_ > 0; }
        [[nodiscard]] auto byte_size() const noexcept -> std::size_t { return buf_.size(); }

        [[nodiscard]] auto exact_at(std::size_t i) const noexcept -> std::string_view { return read_span(exact_off_, i); }
        [[nodiscard]] auto suffix_at(std::size_t i) const noexcept -> std::string_view { return read_span(suffix_off_, i); }
        [[nodiscard]] auto v4_at(std::size_t i) const noexcept -> std::pair<std::uint32_t, std::uint32_t>;
        [[nodiscard]] auto v6_at(std::size_t i) const noexcept -> std::pair<std::array<std::uint8_t, 16>, std::array<std::uint8_t, 16>>;
        [[nodiscard]] auto tail_beve() const noexcept -> std::string_view {
            if (!tail_beve_bytes_) return {};
            return {reinterpret_cast<char const*>(buf_.data() + tail_off_), tail_beve_bytes_};
        }

        [[nodiscard]] auto match_domain(std::string_view domain) const noexcept -> bool;
        [[nodiscard]] auto match_ip(std::array<std::uint8_t, 16> const& bytes, unsigned family,
                                    bool match_mapped_v4 = true) const noexcept -> bool;
    };
}
