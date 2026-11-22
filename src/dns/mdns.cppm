export module dns.mdns;
import std;
import platform.ip_address;

export namespace dns::mdns {
    inline constexpr std::uint16_t port = 5353;
    inline constexpr std::string_view ipv4_multicast = "224.0.0.251";
    inline constexpr std::string_view ipv6_multicast = "ff02::fb";

    enum class RecordType : std::uint16_t { a = 1, ptr = 12, txt = 16, aaaa = 28, srv = 33, any = 255 };

    struct MdnsRecord {
        std::string name;
        std::uint16_t type = 0;
        std::uint16_t klass = 1;
        bool cache_flush = false;
        std::uint32_t ttl = 0;
        std::optional<platform::IpAddress> address;
        std::string target;
        std::uint16_t srv_priority = 0;
        std::uint16_t srv_weight = 0;
        std::uint16_t srv_port = 0;
        std::vector<std::string> txt_strings;
    };

    [[nodiscard]] auto is_mdns_name(std::string_view name) noexcept -> bool;
    [[nodiscard]] auto make_mdns_query(std::string_view name, RecordType type = RecordType::any,
                                       bool unicast_response = false) -> std::expected<std::vector<std::uint8_t>, std::string>;
    [[nodiscard]] auto parse_mdns_response(std::span<std::uint8_t const> wire)
        -> std::expected<std::vector<MdnsRecord>, std::string>;

    class MdnsCache {
        struct Entry {
            MdnsRecord record;
            std::uint64_t expires_at_sec = 0;
        };
        mutable std::mutex mutex_;
        std::vector<Entry> entries_;
        std::size_t max_entries_;
    public:
        explicit MdnsCache(std::size_t max_entries = 512) noexcept : max_entries_(max_entries) {}
        auto ingest(std::span<MdnsRecord const> records, std::uint64_t now_sec) -> void;
        [[nodiscard]] auto lookup(std::string_view name, std::uint16_t type, std::uint64_t now_sec) const
            -> std::vector<MdnsRecord>;
        auto prune_expired(std::uint64_t now_sec) -> std::size_t;
        [[nodiscard]] auto size() const noexcept -> std::size_t;
    };
}
