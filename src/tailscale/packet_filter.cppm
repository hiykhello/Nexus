export module tailscale.packet_filter;
import std;

export namespace tailscale::packet_filter {
    inline constexpr std::size_t max_json_bytes=4u*1024*1024;
    inline constexpr std::size_t max_chunks=64,max_rules=512,max_addresses=8192,max_protocols=256,max_name_bytes=128;
    enum class Error { json,schema,unsupported,limit,address,duplicate,allocation };
    // IPv4 occupies the first four bytes; IPv4-mapped IPv6 remains IPv6.
    struct Address {
        std::array<std::uint8_t,16> bytes{};
        std::uint8_t family=0;
        auto operator==(Address const&) const -> bool = default;
    };
    struct Range {
        Address first,last;
        auto contains(Address const& address) const noexcept -> bool;
    };
    struct Destination {Range range;std::uint16_t first=0,last=0;};
    struct Rule {
        std::vector<Range> sources;
        std::vector<Destination> destinations;
        std::array<std::uint64_t,4> protocols{};
        auto matches(Address const& source,Address const& destination,std::uint8_t protocol,std::uint16_t port) const noexcept -> bool;
    };
    struct Chunk {std::string name;std::vector<Rule> rules;};
    // All rule predicates require source and destination of the same IP family.
    // Stateless rules only: this does not parse packets, track return flows,
    // authenticate peers, implement capability grants or authorize installation.
    // In particular, ICMP and protocols without ports require separate ingress
    // rules; a match with port zero is not an authorization decision.
    // SrcIPs, DstPorts and IPProto have at most 256 entries per rule.
    // The owner must revoke the surrounding session on any update error.
    // Access and updates are serialized on one executor.
    class Filter {
        std::vector<Chunk> chunks_;
        bool received_=false;
    public:
        Filter()=default;
        Filter(Filter const&)=delete;
        auto operator=(Filter const&) -> Filter& = delete;
        // Missing and JSON null leave that field unchanged. Non-null legacy
        // replaces "base" before named updates. An empty list clears only
        // that chunk; other named chunks can still allow matches.
        auto update(std::optional<std::string_view> legacy,std::optional<std::string_view> named) noexcept -> std::expected<void,Error>;
        auto clear() noexcept -> void {chunks_.clear();received_=false;}
        auto received() const noexcept -> bool {return received_;}
        auto chunks() const noexcept -> std::span<Chunk const> {return chunks_;}
        auto matches(Address const& source,Address const& destination,std::uint8_t protocol,std::uint16_t port) const noexcept -> bool;
    };
}
