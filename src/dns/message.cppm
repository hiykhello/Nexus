export module nexus.dns.message;
import std;

export namespace nexus::dns {
    using Bytes = std::vector<std::uint8_t>;
    enum class MessageError { invalid_name, malformed, mismatch, truncated, limit, unsupported, alias_loop };
    enum class Section { answer, authority, additional };
    struct Question {
        std::string name;
        std::uint16_t type;
        std::uint16_t klass = 1;
    };
    struct Record {
        std::string name;
        std::uint16_t type, klass;
        std::uint32_t ttl;
        Section section;
        std::size_t data_offset, data_length;
        // CNAME is decoded while validating compression boundaries.
        std::optional<std::string> cname;
    };
    struct Edns {
        std::uint16_t udp_payload_size;
        std::uint8_t version;
        std::uint16_t flags;
        std::size_t option_count;
    };
    struct Response {
        std::uint16_t flags;
        std::uint16_t rcode;
        // Retain the full wire message: compressed RDATA may refer to it.
        Bytes wire;
        std::vector<Record> records;
        std::optional<Edns> edns;
    };
    struct Address {
        std::array<std::uint8_t, 16> bytes{};
        std::uint8_t size;
    };
    struct AddressAnswer {
        std::string canonical_name;
        // Names traversed, including the initial and terminal names.
        std::vector<std::string> chain;
        std::vector<Address> addresses;
        // Minimum across the followed CNAME chain and returned address RRset.
        // An empty answer is not a negative-cache result.
        std::optional<std::uint32_t> ttl;
    };
    // Accepts NOERROR IN A/AAAA only; EDNS requires explicit opt-in and no options.
    // Source, port and authenticity must be checked separately by the transport.
    [[nodiscard]] auto parse_addresses(std::span<std::uint8_t const> message, std::uint16_t id,
        Question const& expected, bool accept_edns=false) -> std::expected<AddressAnswer, MessageError>;
    // Validate an NXDOMAIN CNAME chain without treating it as a positive answer.
    [[nodiscard]] auto parse_nxdomain_alias(std::span<std::uint8_t const> message, std::uint16_t id,
        Question const& expected, bool accept_edns=false) -> std::expected<AddressAnswer, MessageError>;
    // For an already validated negative response, find the closest covering IN
    // authority SOA and return min(SOA TTL, MINIMUM). No local cap is applied.
    // This does not establish that the response is actually negative or authentic.
    [[nodiscard]] auto negative_ttl(Response const& response, std::string_view name)
        -> std::optional<std::uint32_t>;
    // A restricted ASCII hostname query; the caller supplies an unpredictable ID.
    [[nodiscard]] auto make_query(std::uint16_t id, Question const& question) -> std::expected<Bytes, MessageError>;
    // EDNS(0), no options or DNSSEC request; payload is bounded to 512..4096 bytes.
    [[nodiscard]] auto make_edns_query(std::uint16_t id, Question const& question, std::uint16_t payload)
        -> std::expected<Bytes, MessageError>;
    // Checks message identity, question and framing, not source endpoint or DNSSEC.
    [[nodiscard]] auto parse_response(std::span<std::uint8_t const> message, std::uint16_t id,
        Question const& expected) -> std::expected<Response, MessageError>;
}
