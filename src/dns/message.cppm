export module dns.message;
import std;

export namespace dns {
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
    struct QueryOption { std::uint16_t code;Bytes data; };
    struct QueryEdns { std::uint16_t udp_payload_size;std::uint8_t version;bool dnssec_ok;std::vector<QueryOption> options; };
    struct ClientSubnet {
        std::uint16_t family;std::uint8_t prefix;std::array<std::uint8_t,16> address{};
        auto operator<=>(ClientSubnet const&) const = default;
    };
    [[nodiscard]] inline auto valid_client_subnet(ClientSubnet const& subnet) noexcept -> bool {
        auto maximum=subnet.family==1 ? 32u : subnet.family==2 ? 128u : 0u;
        if(!maximum || subnet.prefix>maximum)return false;
        auto bytes=(std::size_t(subnet.prefix)+7)/8;
        if(subnet.prefix%8 && (subnet.address[bytes-1] & ((1u<<(8-subnet.prefix%8))-1u)))return false;
        return std::ranges::all_of(std::span(subnet.address).subspan(bytes),[](auto value){return value==0;});
    }
    [[nodiscard]] auto query_client_subnet(QueryEdns const& edns) -> std::expected<std::optional<ClientSubnet>,MessageError>;
    inline constexpr std::uint16_t checking_disabled_flag=0x0010;
    inline constexpr std::uint16_t authenticated_data_flag=0x0020;
    struct QueryMessage { std::uint16_t id,flags;Question question;std::optional<QueryEdns> edns; };
    // Conservative retained size for one parsed listener-owned question.
    // Includes container capacities and inline object; excludes allocator
    // overhead, parser temporaries and copies made by execution programs.
    [[nodiscard]] auto listener_query_cost(QueryMessage const& query) noexcept -> std::optional<std::size_t>;
    // The only upstream-query state needed after an exchange completes to
    // validate and restore ECS. Opaque EDNS options need not be retained.
    struct ResponseEcsView {std::optional<ClientSubnet> subnet;};
    [[nodiscard]] auto response_ecs_view(QueryMessage const& query) -> std::expected<ResponseEcsView,MessageError>;
    // Replace or remove ECS while preserving all unrelated EDNS options. A
    // replacement creates an EDNS(0) OPT when the query has none.
    [[nodiscard]] auto set_query_client_subnet(QueryMessage& query,std::optional<ClientSubnet> subnet)
        -> std::expected<void,MessageError>;
    // Parses one QUERY question and an optional EDNS OPT, retaining options.
    [[nodiscard]] auto parse_query(std::span<std::uint8_t const> message) -> std::expected<QueryMessage,MessageError>;
    // A bounded header-only error response when a malformed request has a
    // usable DNS header. Incoming responses and short packets are ignored.
    [[nodiscard]] auto query_error_response(std::span<std::uint8_t const> message) -> std::optional<Bytes>;
    [[nodiscard]] auto encode_query(QueryMessage const& query) -> std::expected<Bytes,MessageError>;
    struct Response {
        std::uint16_t flags;
        std::uint16_t rcode;
        // Retain the full wire message: compressed RDATA may refer to it.
        Bytes wire;
        std::vector<Record> records;
        std::optional<Edns> edns;
    };
    // Validate an upstream ECS option against the originating query. Other
    // EDNS options remain opaque and an absent ECS response is permitted.
    [[nodiscard]] auto validate_response_ecs(QueryMessage const& query,Response const& response) -> std::expected<void,MessageError>;
    [[nodiscard]] auto validate_response_ecs(ResponseEcsView const& view,Response const& response) -> std::expected<void,MessageError>;
    // Echo a requested ECS with scope zero when the upstream omitted it.
    [[nodiscard]] auto complete_response_ecs(QueryMessage const& query,Response const& response) -> std::expected<Bytes,MessageError>;
    // Restore the client's ECS/EDNS view after an upstream query override.
    [[nodiscard]] auto restore_response_ecs(QueryMessage const& client,QueryMessage const& upstream,Response const& response)
        -> std::expected<Bytes,MessageError>;
    [[nodiscard]] auto restore_response_ecs(QueryMessage const& client,ResponseEcsView const& upstream,Response const& response)
        -> std::expected<Bytes,MessageError>;
    [[nodiscard]] auto encode_response(Response const& response,std::uint16_t id,std::optional<std::uint32_t> ttl) -> std::expected<Bytes,MessageError>;
    // Validate every record before modifying either the wire or parsed TTLs.
    [[nodiscard]] auto rewrite_response(Response& response,std::uint16_t id,std::optional<std::uint32_t> ttl) -> std::expected<void,MessageError>;
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
    // Validate the same restricted ASCII names accepted by make_query, strip
    // a trailing root dot and lowercase ASCII in place. Root remains ".".
    // Invalid inputs are left unchanged.
    [[nodiscard]] auto canonicalize_name(std::string& name) -> bool;
    // Accepts NOERROR IN A/AAAA only; EDNS requires explicit opt-in. An ECS
    // response is accepted only when it matches the supplied request subnet.
    // Source, port and authenticity must be checked separately by the transport.
    [[nodiscard]] auto parse_addresses(std::span<std::uint8_t const> message, std::uint16_t id,
        Question const& expected, bool accept_edns=false,std::optional<ClientSubnet> subnet={}) -> std::expected<AddressAnswer, MessageError>;
    // Validate an NXDOMAIN CNAME chain without treating it as a positive answer.
    [[nodiscard]] auto parse_nxdomain_alias(std::span<std::uint8_t const> message, std::uint16_t id,
        Question const& expected, bool accept_edns=false,std::optional<ClientSubnet> subnet={}) -> std::expected<AddressAnswer, MessageError>;
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
    // Consume an owned wire buffer after validation without copying its bytes.
    [[nodiscard]] auto parse_owned_response(Bytes message,std::uint16_t id,
        Question const& expected) -> std::expected<Response,MessageError>;
}
namespace dns {
    auto copy_response_wire(Response const&, std::uint16_t, std::optional<std::uint32_t>)
        -> std::expected<Bytes, MessageError>;
}
