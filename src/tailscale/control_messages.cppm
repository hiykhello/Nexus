export module tailscale.control_messages;
import std;
import containers.inplace_vector;
import tailscale.control;

export namespace tailscale::control_messages {
    inline constexpr std::size_t max_json_bytes=4<<20,max_peers=64,max_prefixes=32,max_endpoints=16;
    enum class Error { state,http_status,size,json,schema,limit,identity,address,duplicate,unsupported_security,capacity,overlap };
    struct Failure {Error error;unsigned status=0;auto operator==(Failure const&) const -> bool = default;};
    enum class Presence { missing,null_value,value };
    // This is validated JSON syntax, not a decoded string/URL. Every view
    // borrows unchanged caller input and expires before that frame is reused.
    struct JsonField {Presence presence=Presence::missing;std::string_view json;};
    enum class RegistrationState { authorized,pending,expired,denied };
    struct Prefix {
        std::array<std::uint8_t,16> address{};
        std::uint8_t family=0,bits=0;
        auto operator==(Prefix const&) const -> bool = default;
    };
    struct Endpoint {
        std::array<std::uint8_t,16> address{};
        std::uint8_t family=0;
        std::uint16_t port=0;
        auto operator==(Endpoint const&) const -> bool = default;
    };
    struct RegisterRequest {
        control::NodePublic node;
        std::string_view auth_key,hostname,os,client_version;
        bool ephemeral=false;
        std::span<Prefix const> advertise_routes{};
    };
    // Exclusive lease on the final caller-owned JSON buffer. Retain through
    // the H2 body's release point; success/failure/abandonment clears secrets.
    // The backing storage outlives this lease and is not reused concurrently.
    class RegisterWire {
        std::span<std::uint8_t> bytes_;
        explicit RegisterWire(std::span<std::uint8_t>) noexcept;
        friend auto encode_register(std::span<std::uint8_t>,RegisterRequest const&) noexcept -> std::expected<RegisterWire,Failure>;
    public:
        ~RegisterWire();
        RegisterWire(RegisterWire const&)=delete;
        auto operator=(RegisterWire const&) -> RegisterWire& = delete;
        RegisterWire(RegisterWire&&) noexcept;
        auto operator=(RegisterWire&&) noexcept -> RegisterWire&;
        auto bytes() const noexcept -> std::span<std::uint8_t const> {return bytes_;}
        auto clear() noexcept -> void;
    };
    struct RegisterReply {
        RegistrationState state=RegistrationState::pending;
        bool machine_authorized=false;
        JsonField error,auth_url,user,login;
    };
    // Non-200 is a status failure; transport failures never enter this parser.
    // Unknown keys are deliberately rejected by this initial narrow schema.
    auto encode_register(std::span<std::uint8_t>,RegisterRequest const&) noexcept -> std::expected<RegisterWire,Failure>;
    auto parse_register(unsigned status,std::span<std::uint8_t const>) noexcept -> std::expected<RegisterReply,Failure>;
    enum class MapRequestMode { endpoints, stream };
    using DiscoKey = std::array<std::uint8_t,32>;
    [[nodiscard]] auto encode_map_request(control::NodePublic const& node, MapRequestMode mode,
        std::span<const Endpoint> endpoints = {}, std::optional<DiscoKey> const& disco = {},
        std::span<const Prefix> advertise_routes = {}) -> std::expected<std::string, Failure>;
    struct PeerCandidate {
        std::int64_t id=0,home_derp=0;
        control::NodePublic key;
        JsonField original_node,name,stable_id,key_expiry,disco_key,tags;
        containers::inplace_vector<Prefix,max_prefixes> addresses,allowed_ips;
        containers::inplace_vector<Endpoint,max_endpoints> endpoints;
        Presence allowed_ips_presence=Presence::missing;
        bool machine_authorized=false,expired=false;
        std::optional<std::chrono::sys_seconds> not_after;
        std::optional<DiscoKey> discovery;
    };
    struct DecodeOrigin {
        control::NodePublic local_node;
        std::uint64_t connection_generation=0,stream_generation=0;
    };
    enum class MapMode { unchanged,full,delta };
    struct MapView {
        DecodeOrigin origin;
        MapMode mode=MapMode::unchanged;
        bool keep_alive=false;
        JsonField original_map,session_handle,sequence,derp_map,dns_config,domain,control_time;
        Presence self_presence=Presence::missing,peers_presence=Presence::missing,changed_presence=Presence::missing,removed_presence=Presence::missing;
        PeerCandidate const* self=nullptr;
        std::span<PeerCandidate const> peers,changed;
        std::span<std::int64_t const> removed;
    };
    struct DerpNode {
        std::uint16_t region, port;
        std::string host, ipv4, ipv6;
    };
    using DerpNodes = std::vector<DerpNode>;
    // A missing Regions field preserves the previous snapshot. An empty
    // Regions object supplies an empty replacement snapshot.
    auto derp_nodes(JsonField field) noexcept -> std::expected<std::optional<DerpNodes>, Failure>;
    // Borrowed untrusted JSON; valid only until the Map frame is reused.
    // This is not an authorization or an installable policy.
    struct FilterFields {JsonField legacy,named;};
    // Scratch storage for one non-installable candidate transaction. Parsing
    // never changes a live peer table, route, ACL, checkpoint or key owner.
    // The input outlives this object/view. On error all candidate access fails;
    // future policy/TKA code must authorize before any installation API exists.
    class MapCandidate {
        DecodeOrigin origin_;
        MapMode mode_=MapMode::unchanged;
        bool ready_=false,keep_alive_=false;
        JsonField original_map_,session_handle_,sequence_,derp_map_,dns_config_,domain_,control_time_;
        Presence self_presence_=Presence::missing,peers_presence_=Presence::missing,changed_presence_=Presence::missing,removed_presence_=Presence::missing;
        std::optional<PeerCandidate> self_;
        containers::inplace_vector<PeerCandidate,max_peers> peers_,changed_;
        containers::inplace_vector<std::int64_t,max_peers> removed_;
        auto parse(std::span<std::uint8_t const>,DecodeOrigin const&,FilterFields*) noexcept -> std::expected<void,Failure>;
        friend auto parse_map(std::span<std::uint8_t const>,DecodeOrigin const&,MapCandidate&) noexcept -> std::expected<void,Failure>;
        friend auto parse_map_projection(std::span<std::uint8_t const>,DecodeOrigin const&,MapCandidate&,FilterFields&) noexcept -> std::expected<void,Failure>;
    public:
        MapCandidate()=default;
        MapCandidate(MapCandidate const&)=delete;
        auto operator=(MapCandidate const&) -> MapCandidate& = delete;
        MapCandidate(MapCandidate&&)=delete;
        auto operator=(MapCandidate&&) -> MapCandidate& = delete;
        auto clear() noexcept -> void;
        auto view() const noexcept -> std::expected<MapView,Failure>;
    };
    auto parse_map(std::span<std::uint8_t const>,DecodeOrigin const&,MapCandidate&) noexcept -> std::expected<void,Failure>;
    // Only for non-installable Map projection. The consumer must synchronously
    // validate both filter fields and revoke the complete stream on failure.
    // TKA and unsupported node capabilities remain rejected.
    auto parse_map_projection(std::span<std::uint8_t const>,DecodeOrigin const&,MapCandidate&,FilterFields&) noexcept -> std::expected<void,Failure>;
}
