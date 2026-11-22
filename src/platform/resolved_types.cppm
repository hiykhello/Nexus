export module platform.resolved_types;
import std;
export namespace platform::resolved {
    struct Server {
        std::array<std::uint8_t,16> address{};
        std::array<char,256> name{};
        std::uint16_t port=0;
        std::uint8_t family=0;
        auto operator==(Server const&) const noexcept -> bool = default;
    };
    struct Domain {
        std::array<char,256> name{};
        bool route_only=false;
        auto operator==(Domain const&) const noexcept -> bool = default;
    };
    struct Snapshot {
        std::array<Server,8> servers{};
        std::array<Domain,8> domains{};
        std::uint8_t server_count=0,domain_count=0;
        auto operator==(Snapshot const&) const noexcept -> bool = default;
    };
}
