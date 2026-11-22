export module dns.fakeip_request;
import std;
import dns.fakeip_registry;
import dns.fakeip_target;
import dns.fakeip_shared;
import socks5;
export namespace dns {
    struct FakeIpRequest {
        socks5::Request request;
        // Null for an ordinary destination. Registry must outlive this handle;
        // release after all connection activity, on the registry executor.
        std::unique_ptr<FakeIpTarget> target;
    };
    struct SharedFakeIpRequest {
        socks5::Request request;
        std::unique_ptr<FakeIpShared::Target> target;
    };
    // Converts IPv4 and IPv4-mapped IPv6 FakeIPs to their domain before route
    // preflight and resolution. Ordinary addresses and domains pass through.
    [[nodiscard]] auto translate_fakeip_request(FakeIpRegistry& registry,socks5::Request const& request,
        std::uint64_t view,std::chrono::steady_clock::time_point now)
        -> std::expected<FakeIpRequest,FakeIpRegistryError>;
    [[nodiscard]] auto translate_fakeip_request(FakeIpShared& registry,socks5::Request const& request,
        std::uint64_t view) -> std::expected<SharedFakeIpRequest,FakeIpRegistryError>;
    // Reject every resolved address in a registered FakeIP range, including
    // mapped IPv4, before it is considered for a network connection.
    [[nodiscard]] auto validate_fakeip_resolution(FakeIpRegistry const& registry,
        std::span<std::uint8_t const> address) -> std::expected<void,FakeIpRegistryError>;
    [[nodiscard]] auto validate_fakeip_resolution(FakeIpShared const& registry,
        std::span<std::uint8_t const> address) -> std::expected<void,FakeIpRegistryError>;
}
