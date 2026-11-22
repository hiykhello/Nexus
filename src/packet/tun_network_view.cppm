export module packet.tun_network_view;
import std;
import platform.netlink_abi;
import platform.netlink_codec;
import platform.netlink_socket;
import packet.tun_network_types;
import packet.tun_network_records;

export namespace packet::tun_network_detail {
    template <class Socket> class View {
        Socket &socket_;
        std::int32_t index_;
        platform::netlink::Clock::time_point deadline_;

      public:
        View(Socket &socket, std::int32_t index, platform::netlink::Clock::time_point deadline) noexcept : socket_(socket), index_(index), deadline_(deadline) {}
        auto link(std::optional<std::string_view> name = {}) -> std::expected<std::optional<LinkRecord>, nl::Failure> {
            std::optional<LinkRecord> found;
            auto result = socket_.dump(abi::RTM_GETLINK, abi::AF_UNSPEC, deadline_, [&](nl::Message message) -> std::expected<void, nl::Failure> {
                auto parsed = parse_link(message);
                if (!parsed) return std::unexpected(parsed.error());
                auto view = std::string_view(parsed->name.data(), std::char_traits<char>::length(parsed->name.data()));
                if (name ? view != *name : parsed->index != index_) return {};
                if (found) return nl::fail(nl::Error::protocol);
                found = *parsed;
                return {};
            });
            if (!result) return std::unexpected(result.error());
            return found;
        }
        template <class Visitor> auto addresses(std::uint8_t family, Visitor &&visitor) -> std::expected<void, nl::Failure> {
            return socket_.dump(abi::RTM_GETADDR, native_family(family), deadline_, [&](nl::Message message) -> std::expected<void, nl::Failure> {
                auto parsed = parse_address(message);
                if (!parsed) return std::unexpected(parsed.error());
                return visitor(*parsed);
            });
        }
        template <class Record=RouteRecord,class Visitor> auto routes(std::uint8_t family, Visitor &&visitor) -> std::expected<void, nl::Failure> {
            return socket_.dump(abi::RTM_GETROUTE, native_family(family), deadline_, [&](nl::Message message) -> std::expected<void, nl::Failure> {
                auto parsed = parse_route<Record>(message);
                if (!parsed) return std::unexpected(parsed.error());
                return visitor(*parsed);
            });
        }
        auto address(TunAddress const &desired) -> std::expected<std::optional<AddressRecord>, nl::Failure> {
            std::optional<AddressRecord> found;
            auto result = addresses(desired.family, [&](AddressRecord const &value) -> std::expected<void, nl::Failure> {
                if (value.index != std::uint32_t(index_) || value.address.family != desired.family || value.address.bytes != desired.bytes) return {};
                if (found) return nl::fail(nl::Error::protocol);
                found = value;
                return {};
            });
            if (!result) return std::unexpected(result.error());
            return found;
        }
        auto route(TunAddress const &desired) -> std::expected<std::optional<RouteRecord>, nl::Failure> {
            std::optional<RouteRecord> found;
            auto result = routes(desired.family, [&](RouteRecord const &value) -> std::expected<void, nl::Failure> {
                if (value.table != abi::RT_TABLE_MAIN || value.index != std::uint32_t(index_) || value.destination != desired) return {};
                if (found) return nl::fail(nl::Error::protocol);
                found = value;
                return {};
            });
            if (!result) return std::unexpected(result.error());
            return found;
        }
        auto route_conflict(TunAddress const &desired) -> std::expected<bool, nl::Failure> {
            bool conflict = false;
            auto result = routes(desired.family, [&](RouteRecord const &value) -> std::expected<void, nl::Failure> {
                if (value.table == abi::RT_TABLE_MAIN && value.index != std::uint32_t(index_) && contains(desired, value.destination)) conflict = true;
                return {};
            });
            if (!result) return std::unexpected(result.error());
            return conflict;
        }
    };
} // namespace packet::tun_network_detail
