export module platform.nftables;
import std;
import platform.socket_options;

export namespace platform::nftables {
    struct Prefix {
        std::uint8_t family=0, length=0;
        std::array<std::uint8_t,16> address{};
    };
    struct Redirect {
        std::uint16_t port=0;
        bool ipv4=false, ipv6=false, intercept_dns=false, exclude_mptcp=false;
        std::uint32_t socket_mark=0;
        std::optional<RoutingMarkFilter> include_mark, exclude_mark;
        std::span<Prefix const> excludes, protected_destinations, local_destinations;
    };
    struct Transaction {
        std::vector<std::uint8_t> bytes;
        std::uint32_t end=0;
    };
    using Clock=std::chrono::steady_clock;
    [[nodiscard]] auto encode(std::string_view table,Redirect const*,std::uint32_t first)
        -> std::expected<Transaction,std::error_code>;
    class Table {
        int socket_=-1;
        std::string name_;
        std::uint32_t sequence_=1;
        bool owned_=false;
        auto exchange(Transaction const&,Clock::time_point) -> std::error_code;
    public:
        Table()=default;
        Table(Table const&)=delete;
        auto operator=(Table const&) -> Table& = delete;
        ~Table();
        [[nodiscard]] auto start(Redirect const&,Clock::time_point) -> std::error_code;
        [[nodiscard]] auto stop(Clock::time_point) -> std::error_code;
    };
}
