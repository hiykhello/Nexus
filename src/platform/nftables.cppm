export module platform.nftables;
import std;
import platform.socket_options;

export namespace platform::nftables {
    struct Prefix {
        std::uint8_t family=0, length=0;
        std::array<std::uint8_t,16> address{};
    };
    struct UidRange {
        std::uint32_t min=0, max=0;
    };
    struct Redirect {
        std::uint16_t port=0;
        bool ipv4=false, ipv6=false, intercept_dns=false, exclude_mptcp=false;
        std::uint32_t socket_mark=0;
        std::optional<RoutingMarkFilter> include_mark, exclude_mark;
        std::span<Prefix const> excludes, protected_destinations, local_destinations, includes{};
        std::uint32_t input_mark=0, output_mark=0, reset_mark=0, tproxy_mark=0;
        std::uint16_t tproxy_port=0;
        std::span<UidRange const> include_uids{}, exclude_uids{};
        std::span<std::array<char,16> const> include_interfaces{}, exclude_interfaces{};
        std::span<std::array<std::uint8_t,6> const> include_macs{}, exclude_macs{};
    };
    struct Transaction {
        std::vector<std::uint8_t> bytes;
        std::uint32_t end=0;
    };
    using Clock=std::chrono::steady_clock;
    [[nodiscard]] auto encode(std::string_view table,Redirect const*,std::uint32_t first,bool replace_existing=false)
        -> std::expected<Transaction,std::error_code>;
    class Table {
        int socket_=-1;
        std::string name_;
        std::uint32_t sequence_=1;
        bool owned_=false;
        auto close_socket() noexcept -> void;
        auto exchange(Transaction const&,Clock::time_point) -> std::error_code;
    public:
        Table()=default;
        Table(Table const&)=delete;
        auto operator=(Table const&) -> Table& = delete;
        ~Table();
        [[nodiscard]] auto start(Redirect const&,Clock::time_point) -> std::error_code;
        [[nodiscard]] auto replace(Redirect const&,Clock::time_point) -> std::error_code;
        [[nodiscard]] auto stop(Clock::time_point) -> std::error_code;
    };
}
