module;
#include <proxy/proxy_macros.h>
#include <boost/capy/buffers.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/cond.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/resolver.hpp>
export module nexus.proxy;
import std;
import proxy.v4;
import nexus.socks5;
import nexus.rules;
import nexus.http.connect;
import nexus.proxy.session_quota;
#ifdef NEXUS_TEST_FAKEIP
import nexus.dns.fakeip_shared;
#endif
export namespace nexus::proxy { enum class TlsKeyExchange { x25519, x25519_mlkem768, x25519_mlkem768_only }; }
namespace nexus::proxy {
    namespace capy = boost::capy;
    namespace io = boost::corosio;
    using Clock = std::chrono::steady_clock;

    auto valid_destination(io::endpoint const& endpoint) noexcept -> bool {
        auto address=endpoint.address();
        if (!endpoint.port() || address.is_unspecified()) return false;
        if (!address.is_v6()) return true;
        auto bytes=address.to_v6().to_bytes();
        bool mapped=std::ranges::all_of(std::span(bytes).first<10>(),[](auto b) { return b==0; }) &&
                    bytes[10]==255 && bytes[11]==255;
        return !mapped || std::ranges::any_of(std::span(bytes).last<4>(),[](auto b) { return b!=0; });
    }

    struct Session;
    enum class TunnelConnectResult { connected, retryable, failed, timeout };
    PRO_DEF_MEM_DISPATCH(TunnelConnect, connect);
    PRO_DEF_MEM_DISPATCH(TunnelSend, send);
    PRO_DEF_MEM_DISPATCH(TunnelRead, read);
    PRO_DEF_MEM_DISPATCH(TunnelUpload, upload);
    PRO_DEF_MEM_DISPATCH(TunnelDownload, download);
    PRO_DEF_MEM_DISPATCH(TunnelCancel, cancel);
    PRO_DEF_MEM_DISPATCH(TunnelCloseOutput, close_output);
    struct TunnelFacade : pro::facade_builder
        ::add_convention<TunnelConnect, capy::task<TunnelConnectResult>(io::endpoint)>
        ::add_convention<TunnelSend, capy::task<bool>(std::span<std::uint8_t const>)>
        ::add_convention<TunnelRead, capy::task<std::expected<std::size_t,std::string>>(std::span<std::uint8_t>)>
        ::add_convention<TunnelUpload, capy::task<bool>()>
        ::add_convention<TunnelDownload, capy::task<bool>()>
        ::add_convention<TunnelCloseOutput, capy::task<bool>()>
        ::add_convention<TunnelCancel, void() noexcept>::build {};
    using TunnelFactory = std::function<pro::proxy<TunnelFacade>(Session&,io::io_context&)>;
    using InboundFactory = std::function<capy::task<>(Session&,io::io_context&,rules::RouteMatcher const&)>;
    struct DnsState;

    struct Session {
        // Destroyed last, after sockets and all owners of this session.
        std::optional<SessionQuota::Lease> quota;
        io::tcp_socket client;
        io::tcp_socket target;
        std::unique_ptr<io::resolver> resolver;
        DnsState* dns = nullptr;
#ifdef NEXUS_TEST_FAKEIP
        // Borrowed from the server, which outlives its suspended sessions.
        dns::FakeIpShared* fakeip = nullptr;
        std::unique_ptr<dns::FakeIpShared::Target> fakeip_target;
        std::uint64_t fakeip_view=0;
#endif
        // Borrowed from the active DNS query on this session's executor.
        void* dns_operation = nullptr;
        void (*cancel_dns)(void*) noexcept = nullptr;
        // The server retains this snapshot until the context destroys its tasks.
        std::vector<TunnelFactory> const* tunnel_factories = nullptr;
        pro::proxy<TunnelFacade> tunnel;
        Clock::time_point started = Clock::now();
        Clock::time_point touched = started;
        std::stop_source stop;
        // The server registry only borrows this session and outlives its task.
        std::vector<Session*>* registry = nullptr;
        bool relaying = false;
        bool closed = false;
        bool done = false;
        bool http_draining = false;
        Clock::time_point http_drain_started{};
        explicit Session(io::io_context& ctx);
        ~Session();
        auto close() noexcept -> void;
    };

    // The root task owns the session. Capy's trampoline invokes this handler
    // before destroying that task's frame; abandonment invokes no handler.
    inline auto session_error(Session& session) {
        return [&session](std::exception_ptr) noexcept {
            session.close(); session.done=true;
        };
    }

    struct Credentials {
        std::array<std::uint8_t, 255> username{}, password{};
        std::uint8_t username_size = 0, password_size = 0;
    };
#ifdef NEXUS_ENABLE_VLESS
    auto make_vless_inbound_factory(std::string_view certificate,std::string_view key,std::span<std::string const> users)
        -> std::expected<InboundFactory,std::string>;
    auto make_vless_factory(std::string_view host, std::uint16_t port, std::string_view uuid_file,
        std::string_view server_name, std::string_view ca_file, TlsKeyExchange key_exchange, std::optional<std::size_t> bootstrap) -> std::expected<TunnelFactory,std::string>;
#endif

#ifdef NEXUS_ENABLE_SS2022
    auto make_shadowsocks_inbound_factory(std::span<std::uint8_t const> key) -> std::expected<InboundFactory,std::string>;
    auto make_shadowsocks_factory(std::string_view host,std::uint16_t port,std::span<std::uint8_t const> key,
        std::optional<std::size_t> bootstrap)
        -> std::expected<TunnelFactory,std::string>;
#endif

    auto resolve_bootstrap(Session& session, io::io_context& context, std::size_t selected,
                           std::string name, std::uint16_t port) -> capy::task<std::optional<std::vector<io::endpoint>>>;
#ifdef NEXUS_ENABLE_SOCKS_UDP
    auto resolve_udp_domain(Session& session, io::io_context& context, std::string name,
                            std::uint16_t port, Clock::time_point deadline) -> capy::task<std::optional<std::vector<io::endpoint>>>;
#endif
    auto dial(Session& session, io::io_context& context,
              rules::RouteMatcher const& policy, socks5::Request const& request) -> capy::task<std::uint8_t>;
    auto forward_http(Session& session, io::io_context& context,
                      rules::RouteMatcher const& policy, std::string_view input) -> capy::task<>;
    auto handshake(Session& session, io::io_context& context,
                   rules::RouteMatcher const& policy, bool mixed, std::optional<Credentials> const& credentials) -> capy::task<>;
}


export namespace nexus::proxy {
    enum class Inbound { socks5, mixed, vless, shadowsocks };
    enum class RuleFormat { kdl, beve };
    enum class RouteAction { direct, block, vless };
    struct RouteRule { std::string_view data; RuleFormat format; RouteAction action; };
    struct IndexedRouteRule { std::string_view data; RuleFormat format; std::size_t outbound; };
    enum class FailureKind { accept, accept_task, worker };
    struct RuntimeFailure {
        FailureKind kind;
        std::error_code system_error;
    };
    struct DnsServer {
        std::array<std::uint8_t,16> address{};
        bool ipv6=false;
        std::uint16_t port=0;
        bool tcp=false;
        std::string host;
        std::optional<std::size_t> resolver;
    };
    struct DnsRule { std::string domain; bool suffix=false; std::size_t server=0; };
    enum class DnsStrategy { automatic, prefer_ipv4, prefer_ipv6, ipv4_only, ipv6_only };
    struct DnsRouting {
        std::vector<DnsServer> servers;
        std::vector<DnsRule> rules;
        std::size_t final=0;
        DnsStrategy strategy=DnsStrategy::automatic;
        bool disable_cache=false;
        bool edns=false;
    };
    [[nodiscard]] auto describe(FailureKind kind) noexcept -> std::string_view;

    // Loopback server; one worker runs in the caller, multiple workers use threads.
    // Public methods must be called from one controlling thread.
    class Server {
        // The registry outlives context shutdown, which can destroy task frames.
        std::vector<Session*> sessions;
        // Pending DNS tasks borrow this worker-local state until context shutdown.
        std::unique_ptr<DnsState> dns;
        // Session coroutines also borrow the policy and credentials.
        rules::RouteMatcher policy;
        std::optional<Credentials> credentials;
#ifdef NEXUS_TEST_FAKEIP
        // Sessions borrow the shared owner through context shutdown.
        std::shared_ptr<dns::FakeIpShared> fakeip;
        std::uint64_t fakeip_view=0;
#endif
        // Inbound factories outlive context shutdown and suspended sessions.
#ifdef NEXUS_ENABLE_SS2022
        InboundFactory shadowsocks_inbound;
#endif
#ifdef NEXUS_ENABLE_VLESS
        InboundFactory vless_inbound;
        std::shared_ptr<std::vector<TunnelFactory> const> vless;
#endif
#if BOOST_COROSIO_HAVE_LIBURING
        io::io_context context{io::uring};
#else
        io::io_context context;
#endif
        io::tcp_acceptor listener{context};
        SessionQuota quota{64};
        std::optional<DnsRouting> dns_routing;
        std::optional<std::size_t> max_bootstrap_index;
        bool running = false;
        bool mixed = false;
        Inbound inbound_type = Inbound::socks5;
        std::vector<std::unique_ptr<Server>> workers;
        std::vector<std::thread> threads;
        std::atomic_bool stopping{false}, failed{false};
        mutable std::mutex failure_mutex;
        std::optional<RuntimeFailure> failure_state;
        auto record_failure(RuntimeFailure value) -> void;
        auto get_failure() const -> std::optional<RuntimeFailure>;
        auto accept_loop() -> capy::task<>;
        auto serve_session(std::unique_ptr<Session> session) -> capy::task<>;
        auto start_one(std::uint16_t port, Inbound inbound, bool reuse, bool ipv6) -> std::expected<std::uint16_t, std::error_code>;
    public:
        Server();
        // Converts context initialization system failures into an error result.
        [[nodiscard]] static auto create() -> std::expected<std::unique_ptr<Server>, std::error_code>;
        ~Server();
        Server(Server const&) = delete;
        auto operator=(Server const&) -> Server& = delete;

        // Matching predicates block; nonmatching IP requests use direct TCP.
        // The policy can be replaced only while the server is stopped.
        [[nodiscard]] auto set_block_rules(std::string_view data, RuleFormat format)
            -> std::expected<void, std::string>;
        // Install one ordered predicate set and its action; absent data means default only.
        [[nodiscard]] auto set_route(std::optional<std::string_view> data, RuleFormat format,
                                     RouteAction action, RouteAction fallback) -> std::expected<void, std::string>;
        [[nodiscard]] auto set_routes(std::span<RouteRule const> rules, RouteAction fallback)
            -> std::expected<void, std::string>;
        // Outbound 0 is direct, 1 is block, and prepared tunnel instances start at 2.
        [[nodiscard]] auto set_indexed_routes(std::span<IndexedRouteRule const> rules, std::size_t fallback)
            -> std::expected<void, std::string>;
        // Authentication can be changed only while stopped. Mixed authentication
        // is rejected until both protocols can enforce the same credentials.
        [[nodiscard]] auto set_socks5_credentials(std::string_view username, std::string_view password)
            -> std::expected<void, std::string>;
        [[nodiscard]] auto clear_socks5_credentials() -> std::expected<void, std::string>;
        // Configure an explicit unscoped IP DNS server while stopped; absent by default.
        [[nodiscard]] auto set_dns_upstream(std::array<std::uint8_t,4> address, std::uint16_t port)
            -> std::expected<void, std::error_code>;
        [[nodiscard]] auto set_dns_upstream(std::array<std::uint8_t,16> address, std::uint16_t port)
            -> std::expected<void, std::error_code>;
        // A zero port selects the system resolver. Rules are ordered, first match wins.
        [[nodiscard]] auto set_dns_routing(DnsRouting routing) -> std::expected<void, std::error_code>;
#ifdef NEXUS_TEST_FAKEIP
        [[nodiscard]] auto set_fakeip(std::shared_ptr<dns::FakeIpShared> owner,std::uint64_t view)
            -> std::expected<void,std::error_code>;
#endif
        // Bootstrap indexes refer to the current DNS server list. Replacements must retain referenced indexes.
        // Prepare an authenticated VLESS outbound before starting the server.
        [[nodiscard]] auto prepare_vless(std::string_view host, std::uint16_t port,
            std::string_view uuid_file, std::string_view server_name, std::string_view ca_file,
            TlsKeyExchange key_exchange = TlsKeyExchange::x25519, std::optional<std::size_t> bootstrap = {})
            -> std::expected<void, std::string>;
        [[nodiscard]] auto add_vless(std::string_view host, std::uint16_t port,
            std::string_view uuid_file, std::string_view server_name, std::string_view ca_file,
            TlsKeyExchange key_exchange = TlsKeyExchange::x25519, std::optional<std::size_t> bootstrap = {})
            -> std::expected<std::size_t, std::string>;
        // The caller retains responsibility for securely handling the input PSK.
        [[nodiscard]] auto add_shadowsocks(std::string_view host,std::uint16_t port,std::span<std::uint8_t const> key,
            std::optional<std::size_t> bootstrap = {})
            -> std::expected<std::size_t,std::string>;
        [[nodiscard]] auto prepare_vless_inbound(std::string_view certificate,std::string_view key,
            std::span<std::string const> users) -> std::expected<void,std::string>;
        // Configure once; matching keys share a process-lifetime replay table.
        [[nodiscard]] auto prepare_shadowsocks_inbound(std::span<std::uint8_t const> key) -> std::expected<void,std::string>;
        // Workers: 1..16.
        [[nodiscard]] auto start(std::uint16_t port, Inbound inbound = Inbound::socks5, unsigned workers = 1, bool ipv6 = false) -> std::expected<std::uint16_t, std::error_code>;
        [[nodiscard]] auto healthy() const noexcept -> bool;
        // First unexpected runtime failure, retained through stop and cleared on the next start.
        [[nodiscard]] auto failure() const -> std::optional<RuntimeFailure>;
        auto poll(std::chrono::milliseconds maximum_wait) -> void;
        auto stop() noexcept -> void;
    };
}
