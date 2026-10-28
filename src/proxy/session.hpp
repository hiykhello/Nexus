#ifndef NEXUS_PROXY_SESSION_HPP
#define NEXUS_PROXY_SESSION_HPP

#include "session_quota.hpp"

namespace nexus::proxy {
    namespace capy = boost::capy;
    namespace io = boost::corosio;
    using Clock = std::chrono::steady_clock;

    struct Session;
    enum class TunnelConnectResult { connected, retryable, failed };
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
    using InboundFactory = std::function<capy::task<>(std::shared_ptr<Session>,io::io_context&,rules::RouteMatcher const&)>;
    struct DnsState;

    struct Session {
        // Destroyed last, after sockets and all owners of this session.
        std::optional<SessionQuota::Lease> quota;
        io::tcp_socket client;
        io::tcp_socket target;
        std::unique_ptr<io::resolver> resolver;
        std::shared_ptr<DnsState> dns;
#ifdef NEXUS_TEST_FAKEIP
        std::shared_ptr<dns::FakeIpShared> fakeip;
        std::unique_ptr<dns::FakeIpShared::Target> fakeip_target;
        std::uint64_t fakeip_view=0;
#endif
        std::function<void()> cancel_dns;
        pro::proxy<TunnelFacade> tunnel;
        std::shared_ptr<std::vector<TunnelFactory> const> tunnel_factories;
        Clock::time_point started = Clock::now();
        Clock::time_point touched = started;
        std::stop_source stop;
        bool relaying = false;
        bool closed = false;
        bool done = false;
        bool http_upload_active = false;
        bool http_draining = false;
        Clock::time_point http_drain_started{};
        unsigned relay_finished = 0;
        explicit Session(io::io_context& ctx);
#ifdef NEXUS_TEST_FAKEIP
        ~Session();
#endif
        auto close() noexcept -> void;
    };

    // Detached task failures close the connection; other in-flight directions
    // retain shared ownership until their cancellation completes.
    inline auto session_error(std::shared_ptr<Session> session) {
        return [session=std::move(session)](std::exception_ptr) noexcept {
            session->close(); session->done=true;
        };
    }

    // Each relay holds the session until its completion handler runs.
    inline auto relay_complete(std::shared_ptr<Session> session) {
        return [session=std::move(session)]() noexcept {
            if (++session->relay_finished == 2) { session->close(); session->done=true; }
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
    auto dial(std::shared_ptr<Session> session, io::io_context& context,
              rules::RouteMatcher const& policy, socks5::Request const& request) -> capy::task<std::uint8_t>;
    auto forward_http(std::shared_ptr<Session> session, io::io_context& context,
                      rules::RouteMatcher const& policy, std::string_view input) -> capy::task<>;
    auto handshake(std::shared_ptr<Session> session, io::io_context& context,
                   rules::RouteMatcher const& policy, bool mixed, std::optional<Credentials> const& credentials) -> capy::task<>;
}

#endif
