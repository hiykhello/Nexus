module;
#include <proxy/proxy_macros.h>

module relay:trojan_inbound_common;
import std;
import proxy.v4;
import capy;
import corosio;
import rules;
import httpupgrade;
import tls.byte_stream;
import tls.server_credential;
import tls.corosio_application;
import trojan;
import trojan.auth;
import trojan.stream;
import :types;
import :session_interface;
import :transport_helpers;

namespace relay::trojan_in {
    struct TrojanInboundProfile {
        tls::ServerCredential credential;
        std::vector<trojan::PasswordKey> users;
        std::vector<std::string> names;
        std::optional<httpupgrade::Profile> transport;
        std::optional<transport_detail::GrpcSettings> grpc;
        std::optional<config::InboundMultiplexConfig> multiplex;
    };

    PRO_DEF_MEM_DISPATCH(TrojanInReadRequest, read_request);
    PRO_DEF_MEM_DISPATCH(TrojanInRead, read);
    PRO_DEF_MEM_DISPATCH(TrojanInReadSniff, read_sniff);
    PRO_DEF_MEM_DISPATCH(TrojanInSend, send);
    PRO_DEF_MEM_DISPATCH(TrojanInCloseOutput, close_output);
    PRO_DEF_MEM_DISPATCH(TrojanInCancel, cancel);

    struct TrojanInboundFacade : pro::facade_builder
        ::add_convention<TrojanInReadRequest, capy::task<std::optional<trojan::detail::AcceptedRequest>>(tls::detail::ApplicationDeadline)>
        ::add_convention<TrojanInRead, capy::task<std::expected<std::size_t, tls::detail::ByteStreamError>>(std::span<std::uint8_t>, tls::detail::ApplicationDeadline)>
        ::add_convention<TrojanInReadSniff, capy::task<std::expected<std::size_t, tls::detail::ByteStreamError>>(std::span<std::uint8_t>, tls::detail::ApplicationDeadline)>
        ::add_convention<TrojanInSend, capy::task<bool>(std::span<std::uint8_t const>, tls::detail::ApplicationDeadline)>
        ::add_convention<TrojanInCloseOutput, capy::task<bool>()>
        ::add_convention<TrojanInCancel, void() noexcept>
        ::build {};

    struct TrojanInboundRef {
        pro::proxy_view<TrojanInboundFacade> view;

        template<class In>
        static auto from(In& in) noexcept -> TrojanInboundRef {
            return {pro::make_proxy_view<TrojanInboundFacade>(in)};
        }

        auto read_request(tls::detail::ApplicationDeadline d = {}) { return view->read_request(d); }
        auto read(std::span<std::uint8_t> b, tls::detail::ApplicationDeadline d = {}) { return view->read(b, d); }
        auto read_sniff(std::span<std::uint8_t> b, tls::detail::ApplicationDeadline d) {
            return view->read_sniff(b, d);
        }
        auto send(std::span<std::uint8_t const> b, tls::detail::ApplicationDeadline d = {}) {
            return view->send(b, d);
        }
        auto close_output() { return view->close_output(); }
        auto cancel() noexcept -> void { if (view) view->cancel(); }
    };

    auto serve_trojan_stream(Session& session, corosio::io_context& context, rules::RouteMatcher const& policy,
        TrojanInboundProfile const& profile, TrojanInboundRef& incoming, Clock::time_point deadline)
        -> capy::task<>;

    auto serve_trojan_grpc(Session& session, corosio::io_context& context, rules::RouteMatcher const& policy,
        TrojanInboundProfile const& profile, tls::detail::ApplicationConnection<corosio::tcp_socket>& connection)
        -> capy::task<>;
}
