module;
#include <boost/corosio/socket_option.hpp>

module relay:xhttp_http3_listener;
import std;
import hysteria2.transport_options;
import masque.session;
import net.datagram_driver;
import quic.cid_registry;
import quic.datagram_port;
import quic.datagram_session;
import quic.native_memory;
import quic.retry_admission;
import quic.retry_token;
import quic.tls_server;
import rules;
import tls.server_credential;
import ngtcp2;
import capy;
import corosio;
import :types;
import :session_interface;
import :server_interface;
import :xhttp_http1;
import :xhttp_http3_streams;
import :xhttp_http3_channel;
import :xhttp_inbound_types;
import :xhttp_http2_server;
import :xhttp_http3_server;

namespace relay {
    class Xhttp3Inbound {
        using Profile = vless_xhttp::InboundProfile;
        using Registry = quic::CidRegistry<32, 8>;
        using Hooks = vless_xhttp::Http3Streams<Registry, true, 16>;
        using Tls = quic::TlsServer;
        using Application = masque::Session<Tls, Hooks, false>;
        using Native = quic::DatagramSession<Tls, Application>;
        using Endpoint = corosio::endpoint;
        static constexpr std::size_t capacity = 32;

        struct Bundle {
            Xhttp3Inbound& owner;
            quic::SessionHandle id;
            Session parent;
            std::optional<tls::ServerCredential> dynamic_credential;
            Tls tls;
            Hooks hooks;
            quic::NativeMemory<> memory;
            Application app;
            Native session;
            bool working = false;

            Bundle(Xhttp3Inbound& listener, Registry& registry, quic::SessionHandle handle, Endpoint const& peer,
                   SessionQuota::Lease lease, std::optional<tls::ServerCredential> dyn_cred)
                : owner(listener), id(handle), parent(owner.context_), dynamic_credential(std::move(dyn_cred)),
                  tls(dynamic_credential ? *dynamic_credential : *owner.credential_, owner.alpn_),
                  hooks(registry, handle, owner.driver_.changed()), memory(owner.transport_.native_bytes),
                  app(tls, hooks, true, memory.http3()), session(tls, app, owner.local_) {
                owner.server_.attach_session(parent, std::move(lease));
                parent.relaying = true;
                parent.touched = Clock::now();
                parent.datagram_source = traffic_endpoint(peer);
                parent.ingress = owner.server_.transparent_metadata(*parent.datagram_source);
            }
            auto stop() noexcept -> void {
                parent.close();
                app.request_stop();
            }
            template<class Channel>
            auto worker(Channel& channel, vless_xhttp::RelaySlots& slots) -> capy::task<capy::results<>> {
                using vless_xhttp::Http3Request;
                while (!parent.closed && !hooks.dead) {
                    auto next = std::ranges::find_if(hooks.streams, [](auto const& slot) {
                        auto const& stream = slot.second;
                        return (stream.complete || stream.failed) && !stream.accepted && !stream.retired;
                    });
                    if (next == hooks.streams.end()) {
                        if (owner.draining_ && hooks.streams.empty()) break;
                        if (!co_await channel.wait()) break;
                        continue;
                    }
                    next->second.accepted = true;
                    parent.touched = Clock::now();
                    Http3Request request(channel, parent, next->first);
                    if (next->second.failed) continue;
                    auto const& policy = parent.route_snapshot ? parent.route_snapshot->matcher : owner.server_.routing_policy();
                    try { co_await vless_xhttp::handle_request(parent, owner.context_, policy, *owner.profile_, request, slots); }
                    catch (...) { request.cancel(); }
                }
                co_return capy::results<>{};
            }
            auto run() -> capy::task<> {
                vless_xhttp::Http3Channel channel(*this, owner.driver_);
                vless_xhttp::RelaySlots slots;
                std::vector<capy::task<capy::results<>>> workers;
                workers.reserve(Hooks::stream_capacity());
                for (std::size_t i = 0; i < Hooks::stream_capacity(); ++i) workers.push_back(worker(channel, slots));
                (void)co_await capy::when_all(std::move(workers));
            }
        };
        struct Factory {
            using Session = Native;
            using ControlFailure = quic::RetryFailure;
            Xhttp3Inbound& listener;
            quic::RetryAdmission<> retry;
            std::optional<quic::RetryClaims> permit;
            std::optional<ControlFailure> failure;
            std::array<std::optional<Bundle>, capacity> sessions;
            auto admit(ngtcp2::ngtcp2_pkt_hd const& initial, Endpoint const& peer, Clock::time_point now, std::size_t bytes)
                noexcept -> bool {
                if (listener.draining_) return false;
                auto result = retry.inspect(initial, peer, now, bytes);
                if (!result) { failure = result.error(); return false; }
                permit = *result;
                return permit.has_value();
            }
            auto control_failure() const noexcept { return failure; }
            auto control_output(std::span<std::uint8_t> bytes, Clock::time_point now) noexcept
                -> std::expected<std::optional<net::DatagramOutput>, ControlFailure> {
                if (failure) return std::unexpected(*failure);
                return retry.output(bytes, now);
            }
            auto control_transmitted(std::uint64_t token, Clock::time_point now) noexcept { return retry.transmitted(token, now); }
            auto control_next_expiry() const noexcept { return retry.next_expiry(); }
            auto control_expire(Clock::time_point now) noexcept { return retry.expire(now); }
            auto control_request_stop() noexcept -> void { retry.request_stop(); }
            auto control_stop() noexcept -> void { permit.reset(); retry.stop(); }
            auto control_drained() const noexcept -> bool { return retry.drained(); }
            auto create(quic::SessionHandle id, Registry& registry, std::span<std::uint8_t const> source,
                ngtcp2::ngtcp2_pkt_hd const& initial, Endpoint const& peer, Clock::time_point now)
                noexcept -> std::expected<Session*, int> {
                namespace q = ::ngtcp2;
                auto verified = std::exchange(permit, {});
                auto& entry = sessions[id.slot];
                if (entry || !verified || !std::ranges::equal(verified->retry.bytes(), std::span(initial.dcid.data).first(initial.dcid.datalen)))
                    return std::unexpected(q::err_invalid_argument);
                auto lease = listener.server_.acquire_session();
                if (!lease) return std::unexpected(q::err_callback_failure);
                auto settings = Transport::settings(listener.transport_);
                auto params = Transport::parameters(listener.transport_);
                if (!settings || !params) return std::unexpected(q::err_invalid_argument);
                q::ngtcp2_cid_init(&params->original_dcid, verified->original.data.data(), verified->original.size);
                params->original_dcid_present = 1;
                params->retry_scid_present = 1;
                params->retry_scid = initial.dcid;
                settings->token = initial.token;
                settings->tokenlen = initial.tokenlen;
                settings->token_type = q::NGTCP2_TOKEN_TYPE_RETRY;
                q::ngtcp2_cid cid{};
                q::ngtcp2_cid_init(&cid, source.data(), source.size());
                try {
                    std::optional<tls::ServerCredential> dyn_cred;
                    if (listener.atomic_credential_) {
                        auto cur = listener.atomic_credential_->clone_current();
                        if (!cur) return std::unexpected(q::err_callback_failure);
                        dyn_cred.emplace(std::move(*cur));
                    } else if (!listener.credential_) {
                        return std::unexpected(q::err_callback_failure);
                    }
                    entry.emplace(listener, registry, id, peer, std::move(*lease), std::move(dyn_cred));
                    auto result = entry->session.start(true, initial.scid, cid, peer, *settings, *params, entry->memory.transport(), now);
                    if (result) { entry.reset(); return std::unexpected(result); }
                    listener.start_tasks(id, *entry);
                    return &entry->session;
                } catch (...) {
                    entry.reset();
                    return std::unexpected(q::err_callback_failure);
                }
            }
            auto application_drained(quic::SessionHandle id, Session const&) const noexcept -> bool {
                return sessions[id.slot] && !sessions[id.slot]->working;
            }
            auto failed(quic::SessionHandle id, int) noexcept -> void { if (auto& slot = sessions[id.slot]) slot->stop(); }
            auto destroy(quic::SessionHandle id, Session&) noexcept -> void { sessions[id.slot].reset(); }
        };
        using Transport = hysteria2::TransportProfile<Hooks::stream_capacity(), vless_xhttp::h3_window>;
        using Port = quic::DatagramPort<Factory, capacity, 8, 8, true>;
        using Driver = net::DatagramDriver<Port>;

        Server& server_;
        corosio::io_context& context_;
        std::unique_ptr<Profile> profile_;
        std::optional<tls::ServerCredential> credential_;
        std::shared_ptr<tls::AtomicServerCredential> atomic_credential_;
        std::string alpn_{"h3"};
        hysteria2::TransportOptions transport_;
        corosio::udp_socket socket_;
        Endpoint local_;
        Factory factory_{*this};
        Port port_{factory_};
        Driver driver_{socket_, port_};
        bool draining_ = false, stopped_ = false;

        auto start_tasks(quic::SessionHandle id, Bundle& bundle) -> void {
            auto finished = [this, id]() noexcept {
                if (id.slot >= factory_.sessions.size()) return;
                auto& entry = factory_.sessions[id.slot];
                if (!entry || entry->id != id) return;
                entry->working = false;
                entry->stop();
                (void)port_.request_retire(id);
                port_.maintain();
                driver_.notify();
            };
            bundle.working = true;
            try {
                capy::run_async(context_.get_executor(), bundle.parent.stop.get_token(), finished,
                    [finished](std::exception_ptr) noexcept { finished(); })(bundle.run());
            } catch (...) {
                bundle.working = false;
                throw;
            }
        }
    public:
        Xhttp3Inbound(Server& server, std::unique_ptr<Profile> profile, std::optional<tls::ServerCredential> credential,
                      std::shared_ptr<tls::AtomicServerCredential> atomic_credential = {}, std::string alpn = "h3")
            : server_(server), context_(server.executor_context()), profile_(std::move(profile)),
              credential_(std::move(credential)), atomic_credential_(std::move(atomic_credential)),
              alpn_(alpn.empty() ? "h3" : std::move(alpn)), socket_(context_) { transport_.udp = false; }
        ~Xhttp3Inbound() { stop(); }
        auto restart_owner() -> std::shared_ptr<Xhttp3Inbound> {
            if (!stopped_) return {};
            return std::make_shared<Xhttp3Inbound>(server_, std::move(profile_), std::move(credential_),
                std::move(atomic_credential_), alpn_);
        }
        template<class Failure>
        auto start(Endpoint endpoint, Failure failure) -> std::expected<Endpoint, std::error_code> {
            if (!factory_.retry.initialize()) return std::unexpected(std::make_error_code(std::errc::io_error));
            auto family = endpoint.address().family();
            if (auto ec = socket_.open(family)) return std::unexpected(ec);
            if (endpoint.is_v6()) if (auto ec = socket_.set_option(corosio::socket_option::v6_only(true)))
                return std::unexpected(ec);
            if (auto ec = socket_.bind(endpoint)) return std::unexpected(ec);
            local_ = socket_.local_endpoint();
            auto finished = [this, report = std::move(failure)] {
                if (!stopped_) report();
                stop();
            };
            capy::run_async(context_.get_executor(), [finished](auto) { finished(); },
                [finished](std::exception_ptr) { finished(); })(driver_.run());
            return local_;
        }
        auto drain() noexcept -> void {
            draining_ = true;
            driver_.notify();
        }
        auto stop() noexcept -> void {
            if (std::exchange(stopped_, true)) return;
            draining_ = true;
            for (auto& session : factory_.sessions) if (session) session->stop();
            driver_.finish();
        }
    };
}
