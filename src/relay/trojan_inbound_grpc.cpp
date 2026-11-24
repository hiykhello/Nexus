module relay;
import std;
import capy;
import corosio;
import rules;
import grpc.headers;
import grpc.session;
import grpc.stream;
import grpc.multiplex;
import grpc.multiplex_channel;
import grpc.connection;
import tls.byte_stream;
import tls.corosio_application;
import trojan;
import trojan.stream;
import :transport_helpers;
import :trojan_inbound_common;

namespace relay::trojan_in {
    auto serve_trojan_grpc(Session& session, corosio::io_context& context, rules::RouteMatcher const& policy,
        TrojanInboundProfile const& profile, tls::detail::ApplicationConnection<corosio::tcp_socket>& connection)
        -> capy::task<> {
        using Lower = tls::detail::ByteStream<corosio::tcp_socket>;
        using Channel = grpc::MultiplexChannel<Lower, 16, grpc::detail::ByteStreamReadPolicy>;
        Lower lower(connection);
        auto proto = grpc::MultiplexSession<16>::create(
            grpc::Role::server, profile.grpc->request, grpc::ResponsePolicy::standard, profile.grpc->limits);
        if (!proto) co_return;
        Channel channel(lower, std::move(*proto));
        session.relaying = true; session.touched = Clock::now();
        struct Slots { bool primary = true; };
        auto run_ch = [&]() -> capy::task<capy::results<>> { co_return co_await channel.run(); };
        Slots slots;
        auto worker = [&]() -> capy::task<capy::results<>> {
            while (!session.closed) {
                if (auto ticket = channel.accept()) {
                    typename Channel::Stream rpc(channel, *ticket);
                    struct Primary { Slots& s; bool borrowed = false; ~Primary() { if (borrowed) s.primary = true; } } primary{slots};
                    std::optional<SessionQuota::Lease> lease;
                    if (session.quota) {
                        if (slots.primary) { slots.primary = false; primary.borrowed = true; }
                        else { lease = session.quota->try_acquire(); if (!lease) { rpc.cancel(); continue; } }
                    }
                    transport_detail::GrpcByteStream<typename Channel::Stream> adapted{rpc, &session};
                    Session child(context);
                    child.quota = std::move(lease);
                    init_multiplexed_child(child, session, Clock::now() + std::chrono::seconds(10));
                    if (!child.admit_principal_child(session)) { rpc.cancel(); continue; }
                    std::stop_callback sc(session.stop.get_token(), [&]() noexcept { child.close(); rpc.cancel(); });
                    std::stop_callback sc_child(child.stop.get_token(), [&]() noexcept { rpc.cancel(); });
                    trojan::detail::Inbound<corosio::tcp_socket, decltype(adapted)&> in(adapted, profile.users);
                    auto erased = trojan_in::TrojanInboundRef::from(in);
                    try { co_await serve_trojan_stream(child, context, policy, profile, erased, child.handshake_deadline); }
                    catch (...) {}
                    child.close(); rpc.cancel();
                    continue;
                }
                if (!co_await channel.wait_change()) break;
            }
            co_return capy::results<>{};
        };
        std::vector<capy::task<capy::results<>>> tasks;
        tasks.reserve(17); tasks.push_back(run_ch());
        for (unsigned i = 0; i < 16; ++i) tasks.push_back(worker());
        try { (void)co_await capy::when_all(std::move(tasks)); } catch (...) { channel.cancel(); }
    }
}
