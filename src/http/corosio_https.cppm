export module nexus.http.corosio_https;
import std;
import nexus.http.connect;
import nexus.tls.application_io;
import nexus.crypto;
import nexus.tls.corosio_client;
import nexus.tls.corosio_application;
import nexus.thirdparty.capy;


export namespace nexus::http::detail {
    enum class HttpsError { tls, alpn, malformed, truncated, extra_input, output_rejected };

    // Single request on an already-authenticated connection. The caller owns and drains
    // the connection and socket, and keeps request and callback alive until completion.
    // Callback is synchronous, non-reentrant and must not throw; it sees rewritten
    // headers and framed body segments and returns false to stop the transaction.
    template<class Socket, class Output>
    auto https_exchange(tls::detail::ClientConnection<Socket>& client, std::string_view request,
        bool head, Output& output, tls::detail::ApplicationDeadline deadline = {}, bool allow_missing_alpn = false)
        -> nex::capy::task<std::expected<void,HttpsError>> {
        auto* connection=client.application(); auto* negotiated=client.negotiated();
        if (!connection || !negotiated) co_return std::unexpected(HttpsError::tls);
        if (negotiated->alpn != crypto::Bytes({'h','t','t','p','/','1','.','1'}) && !(allow_missing_alpn && !negotiated->alpn)) {
            connection->cancel(); co_return std::unexpected(HttpsError::alpn);
        }
        auto input=std::span{reinterpret_cast<std::uint8_t const*>(request.data()),request.size()};
        if (!co_await connection->send_all(input,deadline)) { connection->cancel(); co_return std::unexpected(HttpsError::tls); }
        tls::detail::ApplicationStreamReader reader(*connection);
        ResponseDecoder decoder(head); std::array<std::uint8_t,4096> buffer{}; bool complete=false;
        while (!complete) {
            auto received=co_await reader.read_some(buffer,deadline);
            if (!received) co_return std::unexpected(HttpsError::tls);
            if (received->kind==tls::detail::AsyncStreamReadKind::backpressure) {
                if (!co_await connection->flush(deadline)) co_return std::unexpected(HttpsError::tls);
                continue;
            }
            if (received->kind==tls::detail::AsyncStreamReadKind::eof) { connection->cancel(); co_return std::unexpected(HttpsError::truncated); }
            if (received->kind==tls::detail::AsyncStreamReadKind::event) {
                auto kind=received->event->kind;
                if (kind==tls::ApplicationEventKind::close_notify) {
                    auto end=decoder.finish();
                    if (end.event!=ResponseEvent::complete) { connection->cancel(); co_return std::unexpected(HttpsError::truncated); }
                    complete=true;
                } else if (kind==tls::ApplicationEventKind::key_update_requested) {
                    if (!co_await connection->flush(deadline)) co_return std::unexpected(HttpsError::tls);
                } else if (kind!=tls::ApplicationEventKind::key_update && kind!=tls::ApplicationEventKind::ticket_discarded && kind!=tls::ApplicationEventKind::handshake_fragment) {
                    connection->cancel(); co_return std::unexpected(HttpsError::tls);
                }
                continue;
            }
            auto data=std::string_view(reinterpret_cast<char const*>(buffer.data()),received->size);
            while (!data.empty()) {
                auto step=decoder.feed(data);
                if (step.event==ResponseEvent::malformed || step.event==ResponseEvent::truncated || !step.consumed) { connection->cancel(); co_return std::unexpected(HttpsError::malformed); }
                data.remove_prefix(step.consumed);
                if (!step.wire.empty() && !output(step)) { connection->cancel(); co_return std::unexpected(HttpsError::output_rejected); }
                if (step.event==ResponseEvent::complete) {
                    if (!data.empty()) { connection->cancel(); co_return std::unexpected(HttpsError::extra_input); }
                    complete=true; break;
                }
            }
            if (!complete && decoder.feed({}).event==ResponseEvent::complete) complete=true;
        }
        if (!co_await connection->close_notify(deadline)) { connection->cancel(); co_return std::unexpected(HttpsError::tls); }
        co_return std::expected<void,HttpsError>{};
    }
}
