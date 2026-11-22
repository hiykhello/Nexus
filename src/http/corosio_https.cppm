export module http.corosio_https;
import std;
import http.connect;
import tls.application_io;
import crypto;
import tls.corosio_client;
import tls.corosio_application;
import nexus.thirdparty.capy;


export namespace http::detail {
    enum class HttpsError { tls, alpn, malformed, truncated, extra_input, output_rejected };

    // Single request on an already-authenticated connection. The caller owns and drains
    // the connection and socket, and keeps request and callback alive until completion.
    // Output sees rewritten headers and body segments in the selected format.
    // An asynchronous output completes before the reader advances the decoder.
    template<class Client, class Output>
    auto https_exchange(Client& client, std::string_view request,
        bool head, Output& output, tls::detail::ApplicationDeadline deadline = {}, bool allow_missing_alpn = false,
        ChunkOutput chunk_output=ChunkOutput::framed,bool* reusable=nullptr)
        -> nex::capy::task<std::expected<void,HttpsError>> {
        if (reusable) *reusable=false;
        auto* connection=client.application(); auto* negotiated=client.negotiated();
        if (!connection || !negotiated) co_return std::unexpected(HttpsError::tls);
        if (negotiated->alpn != crypto::Bytes({'h','t','t','p','/','1','.','1'}) && !(allow_missing_alpn && !negotiated->alpn)) {
            connection->cancel(); co_return std::unexpected(HttpsError::alpn);
        }
        auto input=std::span{reinterpret_cast<std::uint8_t const*>(request.data()),request.size()};
        if (!co_await connection->send_all(input,deadline)) { connection->cancel(); co_return std::unexpected(HttpsError::tls); }
        tls::detail::ApplicationStreamReader reader(*connection);
        ResponseDecoder decoder(head,false,chunk_output); std::array<std::uint8_t,4096> buffer{}; bool complete=false;
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
                } else if (kind!=tls::ApplicationEventKind::key_update && kind!=tls::ApplicationEventKind::ticket_discarded && kind!=tls::ApplicationEventKind::ticket_received && kind!=tls::ApplicationEventKind::handshake_fragment) {
                    connection->cancel(); co_return std::unexpected(HttpsError::tls);
                }
                continue;
            }
            auto data=std::string_view(reinterpret_cast<char const*>(buffer.data()),received->size);
            while (!data.empty()) {
                auto step=decoder.feed(data);
                if (step.event==ResponseEvent::malformed || step.event==ResponseEvent::truncated || !step.consumed) { connection->cancel(); co_return std::unexpected(HttpsError::malformed); }
                data.remove_prefix(step.consumed);
                if (!step.wire.empty()) {
                    bool accepted;
                    if constexpr (std::same_as<decltype(output(step)),bool>) accepted=output(step);
                    else accepted=co_await output(step);
                    if (!accepted) { connection->cancel(); co_return std::unexpected(HttpsError::output_rejected); }
                }
                if (step.event==ResponseEvent::complete) {
                    if (!data.empty()) { connection->cancel(); co_return std::unexpected(HttpsError::extra_input); }
                    complete=true; break;
                }
            }
            if (!complete && decoder.feed({}).event==ResponseEvent::complete) complete=true;
        }
        if (reader.pending_plaintext()) {
            connection->cancel();
            co_return std::unexpected(HttpsError::extra_input);
        }
        if (reusable && decoder.reusable() && reader.idle() && !connection->buffered_input()) {
            *reusable=true;
            co_return std::expected<void,HttpsError>{};
        }
        if (!co_await connection->close_notify(deadline)) { connection->cancel(); co_return std::unexpected(HttpsError::tls); }
        co_return std::expected<void,HttpsError>{};
    }
}
