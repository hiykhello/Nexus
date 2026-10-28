export module nexus.http2.tls_server;
export import nexus.http2.server;
import nexus.tls.corosio_application;
import nexus.tls.application_io;
import nexus.thirdparty.capy;
import std;

export namespace nexus::http2 {
    enum class TlsServerStep { progress, paused, drained, peer_closed };
    enum class TlsServerError { invalid_state, http2, tls, timeout, budget_exceeded };

    // A single owner drives this object and its session on one executor. Socket,
    // session and this object must outlive an outstanding step. The caller must
    // have completed a TLS handshake that selected h2 before constructing it.
    template<class Socket>
    class TlsServerConnection {
        ServerSession& session_;
        tls::detail::ApplicationConnection<Socket> tls_;
        crypto::Bytes input_;
        std::size_t offset_=0;
        std::uint64_t ready_revision_=0;
        bool active_=false, closed_=false, failed_=false, resume_pending_=false, peer_closed_=false, ready_to_close_=false, input_reserved_=false, session_abandoned_=false, claimed_=false;
        void release_input() noexcept { crypto::Bytes{}.swap(input_); offset_=0; if (input_reserved_) { session_.release_input(); input_reserved_=false; } }
        static auto tls_error(tls::detail::AsyncApplicationError error) noexcept -> TlsServerError {
            return error==tls::detail::AsyncApplicationError::timeout ? TlsServerError::timeout : TlsServerError::tls;
        }
    public:
        TlsServerConnection(Socket& socket, ServerSession& session, tls::ApplicationRecords&& records,
                            crypto::Bytes&& unread)
            : session_(session), tls_(socket,std::move(records),std::move(unread)), claimed_(session.claim_transport()) { failed_=!claimed_; }
        TlsServerConnection(TlsServerConnection const&)=delete;
        auto operator=(TlsServerConnection const&) -> TlsServerConnection& = delete;
        ~TlsServerConnection() {
            if (claimed_ && !session_abandoned_) session_.fail_transport(input_reserved_);
        }
        auto cancel() noexcept -> void {
            failed_=true;
            if (!claimed_) return;
            if (!active_ && !session_abandoned_) {
                session_.fail_transport(input_reserved_); release_input(); session_abandoned_=true;
            }
            tls_.cancel();
        }

        // After step reports drained or peer_closed, send close_notify without
        // modifying the session afterward. The caller owns the socket and peer-close wait.
        auto close_notify(tls::detail::ApplicationDeadline deadline = {})
            -> nex::capy::task<std::expected<void,TlsServerError>> {
            if (active_ || failed_ || closed_ || resume_pending_ || offset_!=input_.size() ||
                tls_.pending_output() || !ready_to_close_ || session_.revision()!=ready_revision_)
                co_return std::unexpected(TlsServerError::invalid_state);
            active_=true;
            auto result=co_await tls_.close_notify(deadline);
            active_=false;
            if (!result) { cancel(); co_return std::unexpected(tls_error(result.error())); }
            if (failed_) { cancel(); co_return std::unexpected(TlsServerError::tls); }
            closed_=true;
            co_return std::expected<void,TlsServerError>{};
        }

        // Returns after one unit of work so the application can respond outside
        // session callbacks. While input is paused, pending output can still be
        // drained; once paused is returned, resume the indicated session stream
        // before expecting more input. A deadline applies to each socket operation.
        auto step(tls::detail::ApplicationDeadline deadline = {})
            -> nex::capy::task<std::expected<TlsServerStep,TlsServerError>> {
            if (active_ || failed_ || closed_) co_return std::unexpected(TlsServerError::invalid_state);
            ready_to_close_=false;
            active_=true;
            if (tls_.pending_output()) {
                auto result=co_await tls_.flush(deadline); active_=false;
                if (!result) { cancel(); co_return std::unexpected(tls_error(result.error())); }
                if (failed_) { cancel(); co_return std::unexpected(TlsServerError::tls); }
                co_return TlsServerStep::progress;
            }
            std::array<std::byte,16384> output{};
            auto count=session_.output(output);
            if (!count) { active_=false; cancel(); co_return std::unexpected(TlsServerError::http2); }
            if (failed_) { active_=false; cancel(); co_return std::unexpected(TlsServerError::tls); }
            if (*count) {
                auto bytes=std::span{reinterpret_cast<std::uint8_t const*>(output.data()),*count};
                auto result=co_await tls_.send_all(bytes,deadline); active_=false;
                if (!result) { cancel(); co_return std::unexpected(tls_error(result.error())); }
                if (failed_) { cancel(); co_return std::unexpected(TlsServerError::tls); }
                co_return TlsServerStep::progress;
            }
            if (session_.paused_stream()) { active_=false; co_return TlsServerStep::paused; }
            if (resume_pending_) {
                resume_pending_=false;
                auto result=session_.receive({});
                if (!result) { active_=false; cancel(); co_return std::unexpected(TlsServerError::http2); }
                active_=false;
                if (failed_) { cancel(); co_return std::unexpected(TlsServerError::tls); }
                if (session_.paused_stream()) { resume_pending_=true; co_return TlsServerStep::paused; }
                if (offset_==input_.size()) release_input();
                co_return TlsServerStep::progress;
            }
            if (offset_<input_.size()) {
                auto bytes=std::span{input_}.subspan(offset_);
                auto consumed=session_.receive({reinterpret_cast<std::byte const*>(bytes.data()),bytes.size()});
                if (!consumed || (!*consumed && !session_.paused_stream())) {
                    active_=false; cancel(); co_return std::unexpected(TlsServerError::http2);
                }
                offset_+=*consumed;
                active_=false;
                if (failed_) { cancel(); co_return std::unexpected(TlsServerError::tls); }
                if (session_.paused_stream()) { resume_pending_=true; co_return TlsServerStep::paused; }
                if (offset_==input_.size()) release_input();
                co_return TlsServerStep::progress;
            }
            if (peer_closed_) { active_=false; ready_to_close_=true; ready_revision_=session_.revision(); co_return TlsServerStep::peer_closed; }
            if (session_.shutdown_complete()) { active_=false; ready_to_close_=true; ready_revision_=session_.revision(); co_return TlsServerStep::drained; }
            // Reserve a maximum-sized application record before reading. It may
            // remain borrowed by nghttp2 while a DATA callback is paused.
            if (!session_.reserve_input(16384)) { active_=false; cancel(); co_return std::unexpected(TlsServerError::budget_exceeded); }
            input_reserved_=true;
            auto received=co_await tls_.read(deadline); active_=false;
            if (!received) { release_input(); cancel(); co_return std::unexpected(tls_error(received.error())); }
            if (failed_) { release_input(); cancel(); co_return std::unexpected(TlsServerError::tls); }
            if (received->kind==tls::detail::AsyncReadKind::eof) { release_input(); peer_closed_=true; co_return TlsServerStep::progress; }
            if (received->kind==tls::detail::AsyncReadKind::backpressure) { release_input(); co_return TlsServerStep::progress; }
            auto event=std::move(*received->event);
            if (event.kind==tls::ApplicationEventKind::data) input_=std::move(event.data);
            else { release_input(); if (event.kind==tls::ApplicationEventKind::close_notify) peer_closed_=true;
                else if (event.kind==tls::ApplicationEventKind::fatal_alert) { cancel(); co_return std::unexpected(TlsServerError::tls); } }
            if (input_.empty()) release_input();
            co_return TlsServerStep::progress;
        }
    };
}
