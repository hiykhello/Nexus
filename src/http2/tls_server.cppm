export module http2.tls_server;
export import http2.server;
import tls.corosio_application;
import tls.application_io;
import capy;
import std;

export namespace http2 {
    enum class TlsServerStep { progress, paused, drained, peer_closed };
    enum class TlsServerError { invalid_state, http2, tls, timeout, budget_exceeded, allocation };

    // A single owner drives this object and its session on one executor. Socket,
    // session and this object must outlive an outstanding step. The caller must
    // have completed a server TLS handshake that selected h2 before constructing it.
    // Client-role or unready application records invalidate a claimed session.
    template<class Socket>
    class TlsServerConnection {
        ServerSession& session_;
        struct TransportReservation {
            ServerSession& session;
            bool held=false;
            ~TransportReservation() { if (held) session.release_transport(); }
        } transport_{session_};
        bool server_records_;
        tls::detail::ApplicationConnection<Socket> tls_;
        crypto::Bytes input_;
        std::size_t offset_=0;
        std::uint64_t ready_revision_=0;
        // During rotation: next secret (48), derived key (32), IV (12),
        // and replacement record key (32), or a smaller HKDF label peak.
        // This counts requested bytes, excluding crypto-library internals and
        // already-live traffic keys and secrets.
        static constexpr std::size_t rotation_charge_=128;
        bool active_=false, closed_=false, failed_=false, resume_pending_=false, peer_closed_=false, ready_to_close_=false, input_reserved_=false, control_reserved_=false, session_abandoned_=false, claimed_=false;
        void release_input() noexcept { crypto::Bytes{}.swap(input_); offset_=0; if (input_reserved_) { session_.release_input(); input_reserved_=false; } }
        void release_control() noexcept { if (control_reserved_) { session_.release_output(); control_reserved_=false; } }
        void abort_exception() noexcept {
            active_=false; session_.release_ciphertext(); release_control(); session_.release_output(); release_input(); cancel();
        }
        struct ActiveGuard {
            bool& active;
            void reset() noexcept { active = false; }
            ~ActiveGuard() { active = false; }
        };
        struct OutputGuard {
            ServerSession& session;
            bool armed = true;
            void release() noexcept { if (armed) { session.release_output(); armed = false; } }
            ~OutputGuard() { release(); }
        };
        struct ControlGuard {
            TlsServerConnection& owner;
            bool armed = true;
            void dismiss() noexcept { armed = false; }
            void release() noexcept { if (armed) { owner.release_control(); armed = false; } }
            ~ControlGuard() { release(); }
        };
        struct InputGuard {
            TlsServerConnection& owner;
            bool armed = true;
            void dismiss() noexcept { armed = false; }
            void release() noexcept { if (armed) { owner.release_input(); armed = false; } }
            ~InputGuard() { release(); }
        };
        struct CiphertextGuard {
            ServerSession& session;
            bool armed = true;
            void release() noexcept { if (armed) { session.release_ciphertext(); armed = false; } }
            ~CiphertextGuard() { release(); }
        };
        static auto tls_error(tls::detail::AsyncApplicationError error) noexcept -> TlsServerError {
            return error==tls::detail::AsyncApplicationError::timeout ? TlsServerError::timeout : TlsServerError::tls;
        }
    public:
        TlsServerConnection(Socket& socket, ServerSession& session, tls::ApplicationRecords&& records,
                            crypto::Bytes&& unread)
            : session_(session), server_records_(records.role()==tls::ApplicationRole::server && records.ready_for_transport()),
              tls_(socket,std::move(records),std::move(unread)), claimed_(session.claim_transport()) {
            failed_=!claimed_ || !server_records_ || !tls_.active();
            if (!failed_) { transport_.held=session_.reserve_transport(4096); failed_=!transport_.held; }
            if (claimed_ && failed_) { session_.fail_transport(false); session_abandoned_=true; tls_.cancel(); }
        }
        TlsServerConnection(TlsServerConnection const&)=delete;
        auto operator=(TlsServerConnection const&) -> TlsServerConnection& = delete;
        ~TlsServerConnection() {
            if (claimed_ && !session_abandoned_) session_.fail_transport(false);
            release_input();
            tls_.discard();
            release_control();
            if (claimed_) {
                session_.release_output();
                session_.release_ciphertext();
            }
        }
        auto cancel() noexcept -> void {
            failed_=true;
            if (!claimed_) return;
            tls_.cancel();
            if (!active_ && !session_abandoned_) {
                session_.fail_transport(false); release_input(); release_control(); session_abandoned_=true;
            }
        }

        // After step reports drained or peer_closed, send close_notify without
        // modifying the session afterward. The caller owns the socket and peer-close wait.
        auto close_notify(tls::detail::ApplicationDeadline deadline = {})
            -> capy::task<std::expected<void,TlsServerError>> {
            if (active_ || failed_ || closed_ || resume_pending_ || offset_!=input_.size() ||
                tls_.pending_output() || !ready_to_close_ || session_.revision()!=ready_revision_)
                co_return std::unexpected(TlsServerError::invalid_state);
            if (!session_.reserve_output(48)) { cancel(); co_return std::unexpected(TlsServerError::budget_exceeded); }
            control_reserved_=true; ControlGuard control_guard{*this};
            active_=true; ActiveGuard active_guard{active_};
            try {
            auto result=co_await tls_.close_notify(deadline);
            active_guard.reset(); control_guard.release();
            if (!result) { cancel(); co_return std::unexpected(tls_error(result.error())); }
            if (failed_) { cancel(); co_return std::unexpected(TlsServerError::tls); }
            closed_=true;
            co_return std::expected<void,TlsServerError>{};
            } catch (std::bad_alloc const&) { abort_exception(); co_return std::unexpected(TlsServerError::allocation); }
              catch (...) { abort_exception(); throw; }
        }

        // Returns after one unit of work so the application can respond outside
        // session callbacks. While input is paused, pending output can still be
        // drained; once paused is returned, resume the indicated session stream
        // before expecting more input. A deadline applies to each socket operation.
        auto step(tls::detail::ApplicationDeadline deadline = {})
            -> capy::task<std::expected<TlsServerStep,TlsServerError>> {
            if (active_ || failed_ || closed_) co_return std::unexpected(TlsServerError::invalid_state);
            ready_to_close_=false;
            if (!session_.reserve_scratch(16384)) { cancel(); co_return std::unexpected(TlsServerError::budget_exceeded); }
            struct ScratchReservation { ServerSession& session; ~ScratchReservation() { session.release_scratch(); } } scratch{session_};
            active_=true; ActiveGuard active_guard{active_};
            try {
            if (tls_.pending_output()) {
                ControlGuard control_guard{*this};
                auto result=co_await tls_.flush(deadline); active_guard.reset(); control_guard.release();
                if (!result) { cancel(); co_return std::unexpected(tls_error(result.error())); }
                if (failed_) { cancel(); co_return std::unexpected(TlsServerError::tls); }
                co_return TlsServerStep::progress;
            }
            std::array<std::byte,16384> output{};
            auto count=session_.output(output);
            if (!count) { active_guard.reset(); cancel(); co_return std::unexpected(TlsServerError::http2); }
            if (failed_) { active_guard.reset(); cancel(); co_return std::unexpected(TlsServerError::tls); }
            if (*count) {
                auto bytes=std::span{reinterpret_cast<std::uint8_t const*>(output.data()),*count};
                // Sealing holds inner plaintext, ciphertext, and the complete
                // record simultaneously; writing holds a record and its copy.
                // A KeyUpdate may precede short application output.
                auto charge=std::max({3*(*count)+40,2*(*count+22),std::size_t{55}})+rotation_charge_;
                if (!session_.reserve_output(charge)) { active_guard.reset(); cancel(); co_return std::unexpected(TlsServerError::budget_exceeded); }
                OutputGuard output_guard{session_};
                auto result=co_await tls_.send_all(bytes,deadline); active_guard.reset();
                output_guard.release();
                if (!result) { cancel(); co_return std::unexpected(tls_error(result.error())); }
                if (failed_) { cancel(); co_return std::unexpected(TlsServerError::tls); }
                co_return TlsServerStep::progress;
            }
            if (session_.terminated()) {
                release_input(); resume_pending_=false; active_guard.reset();
                ready_to_close_=true; ready_revision_=session_.revision();
                co_return peer_closed_ ? TlsServerStep::peer_closed : TlsServerStep::drained;
            }
            if (session_.paused_stream()) { active_guard.reset(); co_return TlsServerStep::paused; }
            if (resume_pending_) {
                resume_pending_=false;
                auto result=session_.receive({});
                if (!result) { active_guard.reset(); cancel(); co_return std::unexpected(TlsServerError::http2); }
                active_guard.reset();
                if (failed_) { cancel(); co_return std::unexpected(TlsServerError::tls); }
                if (session_.paused_stream()) { resume_pending_=true; co_return TlsServerStep::paused; }
                if (offset_==input_.size()) release_input();
                co_return TlsServerStep::progress;
            }
            if (offset_<input_.size()) {
                auto bytes=std::span{input_}.subspan(offset_);
                auto consumed=session_.receive({reinterpret_cast<std::byte const*>(bytes.data()),bytes.size()});
                if (!consumed || (!*consumed && !session_.paused_stream())) {
                    active_guard.reset(); cancel(); co_return std::unexpected(TlsServerError::http2);
                }
                offset_+=*consumed;
                active_guard.reset();
                if (failed_) { cancel(); co_return std::unexpected(TlsServerError::tls); }
                if (session_.paused_stream()) { resume_pending_=true; co_return TlsServerStep::paused; }
                if (offset_==input_.size()) release_input();
                co_return TlsServerStep::progress;
            }
            if (peer_closed_) { active_guard.reset(); ready_to_close_=true; ready_revision_=session_.revision(); co_return TlsServerStep::peer_closed; }
            if (session_.shutdown_complete()) { active_guard.reset(); ready_to_close_=true; ready_revision_=session_.revision(); co_return TlsServerStep::drained; }
            // Decryption allocates the complete ciphertext payload, including its tag,
            // even for invalid records. Successful output retains that capacity
            // while nghttp2 may borrow it during a paused DATA callback.
            if (!session_.reserve_input(16640)) { active_guard.reset(); cancel(); co_return std::unexpected(TlsServerError::budget_exceeded); }
            input_reserved_=true; InputGuard input_guard{*this};
            // A peer KeyUpdate may create a 27-byte response while reading;
            // sealing its five bytes requires a 55-byte coexistence peak.
            if (!session_.reserve_output(55+rotation_charge_)) { active_guard.reset(); input_guard.release(); cancel(); co_return std::unexpected(TlsServerError::budget_exceeded); }
            control_reserved_=true; ControlGuard control_guard{*this};
            // TLS framing may accumulate a full ciphertext record while a read is parked.
            if (!session_.reserve_ciphertext(16650)) { active_guard.reset(); input_guard.release(); control_guard.release(); cancel(); co_return std::unexpected(TlsServerError::budget_exceeded); }
            CiphertextGuard ciphertext_guard{session_};
            auto received=co_await tls_.read(deadline); active_guard.reset();
            ciphertext_guard.release();
            if (received && !failed_ && tls_.pending_output()) control_guard.dismiss();
            else control_guard.release();
            if (!received) { input_guard.release(); cancel(); co_return std::unexpected(tls_error(received.error())); }
            if (failed_) { input_guard.release(); cancel(); co_return std::unexpected(TlsServerError::tls); }
            if (received->kind==tls::detail::AsyncReadKind::eof) { input_guard.release(); peer_closed_=true; co_return TlsServerStep::progress; }
            if (received->kind==tls::detail::AsyncReadKind::backpressure) { input_guard.release(); co_return TlsServerStep::progress; }
            auto event=std::move(*received->event);
            if (event.kind==tls::ApplicationEventKind::data) input_=std::move(event.data);
            else { input_guard.release(); if (event.kind==tls::ApplicationEventKind::close_notify) peer_closed_=true;
                else if (event.kind==tls::ApplicationEventKind::fatal_alert) { cancel(); co_return std::unexpected(TlsServerError::tls); } }
            if (input_.empty()) input_guard.release();
            else input_guard.dismiss();
            co_return TlsServerStep::progress;
            } catch (std::bad_alloc const&) { abort_exception(); co_return std::unexpected(TlsServerError::allocation); }
              catch (...) { abort_exception(); throw; }
        }
    };
}
