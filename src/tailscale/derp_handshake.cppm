export module tailscale.derp_handshake;
import std;
import tailscale.derp;
import tailscale.derp_messages;
import tailscale.derp_info;
import tailscale.box;
import crypto;

export namespace tailscale::derp {
    using HandshakeClock=std::chrono::steady_clock;
    enum class HandshakeState { server_key,server_info,ready,failed,closed };
    enum class HandshakeError { state,closed,timeout,server_identity,protocol,authentication,backend,info };
    namespace detail {
        struct ClearPlaintext {
            std::array<std::uint8_t,max_info_plaintext>& bytes;
            ~ClearPlaintext() { crypto::cleanse(bytes); }
        };
    }
    // The pin comes from configuration or an independently authenticated
    // control channel. A key read from this same stream is not a trust source.
    // This owner has no socket/tasks. The local node key outlives it; the host
    // supplies unique nonce entropy, one absolute deadline, and ordered frames.
    class PinnedClientHandshake {
        crypto::X25519Private const& local_;
        Key trusted_server_;
        HandshakeClock::time_point started_,deadline_;
        std::optional<box::SharedKey> shared_;
        std::optional<ServerSettings> settings_;
        HandshakeState state_=HandshakeState::server_key;
        struct Attempt {
            PinnedClientHandshake& owner;
            bool completed=false;
            ~Attempt() { if (!completed) owner.fail(); }
        };
        auto fail() noexcept -> void { shared_.reset(); settings_.reset(); state_=HandshakeState::failed; }
        auto check(HandshakeClock::time_point now,HandshakeState expected) noexcept -> std::optional<HandshakeError> {
            if (state_==HandshakeState::closed) return HandshakeError::closed;
            if (state_!=expected) return HandshakeError::state;
            if (deadline_<=started_ || now<started_ || now>=deadline_) { fail(); return HandshakeError::timeout; }
            return {};
        }
    public:
        PinnedClientHandshake(crypto::X25519Private const& local,Key const& trusted_server,
            HandshakeClock::time_point started,HandshakeClock::time_point deadline)
            : local_(local),trusted_server_(trusted_server),started_(started),deadline_(deadline) {}
        ~PinnedClientHandshake() { cancel(); }
        PinnedClientHandshake(PinnedClientHandshake const&)=delete;
        auto operator=(PinnedClientHandshake const&) -> PinnedClientHandshake& = delete;
        auto state() const noexcept -> HandshakeState { return state_; }
        auto settings() const noexcept -> std::optional<ServerSettings> { return state_==HandshakeState::ready ? settings_ : std::nullopt; }
        auto cancel() noexcept -> void { shared_.reset(); settings_.reset(); state_=HandshakeState::closed; }
        auto start(Frame frame,Nonce const& nonce,HandshakeClock::time_point now) -> std::expected<std::vector<std::uint8_t>,HandshakeError> {
            if (auto error=check(now,HandshakeState::server_key)) return std::unexpected(*error);
            Attempt attempt{*this};
            auto remote=parse_server_key(frame);
            if (!remote) return std::unexpected(HandshakeError::protocol);
            if (*remote!=trusted_server_) return std::unexpected(HandshakeError::server_identity);
            auto public_key=local_.public_key();
            auto shared=box::SharedKey::derive(local_,*remote);
            if (!public_key || !shared) return std::unexpected(HandshakeError::backend);
            auto plaintext=std::span(reinterpret_cast<std::uint8_t const*>(regular_client_info.data()),regular_client_info.size());
            auto size=key_size+nonce_size+box::tag_size+plaintext.size();
            auto header=encode_header(Type::client_info,size);
            if (!header) return std::unexpected(HandshakeError::protocol);
            std::vector<std::uint8_t> output(header_size+size);
            std::ranges::copy(*header,output.begin());
            std::ranges::copy(*public_key,output.begin()+header_size);
            std::ranges::copy(nonce,output.begin()+header_size+key_size);
            auto encrypted=shared->seal_to(std::span(output).subspan(header_size+key_size+nonce_size),nonce,plaintext);
            if (!encrypted) return std::unexpected(HandshakeError::backend);
            shared_.emplace(std::move(*shared)); state_=HandshakeState::server_info; attempt.completed=true;
            return output;
        }
        auto finish(Frame frame,HandshakeClock::time_point now) -> std::expected<ServerSettings,HandshakeError> {
            if (auto error=check(now,HandshakeState::server_info)) return std::unexpected(*error);
            Attempt attempt{*this};
            auto envelope=parse_server_info(frame);
            if (!envelope || envelope->ciphertext.size()>max_info_plaintext+box::tag_size) return std::unexpected(HandshakeError::protocol);
            std::array<std::uint8_t,max_info_plaintext> plaintext{};
            detail::ClearPlaintext clear{plaintext};
            auto opened=shared_->open_to(plaintext,envelope->nonce,envelope->ciphertext);
            if (!opened) return std::unexpected(opened.error()==box::Error::authentication ? HandshakeError::authentication : HandshakeError::backend);
            auto parsed=parse_server_settings(std::span(plaintext).first(*opened));
            if (!parsed) return std::unexpected(HandshakeError::info);
            settings_=*parsed; shared_.reset(); state_=HandshakeState::ready; attempt.completed=true;
            return *settings_;
        }
    };
}

