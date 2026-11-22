export module wireguard.initiation;
import std;
import crypto;
import wireguard;
import wireguard.admission;
import wireguard.crypto;

export namespace wireguard {
    struct OpenedInitiationState {
        detail::Transcript transcript;
        Key local_public{},remote_public{},ephemeral{};
        std::array<std::uint8_t,28> encrypted_timestamp{};
        std::uint32_t sender=0;
        OpenedInitiationState()=default;
        ~OpenedInitiationState() { clear(); }
        OpenedInitiationState(OpenedInitiationState const&)=delete;
        auto operator=(OpenedInitiationState const&) -> OpenedInitiationState& = delete;
        OpenedInitiationState(OpenedInitiationState&& other) noexcept : transcript(std::move(other.transcript)),local_public(other.local_public),remote_public(other.remote_public),
            ephemeral(other.ephemeral),encrypted_timestamp(other.encrypted_timestamp),sender(other.sender) { other.clear(); }
        auto operator=(OpenedInitiationState&& other) noexcept -> OpenedInitiationState& {
            if (this!=&other) { clear(); transcript=std::move(other.transcript); local_public=other.local_public; remote_public=other.remote_public;
                ephemeral=other.ephemeral; encrypted_timestamp=other.encrypted_timestamp; sender=other.sender; other.clear(); } return *this;
        }
        auto clear() noexcept -> void {
            transcript.chain.clear(); transcript.hash.clear(); crypto::cleanse(local_public); crypto::cleanse(remote_public);
            crypto::cleanse(ephemeral); crypto::cleanse(encrypted_timestamp); sender=0;
        }
    };
    namespace initiation_detail {
        struct NoHooks { static auto static_dh() noexcept -> void {} static auto static_decrypt() noexcept -> void {} };
    }
    // The initiator static is decrypted exactly once with the local identity.
    // A token identifies one candidate peer; only selected-peer ss/timestamp
    // authentication may admit it. It has no owner/key/span borrow.
    class OpenedInitiation {
        OpenedInitiationState state_;
        bool active_=true;
        explicit OpenedInitiation(OpenedInitiationState state) noexcept : state_(std::move(state)) {}
    public:
        ~OpenedInitiation() { close(); }
        OpenedInitiation(OpenedInitiation const&)=delete;
        auto operator=(OpenedInitiation const&) -> OpenedInitiation& = delete;
        OpenedInitiation(OpenedInitiation&& other) noexcept : state_(std::move(other.state_)),active_(std::exchange(other.active_,false)) {}
        auto operator=(OpenedInitiation&& other) noexcept -> OpenedInitiation& {
            if (this!=&other) { close(); state_=std::move(other.state_); active_=std::exchange(other.active_,false); } return *this;
        }
        auto close() noexcept -> void { state_.clear(); active_=false; }
        [[nodiscard]] auto valid() const noexcept -> bool { return active_; }
        [[nodiscard]] auto remote_public() const noexcept -> Key const& { return state_.remote_public; }
        [[nodiscard]] auto local_public() const noexcept -> Key const& { return state_.local_public; }
        [[nodiscard]] auto take() noexcept -> std::expected<OpenedInitiationState,Error> {
            if (!std::exchange(active_,false)) return std::unexpected(Error::invalid_state);
            return std::move(state_);
        }
        template<class Hooks=initiation_detail::NoHooks>
        [[nodiscard]] static auto open(crypto::X25519Private const& local,Key const& public_key,AdmittedHandshake admitted) -> std::expected<OpenedInitiation,Error> {
            static_assert(noexcept(Hooks::static_dh()) && noexcept(Hooks::static_decrypt()));
            auto packet=admitted.take(); if (!packet) return std::unexpected(packet.error());
            auto message=parse_initiation(std::span(packet->bytes).first(packet->size)); if (!message) return std::unexpected(message.error());
            if (!crypto::constant_time_equal(public_key,packet->local_public)) return std::unexpected(Error::authentication);
            auto transcript=detail::Transcript::initial(public_key); if (!transcript) return std::unexpected(transcript.error());
            auto mixed=transcript->mix_hash(message->ephemeral); if (!mixed) return std::unexpected(mixed.error());
            mixed=transcript->mix_key(message->ephemeral); if (!mixed) return std::unexpected(mixed.error());
            Hooks::static_dh(); auto shared=local.agree(message->ephemeral); if (!shared) return std::unexpected(Error::invalid_key);
            auto key=transcript->mix_key2(shared->view()); if (!key) return std::unexpected(key.error());
            Hooks::static_decrypt(); auto remote=crypto::open(crypto::Aead::chacha20_poly1305,key->view(),transport_nonce(0),message->encrypted_static,transcript->hash.view());
            if (!remote) return std::unexpected(detail::open_error(remote.error()));
            detail::Erase erase_remote{*remote};
            if (remote->size()!=32) return std::unexpected(Error::authentication);
            mixed=transcript->mix_hash(message->encrypted_static); if (!mixed) return std::unexpected(mixed.error());
            OpenedInitiationState state; state.transcript=std::move(*transcript); state.local_public=public_key;
            std::ranges::copy(*remote,state.remote_public.begin()); state.ephemeral=message->ephemeral; state.encrypted_timestamp=message->encrypted_timestamp; state.sender=message->sender;
            return OpenedInitiation(std::move(state));
        }
        template<class Hooks=initiation_detail::NoHooks>
        [[nodiscard]] static auto open(crypto::X25519Private const& local,AdmittedHandshake admitted) -> std::expected<OpenedInitiation,Error> {
            auto public_key=local.public_key(); if (!public_key) return std::unexpected(Error::invalid_key);
            return open<Hooks>(local,*public_key,std::move(admitted));
        }
        template<class Hooks=initiation_detail::NoHooks>
        [[nodiscard]] static auto open(crypto::X25519Private const& local,Key const& public_key,std::span<std::uint8_t const> wire) -> std::expected<OpenedInitiation,Error> {
            auto admitted=AdmittedHandshake::authenticate(public_key,wire); if (!admitted) return std::unexpected(admitted.error());
            return open<Hooks>(local,public_key,std::move(*admitted));
        }
        template<class Hooks=initiation_detail::NoHooks>
        [[nodiscard]] static auto open(crypto::X25519Private const& local,std::span<std::uint8_t const> wire) -> std::expected<OpenedInitiation,Error> {
            auto public_key=local.public_key(); if (!public_key) return std::unexpected(Error::invalid_key);
            return open<Hooks>(local,*public_key,wire);
        }
    };
}
