export module wireguard.noise;
import std;
import crypto;
import wireguard;
import wireguard.crypto;
import wireguard.initiation;
import wireguard.session;

export namespace wireguard {
    // Keep one guard per configured peer, across handshake replacements.
    // Authentication happens before this lock; timestamp/rate admission and
    // commit are one transaction even for concurrent initiation attempts.
    class TimestampGuard {
        mutable std::mutex mutex_;
        Timestamp last_{};
        std::optional<Clock::time_point> consumed_;
    public:
        auto commit_authenticated(Timestamp const& timestamp,Clock::time_point now) -> std::expected<void,Error> {
            std::lock_guard lock(mutex_);
            if (timestamp<=last_) return std::unexpected(Error::replay);
            if (consumed_ && (now<*consumed_ || now-*consumed_<=std::chrono::milliseconds(20))) return std::unexpected(Error::too_old);
            last_=timestamp; consumed_=now; return {};
        }
        auto last(this TimestampGuard const& self) -> Timestamp { std::lock_guard lock(self.mutex_); return self.last_; }
    };
    // A single Noise_IKpsk2 attempt for a configured peer. The immutable local
    // identity outlives this object. Fresh ephemeral keys are supplied by the
    // owner's cryptographic RNG; a failed attempt never reuses its state.
    class Handshake {
        enum class State { idle,initiation_sent,initiation_received,response_sent,response_received,finished };
        crypto::X25519Private const& local_;
        Key local_public_,remote_;
        SecretKey psk_,static_shared_;
        detail::Transcript transcript_;
        std::optional<crypto::X25519Private> ephemeral_;
        Key remote_ephemeral_{};
        std::uint32_t local_index_=0,remote_index_=0;
        State state_=State::idle;
        Handshake(crypto::X25519Private const& local,Key local_public,Key remote,SecretKey psk,SecretKey shared) noexcept
            : local_(local),local_public_(local_public),remote_(remote),psk_(std::move(psk)),static_shared_(std::move(shared)) {}
        static auto encrypt(SecretKey const& key,std::span<std::uint8_t const> plaintext,detail::Transcript const& transcript)
            -> std::expected<std::vector<std::uint8_t>,Error> {
            auto result=crypto::seal(crypto::Aead::chacha20_poly1305,key.view(),transport_nonce(0),plaintext,transcript.hash.view());
            if (!result) return std::unexpected(Error::backend); return std::move(*result);
        }
        static auto decrypt(SecretKey const& key,std::span<std::uint8_t const> ciphertext,detail::Transcript const& transcript)
            -> std::expected<std::vector<std::uint8_t>,Error> {
            auto result=crypto::open(crypto::Aead::chacha20_poly1305,key.view(),transport_nonce(0),ciphertext,transcript.hash.view());
            if (!result) return std::unexpected(detail::open_error(result.error())); return std::move(*result);
        }
    public:
        ~Handshake() { close(); }
        Handshake(Handshake const&)=delete;
        auto operator=(Handshake const&) -> Handshake& = delete;
        Handshake(Handshake&& other) noexcept : local_(other.local_),local_public_(other.local_public_),remote_(other.remote_),
            psk_(std::move(other.psk_)),static_shared_(std::move(other.static_shared_)),transcript_(std::move(other.transcript_)),
            ephemeral_(std::move(other.ephemeral_)),remote_ephemeral_(other.remote_ephemeral_),local_index_(other.local_index_),
            remote_index_(other.remote_index_),state_(other.state_) { other.close(); }
        auto operator=(Handshake&&) -> Handshake& = delete;
        static auto create(crypto::X25519Private const& local,Key const& remote,std::span<std::uint8_t const> psk={}) noexcept
            -> std::expected<Handshake,Error> {
            if (!psk.empty() && psk.size()!=32) return std::unexpected(Error::invalid_key);
            auto public_key=local.public_key(); if (!public_key) return std::unexpected(Error::invalid_key);
            auto shared=local.agree(remote); if (!shared) return std::unexpected(Error::invalid_key);
            SecretKey preshared;
            if (!psk.empty()) std::ranges::copy(psk,preshared.writable().begin());
            return Handshake(local,*public_key,remote,std::move(preshared),SecretKey(shared->view()));
        }
        auto close(this Handshake& self) noexcept -> void {
            self.psk_.clear(); self.static_shared_.clear(); self.transcript_.chain.clear(); self.transcript_.hash.clear();
            self.ephemeral_.reset(); crypto::cleanse(self.remote_ephemeral_); self.state_=State::finished;
        }
        auto initiate(std::uint32_t local_index,Timestamp const& timestamp,crypto::X25519Private ephemeral,
            std::span<std::uint8_t const> cookie={}) -> std::expected<std::array<std::uint8_t,initiation_size>,Error> {
            if (state_!=State::idle) return std::unexpected(Error::invalid_state);
            auto transcript=detail::Transcript::initial(remote_); if (!transcript) return std::unexpected(transcript.error());
            auto public_key=ephemeral.public_key(); if (!public_key) return std::unexpected(Error::invalid_key);
            Initiation message; message.sender=local_index; message.ephemeral=*public_key;
            auto mixed=transcript->mix_hash(message.ephemeral); if (!mixed) return std::unexpected(mixed.error());
            mixed=transcript->mix_key(message.ephemeral); if (!mixed) return std::unexpected(mixed.error());
            auto shared=ephemeral.agree(remote_); if (!shared) return std::unexpected(Error::invalid_key);
            auto key=transcript->mix_key2(shared->view()); if (!key) return std::unexpected(key.error());
            auto encrypted=encrypt(*key,local_public_,*transcript); if (!encrypted) return std::unexpected(encrypted.error());
            if (encrypted->size()!=message.encrypted_static.size()) return std::unexpected(Error::backend);
            std::ranges::copy(*encrypted,message.encrypted_static.begin());
            mixed=transcript->mix_hash(message.encrypted_static); if (!mixed) return std::unexpected(mixed.error());
            key=transcript->mix_key2(static_shared_.view()); if (!key) return std::unexpected(key.error());
            encrypted=encrypt(*key,timestamp,*transcript); if (!encrypted) return std::unexpected(encrypted.error());
            if (encrypted->size()!=message.encrypted_timestamp.size()) return std::unexpected(Error::backend);
            std::ranges::copy(*encrypted,message.encrypted_timestamp.begin());
            mixed=transcript->mix_hash(message.encrypted_timestamp); if (!mixed) return std::unexpected(mixed.error());
            auto wire=encode(message); auto macs=detail::add_macs(wire,remote_,cookie); if (!macs) return std::unexpected(macs.error());
            transcript_=std::move(*transcript); ephemeral_.emplace(std::move(ephemeral));
            local_index_=local_index; state_=State::initiation_sent; return wire;
        }
        auto consume_initiation(std::span<std::uint8_t const> wire,TimestampGuard& replay,Clock::time_point now)
            -> std::expected<void,Error> {
            if (state_!=State::idle) return std::unexpected(Error::invalid_state);
            auto opened=OpenedInitiation::open(local_,local_public_,wire); if (!opened) return std::unexpected(opened.error());
            return consume_opened(std::move(*opened),replay,now);
        }
        auto consume_opened(OpenedInitiation opened,TimestampGuard& replay,Clock::time_point now) -> std::expected<void,Error> {
            if (state_!=State::idle) return std::unexpected(Error::invalid_state);
            auto state=opened.take(); if (!state) return std::unexpected(state.error());
            if (!crypto::constant_time_equal(state->local_public,local_public_) || !crypto::constant_time_equal(state->remote_public,remote_)) return std::unexpected(Error::authentication);
            auto key=state->transcript.mix_key2(static_shared_.view()); if (!key) return std::unexpected(key.error());
            auto plaintext=decrypt(*key,state->encrypted_timestamp,state->transcript); if (!plaintext) return std::unexpected(plaintext.error());
            detail::Erase erase_timestamp{*plaintext};
            if (plaintext->size()!=12) return std::unexpected(Error::authentication);
            auto mixed=state->transcript.mix_hash(state->encrypted_timestamp); if (!mixed) return mixed;
            Timestamp timestamp; std::ranges::copy(*plaintext,timestamp.begin());
            auto admitted=replay.commit_authenticated(timestamp,now); if (!admitted) return admitted;
            transcript_=std::move(state->transcript); remote_index_=state->sender; remote_ephemeral_=state->ephemeral;
            state_=State::initiation_received; return {};
        }
        auto respond(std::uint32_t local_index,crypto::X25519Private ephemeral,std::span<std::uint8_t const> cookie={})
            -> std::expected<std::array<std::uint8_t,response_size>,Error> {
            if (state_!=State::initiation_received) return std::unexpected(Error::invalid_state);
            auto transcript=transcript_.clone();
            auto public_key=ephemeral.public_key(); if (!public_key) return std::unexpected(Error::invalid_key);
            Response message; message.sender=local_index; message.receiver=remote_index_; message.ephemeral=*public_key;
            auto mixed=transcript.mix_hash(message.ephemeral); if (!mixed) return std::unexpected(mixed.error());
            mixed=transcript.mix_key(message.ephemeral); if (!mixed) return std::unexpected(mixed.error());
            auto shared=ephemeral.agree(remote_ephemeral_); if (!shared) return std::unexpected(Error::invalid_key);
            mixed=transcript.mix_key(shared->view()); if (!mixed) return std::unexpected(mixed.error());
            shared=ephemeral.agree(remote_); if (!shared) return std::unexpected(Error::invalid_key);
            mixed=transcript.mix_key(shared->view()); if (!mixed) return std::unexpected(mixed.error());
            auto key=transcript.mix_psk(psk_.view()); if (!key) return std::unexpected(key.error());
            auto encrypted=encrypt(*key,{},transcript); if (!encrypted) return std::unexpected(encrypted.error());
            if (encrypted->size()!=message.encrypted_empty.size()) return std::unexpected(Error::backend);
            std::ranges::copy(*encrypted,message.encrypted_empty.begin());
            mixed=transcript.mix_hash(message.encrypted_empty); if (!mixed) return std::unexpected(mixed.error());
            auto wire=encode(message); auto macs=detail::add_macs(wire,remote_,cookie); if (!macs) return std::unexpected(macs.error());
            transcript_=std::move(transcript); local_index_=local_index; state_=State::response_sent; return wire;
        }
        auto consume_response(std::span<std::uint8_t const> wire) -> std::expected<void,Error> {
            if (state_!=State::initiation_sent || !ephemeral_) return std::unexpected(Error::invalid_state);
            auto authenticated=detail::check_mac1(wire,local_public_); if (!authenticated) return authenticated;
            auto message=parse_response(wire); if (!message) return std::unexpected(message.error());
            if (message->receiver!=local_index_) return std::unexpected(Error::invalid_state);
            auto transcript=transcript_.clone();
            auto mixed=transcript.mix_hash(message->ephemeral); if (!mixed) return mixed;
            mixed=transcript.mix_key(message->ephemeral); if (!mixed) return mixed;
            auto shared=ephemeral_->agree(message->ephemeral); if (!shared) return std::unexpected(Error::invalid_key);
            mixed=transcript.mix_key(shared->view()); if (!mixed) return mixed;
            shared=local_.agree(message->ephemeral); if (!shared) return std::unexpected(Error::invalid_key);
            mixed=transcript.mix_key(shared->view()); if (!mixed) return mixed;
            auto key=transcript.mix_psk(psk_.view()); if (!key) return std::unexpected(key.error());
            auto plaintext=decrypt(*key,message->encrypted_empty,transcript); if (!plaintext) return std::unexpected(plaintext.error());
            if (!plaintext->empty()) { crypto::cleanse(*plaintext); return std::unexpected(Error::authentication); }
            mixed=transcript.mix_hash(message->encrypted_empty); if (!mixed) return mixed;
            transcript_=std::move(transcript); remote_index_=message->sender; state_=State::response_received; return {};
        }
        auto finish(Clock::time_point now) -> std::expected<Session,Error> {
            if (state_!=State::response_sent && state_!=State::response_received) return std::unexpected(Error::invalid_state);
            auto keys=detail::derive(transcript_.chain.view(),{},2); if (!keys) return std::unexpected(keys.error());
            auto initiator=state_==State::response_received;
            Session session(std::move((*keys)[initiator ? 0 : 1]),std::move((*keys)[initiator ? 1 : 0]),local_index_,remote_index_,initiator,now);
            close(); return session;
        }
    };
}
