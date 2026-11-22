export module tailscale.control;
import std;
import crypto;
import crypto.aead_context;
import wireguard.blake2s;

export namespace tailscale::control {
    using Clock=std::chrono::steady_clock;
    using KeyBytes=std::array<std::uint8_t,32>;
    enum class Role { client,server };
    enum class Error { state,closed,timeout,framing,peer_hint,authentication,backend,capacity,overlap,exhausted };
    struct MachineTag;
    struct ControlTag;
    struct NodeTag;
    struct EphemeralTag;
    template<class Tag>
    class PublicKey {
        KeyBytes bytes_{};
    public:
        PublicKey()=default;
        static auto from_bytes(std::span<std::uint8_t const> bytes) noexcept -> std::expected<PublicKey,crypto::Error> {
            if (bytes.size()!=32) return std::unexpected(crypto::Error::invalid_key);
            PublicKey result;std::ranges::copy(bytes,result.bytes_.begin());return result;
        }
        auto view() const noexcept -> std::span<std::uint8_t const,32> {return bytes_;}
        auto operator==(PublicKey const&) const -> bool = default;
    };
    template<class Tag>
    class PrivateKey {
        crypto::X25519Private key_;
        explicit PrivateKey(crypto::X25519Private&& key) noexcept : key_(std::move(key)) {}
    public:
        PrivateKey(PrivateKey const&)=delete;
        auto operator=(PrivateKey const&) -> PrivateKey& = delete;
        PrivateKey(PrivateKey&&) noexcept=default;
        auto operator=(PrivateKey&&) noexcept -> PrivateKey& = default;
        static auto generate() -> std::expected<PrivateKey,crypto::Error> {
            auto key=crypto::X25519Private::generate();if (!key) return std::unexpected(key.error());
            return PrivateKey(std::move(*key));
        }
        static auto from_bytes(std::span<std::uint8_t const> bytes) -> std::expected<PrivateKey,crypto::Error> {
            auto key=crypto::X25519Private::from_bytes(bytes);if (!key) return std::unexpected(key.error());
            return PrivateKey(std::move(*key));
        }
        auto public_key() const -> std::expected<PublicKey<Tag>,crypto::Error> {
            auto bytes=key_.public_key();if (!bytes) return std::unexpected(bytes.error());
            return PublicKey<Tag>::from_bytes(*bytes);
        }
        template<class PeerTag>
        auto agree(PublicKey<PeerTag> const& peer) const -> std::expected<crypto::Secret32,crypto::Error> {
            return key_.agree(peer.view());
        }
    };
    using MachinePublic=PublicKey<MachineTag>;
    using ControlPublic=PublicKey<ControlTag>;
    using NodePublic=PublicKey<NodeTag>;
    using EphemeralPublic=PublicKey<EphemeralTag>;
    using MachinePrivate=PrivateKey<MachineTag>;
    using ControlPrivate=PrivateKey<ControlTag>;
    using NodePrivate=PrivateKey<NodeTag>;
    using EphemeralPrivate=PrivateKey<EphemeralTag>;
    template<Role> class Handshake;
    class Records;
    // Only a completed Noise handshake can produce installable keys. Moving
    // this one-shot material clears its source; installing consumes it too.
    class TransportKeys {
        KeyBytes tx_{},rx_{};
        bool available_=false;
        TransportKeys()=default;
        template<Role> friend class Handshake;
        friend class Records;
        auto clear() noexcept -> void {crypto::cleanse(tx_);crypto::cleanse(rx_);available_=false;}
    public:
        ~TransportKeys() {clear();}
        TransportKeys(TransportKeys const&)=delete;
        auto operator=(TransportKeys const&) -> TransportKeys& = delete;
        TransportKeys(TransportKeys&& other) noexcept : tx_(other.tx_),rx_(other.rx_),available_(other.available_) {other.clear();}
        auto operator=(TransportKeys&& other) noexcept -> TransportKeys& {
            if (this!=&other) {clear();tx_=other.tx_;rx_=other.rx_;available_=other.available_;other.clear();}return *this;
        }
        auto available() const noexcept -> bool {return available_;}
    };
}

export namespace tailscale::control {
    enum class HandshakeState { initial,await_response,ready,taken,failed,closed };
    inline constexpr std::size_t initiation_size=101,response_size=51,max_public_hint=256;
    namespace detail {
        inline auto bytes(std::string_view text) noexcept -> std::span<std::uint8_t const> {
            return {reinterpret_cast<std::uint8_t const*>(text.data()),text.size()};
        }
        template<class Buffer> struct Erase {Buffer& buffer;~Erase() {crypto::cleanse(buffer);}};
        inline auto read16(std::span<std::uint8_t const> value) noexcept -> std::uint16_t {
            return static_cast<std::uint16_t>((std::uint16_t(value[0])<<8)|value[1]);
        }
        inline auto write16(std::span<std::uint8_t> value,std::uint16_t number) noexcept -> void {
            value[0]=static_cast<std::uint8_t>(number>>8);value[1]=static_cast<std::uint8_t>(number);
        }
        class SymmetricState {
            KeyBytes hash_{},chain_{};
            bool initialized_=false;
            auto expand(std::span<std::uint8_t const> input,std::span<std::uint8_t,32> first,
                std::span<std::uint8_t,32> second) noexcept -> std::expected<void,Error> {
                KeyBytes extract{};Erase clear{extract};
                std::array<std::uint8_t,1> one{1},two{2};
                if (!wireguard::blake2s::hmac_to(extract,chain_,{input}) ||
                    !wireguard::blake2s::hmac_to(first,extract,{one}) ||
                    !wireguard::blake2s::hmac_to(second,extract,{first,two})) return std::unexpected(Error::backend);
                return {};
            }
        public:
            SymmetricState()=default;
            ~SymmetricState() {clear();}
            SymmetricState(SymmetricState const&)=delete;
            auto operator=(SymmetricState const&) -> SymmetricState& = delete;
            auto clear() noexcept -> void {crypto::cleanse(hash_);crypto::cleanse(chain_);initialized_=false;}
            auto hash() const noexcept -> std::span<std::uint8_t const,32> {return hash_;}
            auto mix_hash(std::span<std::uint8_t const> input) noexcept -> std::expected<void,Error> {
                if (!initialized_) return std::unexpected(Error::state);
                KeyBytes next{};Erase clear{next};
                if (!wireguard::blake2s::digest_parts_to(std::span(next),{hash_,input})) return std::unexpected(Error::backend);
                hash_=next;return {};
            }
            auto initialize(ControlPublic const& responder,std::uint16_t version) noexcept -> std::expected<void,Error> {
                clear();
                if (!wireguard::blake2s::digest_to(std::span(hash_),bytes("Noise_IK_25519_ChaChaPoly_BLAKE2s"))) return std::unexpected(Error::backend);
                chain_=hash_;initialized_=true;
                constexpr std::string_view prefix="Tailscale Control Protocol v";
                std::array<char,prefix.size()+5> prologue{};std::ranges::copy(prefix,prologue.begin());
                auto number=std::to_chars(prologue.data()+prefix.size(),prologue.data()+prologue.size(),version);
                if (number.ec!=std::errc{}) return std::unexpected(Error::backend);
                auto mixed=mix_hash(bytes({prologue.data(),static_cast<std::size_t>(number.ptr-prologue.data())}));
                if (!mixed) return mixed;
                return mix_hash(responder.view());
            }
            template<class LocalTag,class PeerTag>
            auto mix_dh(crypto::AeadContext& cipher,PrivateKey<LocalTag> const& local,PublicKey<PeerTag> const& peer) noexcept -> std::expected<void,Error> {
                if (!initialized_) return std::unexpected(Error::state);
                cipher.clear();
                auto secret=local.agree(peer);if (!secret) return std::unexpected(Error::backend);
                KeyBytes chain{},key{};Erase clear_chain{chain};Erase clear_key{key};
                auto derived=expand(secret->view(),chain,key);if (!derived) return derived;
                chain_=chain;
                if (!cipher.reset(crypto::Aead::chacha20_poly1305,key)) return std::unexpected(Error::backend);
                return {};
            }
            auto crypt(crypto::AeadContext& cipher,bool encrypt,std::span<std::uint8_t> output,std::span<std::uint8_t const> input) noexcept -> std::expected<void,Error> {
                if (!initialized_ || !cipher.valid()) return std::unexpected(Error::state);
                // Every MixDH-derived handshake key is used exactly once at nonce zero.
                std::array<std::uint8_t,12> nonce{};
                auto result=encrypt ? cipher.seal_to(output,nonce,input,hash_) : cipher.open_to(output,nonce,input,hash_);
                cipher.clear();
                if (!result) return std::unexpected(result.error()==crypto::Error::authentication_failed ? Error::authentication : Error::backend);
                return mix_hash(encrypt ? std::span<std::uint8_t const>(output.first(*result)) : input);
            }
            auto split(std::span<std::uint8_t,32> first,std::span<std::uint8_t,32> second) noexcept -> std::expected<void,Error> {
                if (!initialized_) return std::unexpected(Error::state);
                auto result=expand({},first,second);clear();return result;
            }
        };
    }
    // A pure, bounded Noise IK owner. The static local key outlives this
    // object. The caller supplies a fresh ephemeral key for each attempt and
    // one monotonic absolute handshake budget, then sends the returned frame.
    // The client pin must come from an independent trust source.
    template<Role Side>
    class Handshake {
        using Local=std::conditional_t<Side==Role::client,MachinePrivate,ControlPrivate>;
        Local const& local_;
        ControlPublic control_;
        MachinePublic machine_;
        std::optional<EphemeralPrivate> ephemeral_;
        detail::SymmetricState symmetric_;
        TransportKeys keys_;
        KeyBytes hash_{};
        Clock::time_point started_,deadline_,last_;
        std::uint16_t version_=0;
        HandshakeState state_=HandshakeState::initial;
        auto fail() noexcept -> void {ephemeral_.reset();symmetric_.clear();keys_.clear();crypto::cleanse(hash_);state_=HandshakeState::failed;}
        struct Attempt {Handshake& owner;bool done=false;~Attempt() {if (!done) owner.fail();}};
        auto check(Clock::time_point now,HandshakeState wanted) noexcept -> std::optional<Error> {
            if (state_==HandshakeState::closed) return Error::closed;
            if (state_!=wanted) return Error::state;
            if (deadline_<=started_ || now<last_ || now>=deadline_) {fail();return Error::timeout;}
            last_=now;return {};
        }
        auto finish_keys() noexcept -> std::expected<void,Error> {
            std::ranges::copy(symmetric_.hash(),hash_.begin());
            auto result=[&] {
                if constexpr (Side==Role::client) return symmetric_.split(keys_.tx_,keys_.rx_);
                else return symmetric_.split(keys_.rx_,keys_.tx_);
            }();
            if (!result) return result;
            ephemeral_.reset();keys_.available_=true;state_=HandshakeState::ready;return {};
        }
        auto metadata_ready() const noexcept -> bool {return state_==HandshakeState::ready || state_==HandshakeState::taken;}
    public:
        Handshake(Local const& local,ControlPublic pin,std::uint16_t version,Clock::time_point started,Clock::time_point deadline)
            requires (Side==Role::client) : local_(local),control_(pin),started_(started),deadline_(deadline),last_(started),version_(version) {}
        Handshake(Local const& local,Clock::time_point started,Clock::time_point deadline)
            requires (Side==Role::server) : local_(local),started_(started),deadline_(deadline),last_(started) {}
        ~Handshake() {cancel();}
        Handshake(Handshake const&)=delete;
        auto operator=(Handshake const&) -> Handshake& = delete;
        auto state() const noexcept -> HandshakeState {return state_;}
        auto protocol_version() const noexcept -> std::optional<std::uint16_t> {return metadata_ready() ? std::optional(version_) : std::nullopt;}
        auto handshake_hash() const noexcept -> std::optional<KeyBytes> {return metadata_ready() ? std::optional(hash_) : std::nullopt;}
        auto machine_peer() const noexcept -> std::optional<MachinePublic> requires (Side==Role::server) {
            return metadata_ready() ? std::optional(machine_) : std::nullopt;
        }
        auto control_peer() const noexcept -> std::optional<ControlPublic> requires (Side==Role::client) {
            return metadata_ready() ? std::optional(control_) : std::nullopt;
        }
        auto cancel() noexcept -> void {fail();state_=HandshakeState::closed;}
        auto start(EphemeralPrivate&& ephemeral,Clock::time_point now) noexcept -> std::expected<std::array<std::uint8_t,initiation_size>,Error>
            requires (Side==Role::client) {
            if (auto error=check(now,HandshakeState::initial)) return std::unexpected(*error);
            Attempt attempt{*this};crypto::AeadContext cipher;ephemeral_.emplace(std::move(ephemeral));
            auto machine=local_.public_key();auto public_ephemeral=ephemeral_->public_key();
            if (!machine || !public_ephemeral) return std::unexpected(Error::backend);
            std::array<std::uint8_t,initiation_size> wire{};
            detail::write16(wire,version_);wire[2]=1;detail::write16(std::span(wire).subspan(3),96);
            std::ranges::copy(public_ephemeral->view(),wire.begin()+5);
            if (auto result=symmetric_.initialize(control_,version_);!result) return std::unexpected(result.error());
            if (auto result=symmetric_.mix_hash(public_ephemeral->view());!result) return std::unexpected(result.error());
            if (auto result=symmetric_.mix_dh(cipher,*ephemeral_,control_);!result) return std::unexpected(result.error());
            if (auto result=symmetric_.crypt(cipher,true,std::span(wire).subspan(37,48),machine->view());!result) return std::unexpected(result.error());
            if (auto result=symmetric_.mix_dh(cipher,local_,control_);!result) return std::unexpected(result.error());
            if (auto result=symmetric_.crypt(cipher,true,std::span(wire).subspan(85),{});!result) return std::unexpected(result.error());
            machine_=*machine;state_=HandshakeState::await_response;attempt.done=true;return wire;
        }
        auto finish(std::span<std::uint8_t const> wire,Clock::time_point now) noexcept -> std::expected<void,Error>
            requires (Side==Role::client) {
            if (auto error=check(now,HandshakeState::await_response)) return std::unexpected(*error);
            Attempt attempt{*this};crypto::AeadContext cipher;
            if (wire.size()>=3 && wire[0]==3 && wire.size()==3+detail::read16(wire.subspan(1)) && wire.size()<=3+max_public_hint)
                return std::unexpected(Error::peer_hint); // Unauthenticated, deliberately not published as trusted text.
            if (wire.size()!=response_size || wire[0]!=2 || detail::read16(wire.subspan(1))!=48) return std::unexpected(Error::framing);
            auto ephemeral=EphemeralPublic::from_bytes(wire.subspan(3,32));if (!ephemeral) return std::unexpected(Error::framing);
            if (auto result=symmetric_.mix_hash(ephemeral->view());!result) return result;
            if (auto result=symmetric_.mix_dh(cipher,*ephemeral_,*ephemeral);!result) return result;
            if (auto result=symmetric_.mix_dh(cipher,local_,*ephemeral);!result) return result;
            if (auto result=symmetric_.crypt(cipher,false,{},wire.subspan(35));!result) return result;
            auto result=finish_keys();if (!result) return result;attempt.done=true;return {};
        }
        auto respond(std::span<std::uint8_t const> wire,EphemeralPrivate&& ephemeral,Clock::time_point now) noexcept
            -> std::expected<std::array<std::uint8_t,response_size>,Error> requires (Side==Role::server) {
            if (auto error=check(now,HandshakeState::initial)) return std::unexpected(*error);
            Attempt attempt{*this};crypto::AeadContext cipher;
            if (wire.size()!=initiation_size || wire[2]!=1 || detail::read16(wire.subspan(3))!=96) return std::unexpected(Error::framing);
            version_=detail::read16(wire);ephemeral_.emplace(std::move(ephemeral));
            auto control=local_.public_key();auto public_ephemeral=ephemeral_->public_key();
            auto remote_ephemeral=EphemeralPublic::from_bytes(wire.subspan(5,32));
            if (!control || !public_ephemeral || !remote_ephemeral) return std::unexpected(Error::backend);
            if (auto result=symmetric_.initialize(*control,version_);!result) return std::unexpected(result.error());
            if (auto result=symmetric_.mix_hash(remote_ephemeral->view());!result) return std::unexpected(result.error());
            if (auto result=symmetric_.mix_dh(cipher,local_,*remote_ephemeral);!result) return std::unexpected(result.error());
            KeyBytes plaintext{};detail::Erase erase{plaintext};
            if (auto result=symmetric_.crypt(cipher,false,plaintext,wire.subspan(37,48));!result) return std::unexpected(result.error());
            auto candidate=MachinePublic::from_bytes(plaintext);if (!candidate) return std::unexpected(Error::framing);
            if (auto result=symmetric_.mix_dh(cipher,local_,*candidate);!result) return std::unexpected(result.error());
            if (auto result=symmetric_.crypt(cipher,false,{},wire.subspan(85));!result) return std::unexpected(result.error());
            std::array<std::uint8_t,response_size> response{};response[0]=2;detail::write16(std::span(response).subspan(1),48);
            std::ranges::copy(public_ephemeral->view(),response.begin()+3);
            if (auto result=symmetric_.mix_hash(public_ephemeral->view());!result) return std::unexpected(result.error());
            if (auto result=symmetric_.mix_dh(cipher,*ephemeral_,*remote_ephemeral);!result) return std::unexpected(result.error());
            if (auto result=symmetric_.mix_dh(cipher,*ephemeral_,*candidate);!result) return std::unexpected(result.error());
            if (auto result=symmetric_.crypt(cipher,true,std::span(response).subspan(35),{});!result) return std::unexpected(result.error());
            control_=*control;machine_=*candidate;
            if (auto result=finish_keys();!result) return std::unexpected(result.error());
            attempt.done=true;return response;
        }
        auto take_transport() noexcept -> std::expected<TransportKeys,Error> {
            if (state_!=HandshakeState::ready || !keys_.available_) return std::unexpected(Error::state);
            state_=HandshakeState::taken;return std::move(keys_);
        }
    };
    using ClientHandshake=Handshake<Role::client>;
    using ServerHandshake=Handshake<Role::server>;
}

export namespace tailscale::control {
    inline constexpr std::size_t record_header_size=3,max_record_wire=4096,max_record_ciphertext=4093,max_record_plaintext=4077;
    namespace record_detail {
        inline auto overlaps(std::span<std::uint8_t> output,std::span<std::uint8_t const> input) noexcept -> bool {
            if (output.empty() || input.empty()) return false;
            auto first=reinterpret_cast<std::uintptr_t>(output.data()),second=reinterpret_cast<std::uintptr_t>(input.data());
            return first<=second ? second-first<output.size() : first-second<input.size();
        }
        inline auto length(std::span<std::uint8_t const> wire) noexcept -> std::size_t {return (std::size_t(wire[1])<<8)|wire[2];}
    }
    // Tailscale controlbase uses big-endian counter bytes, including at the
    // Noise transport boundary. The all-ones counter is never used.
    class NonceCounter {
        std::uint64_t next_=0;
    public:
        explicit NonceCounter(std::uint64_t first=0) noexcept : next_(first) {}
        auto exhausted() const noexcept -> bool {return next_==std::numeric_limits<std::uint64_t>::max();}
        auto take() noexcept -> std::expected<std::array<std::uint8_t,12>,Error> {
            if (exhausted()) return std::unexpected(Error::exhausted);
            std::array<std::uint8_t,12> result{};
            auto value=next_++;for (unsigned i=0;i<8;++i) {result[11-i]=static_cast<std::uint8_t>(value);value>>=8;}
            return result;
        }
        auto clear() noexcept -> void {next_=std::numeric_limits<std::uint64_t>::max();}
    };
    // Stable-address contexts with no wrapper allocation. One ordered writer
    // and one reader may operate independently. A generated record consumes
    // its nonce immediately; the host must confirm the complete write with
    // sent(), or call fail_send() after any partial/failed/abandoned write.
    class Records {
        crypto::AeadContext tx_,rx_;
        NonceCounter tx_nonce_,rx_nonce_;
        bool installed_=false,tx_alive_=false,rx_alive_=false,pending_=false;
    public:
        Records()=default;
        ~Records() {cancel();}
        Records(Records const&)=delete;
        auto operator=(Records const&) -> Records& = delete;
        Records(Records&&)=delete;
        auto operator=(Records&&) -> Records& = delete;
        auto send_alive() const noexcept -> bool {return tx_alive_;}
        auto receive_alive() const noexcept -> bool {return rx_alive_;}
        auto send_pending() const noexcept -> bool {return pending_;}
        auto fail_send() noexcept -> void {tx_.clear();tx_nonce_.clear();tx_alive_=false;pending_=false;}
        auto fail_receive() noexcept -> void {rx_.clear();rx_nonce_.clear();rx_alive_=false;}
        auto cancel() noexcept -> void {fail_send();fail_receive();}
        auto install(TransportKeys&& keys) noexcept -> std::expected<void,Error> {
            if (installed_ || tx_nonce_.exhausted() || rx_nonce_.exhausted() || !keys.available_) return std::unexpected(Error::state);
            installed_=true;
            auto tx=tx_.reset(crypto::Aead::chacha20_poly1305,keys.tx_);
            auto rx=rx_.reset(crypto::Aead::chacha20_poly1305,keys.rx_);
            keys.clear();
            if (!tx || !rx) {cancel();return std::unexpected(Error::backend);}
            tx_alive_=rx_alive_=true;return {};
        }
        auto sent() noexcept -> std::expected<void,Error> {
            if (!tx_alive_) return std::unexpected(Error::closed);
            if (!pending_) return std::unexpected(Error::state);
            pending_=false;return {};
        }
        auto seal_to(std::span<std::uint8_t> output,std::span<std::uint8_t const> plaintext) noexcept -> std::expected<std::size_t,Error> {
            if (!tx_alive_) return std::unexpected(installed_ || tx_nonce_.exhausted() ? Error::closed : Error::state);
            if (pending_) return std::unexpected(Error::state);
            if (plaintext.size()>max_record_plaintext || output.size()<record_header_size+16+plaintext.size()) return std::unexpected(Error::capacity);
            auto wire=output.first(record_header_size+16+plaintext.size());
            if (plaintext.data()!=wire.data()+record_header_size && record_detail::overlaps(wire,plaintext)) return std::unexpected(Error::overlap);
            auto nonce=tx_nonce_.take();if (!nonce) {fail_send();return std::unexpected(nonce.error());}
            auto sealed=tx_.seal_to(wire.subspan(record_header_size),*nonce,plaintext);
            if (!sealed) {fail_send();return std::unexpected(Error::backend);}
            wire[0]=4;wire[1]=static_cast<std::uint8_t>(*sealed>>8);wire[2]=static_cast<std::uint8_t>(*sealed);
            pending_=true;return wire.size();
        }
        auto open_to(std::span<std::uint8_t> output,std::span<std::uint8_t const> wire) noexcept -> std::expected<std::size_t,Error> {
            if (!rx_alive_) return std::unexpected(installed_ || rx_nonce_.exhausted() ? Error::closed : Error::state);
            if (wire.size()<record_header_size+16 || wire.size()>max_record_wire || wire[0]!=4 || record_detail::length(wire)!=wire.size()-record_header_size) {
                fail_receive();return std::unexpected(Error::framing);
            }
            auto size=wire.size()-record_header_size-16;
            if (output.size()<size) return std::unexpected(Error::capacity);
            auto destination=output.first(size);
            if (destination.data()!=wire.data()+record_header_size && record_detail::overlaps(destination,wire)) return std::unexpected(Error::overlap);
            auto nonce=rx_nonce_.take();if (!nonce) {fail_receive();return std::unexpected(nonce.error());}
            auto opened=rx_.open_to(destination,*nonce,wire.subspan(record_header_size));
            if (!opened) {
                fail_receive();return std::unexpected(opened.error()==crypto::Error::authentication_failed ? Error::authentication : Error::backend);
            }
            return *opened; // Zero authentic bytes are a record, never EOF.
        }
    };
    // Exactly one bounded wire frame. feed stops at the boundary and leaves
    // following input with the caller; wire views live until consume/destroy.
    class RecordDecoder {
        std::array<std::uint8_t,max_record_wire> bytes_{};
        std::size_t used_=0,needed_=record_header_size;
        bool failed_=false;
    public:
        auto ready() const noexcept -> bool {return !failed_ && used_==needed_;}
        auto wire() const noexcept -> std::span<std::uint8_t const> {return ready() ? std::span(bytes_).first(used_) : std::span<std::uint8_t const>{};}
        auto feed(std::span<std::uint8_t const> input) noexcept -> std::expected<std::size_t,Error> {
            if (failed_) return std::unexpected(Error::closed);
            if (ready()) return std::size_t{0};
            std::size_t consumed=0;
            while (!input.empty() && !ready()) {
                auto size=std::min(input.size(),needed_-used_);
                std::copy_n(input.begin(),size,bytes_.begin()+used_);used_+=size;consumed+=size;input=input.subspan(size);
                if (used_==record_header_size && needed_==record_header_size) {
                    auto length=record_detail::length(bytes_);
                    if (bytes_[0]!=4 || length<16 || length>max_record_ciphertext) {failed_=true;return std::unexpected(Error::framing);}
                    needed_=record_header_size+length;
                }
            }
            return consumed;
        }
        auto consume() noexcept -> std::expected<void,Error> {
            if (!ready()) return std::unexpected(failed_ ? Error::closed : Error::state);
            used_=0;needed_=record_header_size;return {};
        }
        auto eof() noexcept -> std::expected<void,Error> {
            if (failed_) return std::unexpected(Error::closed);
            failed_=true;
            if (used_) return std::unexpected(Error::framing);return {};
        }
    };
}
