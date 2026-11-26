export module quic.packet_protection;
import std;
import crypto;
import crypto.aead_context;
import quic.packet_keys;
import quic.varint;
import ngtcp2;

export namespace quic {
    // RFC9001 Retry integrity is public authentication, not peer identity.
    // The native writer and client verifier share this one fixed-key setup.
    inline auto initialize_retry_cipher(crypto::AeadContext& slot) noexcept -> int {
        constexpr std::array<std::uint8_t,16> key{0xbe,0x0c,0x69,0x0b,0x9f,0x66,0x57,0x5a,0x1d,0x76,0x6b,0x54,0xe3,0x68,0xc8,0x4e};
        return slot.reset(crypto::Aead::aes_128_gcm,key) ? 0 : ngtcp2::err_callback_failure;
    }
    // ngtcp2 owns references into these direct, non-moving slots. AEAD and HP
    // references retire independently: a key update keeps the original HP key.
    // The owning Connection must delete ngtcp2 before destroying this object.
    template<std::size_t Capacity=16>
    class PacketProtection {
        static_assert(Capacity>=4);
        using Native=ngtcp2::ngtcp2_conn;
        struct Slot { PacketKeys keys; bool reserved=false,aead=false,header=false; };
        std::array<Slot,Capacity> slots_{};
        crypto::AeadContext retry_;
        std::optional<PacketSuite> suite_;
        unsigned installed_=0;
        static auto abandon(Slot& slot) noexcept -> void { slot.keys.clear(); slot.reserved=slot.aead=slot.header=false; }
        auto acquire(PacketSuite suite,std::span<std::uint8_t const> secret) -> std::expected<Slot*,int> {
            for (auto& slot:slots_) {
                if (slot.reserved) continue;
                slot.reserved=true;
                try {
                    auto result=slot.keys.reset(suite,secret);
                    if (result) return &slot;
                    abandon(slot); return std::unexpected(ngtcp2::err_crypto);
                } catch (std::bad_alloc const&) { abandon(slot); return std::unexpected(ngtcp2::err_nomem); }
                catch (...) { abandon(slot); return std::unexpected(ngtcp2::err_callback_failure); }
            }
            return std::unexpected(ngtcp2::err_nomem);
        }
        static auto aead(Slot& slot) noexcept -> ngtcp2::ngtcp2_crypto_aead_ctx { return {&slot.keys.aead_context()}; }
        static auto header(Slot& slot) noexcept -> ngtcp2::ngtcp2_crypto_cipher_ctx { return {&slot.keys}; }
        static auto description(PacketSuite suite=PacketSuite::aes128_gcm_sha256) noexcept -> ngtcp2::ngtcp2_crypto_ctx {
            ngtcp2::ngtcp2_crypto_ctx result{};
            result.aead.max_overhead=16;
            // RFC9001 6.6: ChaCha has no confidentiality bound below the
            // packet-number limit, and a separate 2^36 integrity bound.
            auto chacha=suite==PacketSuite::chacha20_poly1305_sha256;
            result.max_encryption=chacha ? max_varint : std::uint64_t{1}<<23;
            result.max_decryption_failure=std::uint64_t{1}<<(chacha ? 36 : 52);
            return result;
        }
    public:
        PacketProtection()=default;
        PacketProtection(PacketProtection const&)=delete;
        auto operator=(PacketProtection const&) -> PacketProtection& = delete;
        PacketProtection(PacketProtection&&)=delete;
        auto operator=(PacketProtection&&) -> PacketProtection& = delete;
        auto active_slots() const noexcept -> std::size_t {
            return static_cast<std::size_t>(std::ranges::count_if(slots_,[](auto const& slot) { return slot.reserved; }));
        }
        auto application_keys_ready() const noexcept -> bool { return (installed_&12u)==12u; }
        // These C callbacks borrow the original backend member. In particular,
        // ngtcp2 already formed the complete nonce passed to seal/open.
        static auto encrypt(std::uint8_t* dest,ngtcp2::ngtcp2_crypto_aead const*,ngtcp2::ngtcp2_crypto_aead_ctx const* context,
            std::uint8_t const* input,std::size_t size,std::uint8_t const* nonce,std::size_t nonce_size,
            std::uint8_t const* aad,std::size_t aad_size) noexcept -> int {
            if (!context || !context->native_handle || size>std::numeric_limits<std::size_t>::max()-16) return ngtcp2::err_callback_failure;
            auto& cipher=*static_cast<crypto::AeadContext*>(context->native_handle);
            auto result=cipher.seal_to({dest,size+16},{nonce,nonce_size},{input,size},{aad,aad_size});
            return result ? 0 : ngtcp2::err_callback_failure;
        }
        static auto decrypt(std::uint8_t* dest,ngtcp2::ngtcp2_crypto_aead const*,ngtcp2::ngtcp2_crypto_aead_ctx const* context,
            std::uint8_t const* input,std::size_t size,std::uint8_t const* nonce,std::size_t nonce_size,
            std::uint8_t const* aad,std::size_t aad_size) noexcept -> int {
            if (!context || !context->native_handle || size<16) return ngtcp2::err_callback_failure;
            auto& cipher=*static_cast<crypto::AeadContext*>(context->native_handle);
            auto result=cipher.open_to({dest,size-16},{nonce,nonce_size},{input,size},{aad,aad_size});
            if (result) return 0;
            return result.error()==crypto::Error::authentication_failed ? ngtcp2::err_decrypt : ngtcp2::err_callback_failure;
        }
        static auto hp_mask(std::uint8_t* dest,ngtcp2::ngtcp2_crypto_cipher const*,ngtcp2::ngtcp2_crypto_cipher_ctx const* context,
            std::uint8_t const* sample) noexcept -> int {
            if (!context || !context->native_handle) return ngtcp2::err_callback_failure;
            auto& keys=*static_cast<PacketKeys*>(context->native_handle);
            return keys.mask_to(std::span<std::uint8_t,16>(dest,16),std::span<std::uint8_t const,16>(sample,16)) ? 0 : ngtcp2::err_callback_failure;
        }
        auto release_aead(ngtcp2::ngtcp2_crypto_aead_ctx& context) noexcept -> void {
            if (context.native_handle==&retry_) { retry_.clear(); context.native_handle=nullptr; return; }
            for (auto& slot:slots_) if (context.native_handle==&slot.keys.aead_context()) {
                // Retired traffic keys are erased immediately even while the
                // original header-protection schedule remains in use after KU.
                slot.keys.aead_context().clear(); slot.aead=false;
                if (!slot.header) abandon(slot);
                context.native_handle=nullptr; return;
            }
        }
        auto release_header(ngtcp2::ngtcp2_crypto_cipher_ctx& context) noexcept -> void {
            for (auto& slot:slots_) if (context.native_handle==&slot.keys) {
                slot.header=false; if (!slot.aead) abandon(slot); context.native_handle=nullptr; return;
            }
        }
        auto install_retry(Native& conn) noexcept -> int {
            if (retry_.valid()) return ngtcp2::err_invalid_argument;
            if(auto error=initialize_retry_cipher(retry_))return error;
            ngtcp2::ngtcp2_crypto_aead cipher{nullptr,16}; ngtcp2::ngtcp2_crypto_aead_ctx context{&retry_};
            ngtcp2::ngtcp2_conn_set_retry_aead(&conn,&cipher,&context); return 0;
        }
        auto install_initial(Native& conn,bool server,std::uint32_t version,std::span<std::uint8_t const> destination,bool negotiated=false) -> int {
            try {
                InitialSecrets secrets;
                if (!secrets.reset(version,destination)) return ngtcp2::err_crypto;
                auto rx=acquire(PacketSuite::aes128_gcm_sha256,server ? secrets.client() : secrets.server());
                if (!rx) return rx.error();
                auto tx=acquire(PacketSuite::aes128_gcm_sha256,server ? secrets.server() : secrets.client());
                if (!tx) { abandon(**rx); return tx.error(); }
                auto rx_aead=aead(**rx),tx_aead=aead(**tx); auto rx_hp=header(**rx),tx_hp=header(**tx);
                auto info=description(); ngtcp2::ngtcp2_conn_set_initial_crypto_ctx(&conn,&info);
                auto error=negotiated ? ngtcp2::ngtcp2_conn_install_vneg_initial_key(&conn,version,&rx_aead,(*rx)->keys.iv().data(),&rx_hp,&tx_aead,(*tx)->keys.iv().data(),&tx_hp,12) :
                    ngtcp2::ngtcp2_conn_install_initial_key(&conn,&rx_aead,(*rx)->keys.iv().data(),&rx_hp,&tx_aead,(*tx)->keys.iv().data(),&tx_hp,12);
                if (error) { abandon(**rx); abandon(**tx); return error; }
                (*rx)->aead=(*rx)->header=(*tx)->aead=(*tx)->header=true; return 0;
            } catch (std::bad_alloc const&) { return ngtcp2::err_nomem; }
            catch (...) { return ngtcp2::err_callback_failure; }
        }
        auto install_early_secret(Native& conn,PacketSuite suite,std::span<std::uint8_t const> secret) -> int {
            return install_client_early_secret(conn,suite,secret);
        }
        auto install_client_early_secret(Native& conn,PacketSuite suite,std::span<std::uint8_t const> secret) -> int {
            using namespace ngtcp2_abi;
            auto slot=acquire(suite,secret);
            if (!slot) return slot.error();
            auto info=description(suite);
            ngtcp2_conn_set_0rtt_crypto_ctx(&conn,&info);
            auto cipher=aead(**slot);
            auto hp=header(**slot);
            auto iv=(*slot)->keys.iv();
            auto error=ngtcp2_conn_install_0rtt_key(&conn,&cipher,iv.data(),iv.size(),&hp);
            if (error) {
                abandon(**slot);
                return error;
            }
            (*slot)->aead=(*slot)->header=true;
            return 0;
        }
        auto install_secret(Native& conn,ngtcp2::ngtcp2_encryption_level level,bool transmit,PacketSuite suite,
            std::span<std::uint8_t const> secret) -> int {
            using namespace ngtcp2;
            if (level!=NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE && level!=NGTCP2_ENCRYPTION_LEVEL_1RTT) return err_invalid_argument;
            auto bit=1u<<((level==NGTCP2_ENCRYPTION_LEVEL_1RTT ? 2u : 0u)+(transmit ? 1u : 0u));
            if (installed_&bit) return err_invalid_argument;
            if (suite_ && *suite_!=suite) return err_crypto;
            auto slot=acquire(suite,secret); if (!slot) return slot.error();
            if (!suite_) { auto info=description(suite); ngtcp2_conn_set_crypto_ctx(&conn,&info); suite_=suite; }
            auto cipher=aead(**slot); auto hp=header(**slot); auto iv=(*slot)->keys.iv();
            auto error=level==NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE ?
                (transmit ? ngtcp2_conn_install_tx_handshake_key(&conn,&cipher,iv.data(),iv.size(),&hp) : ngtcp2_conn_install_rx_handshake_key(&conn,&cipher,iv.data(),iv.size(),&hp)) :
                (transmit ? ngtcp2_conn_install_tx_key(&conn,secret.data(),secret.size(),&cipher,iv.data(),iv.size(),&hp) : ngtcp2_conn_install_rx_key(&conn,secret.data(),secret.size(),&cipher,iv.data(),iv.size(),&hp));
            if (error) { abandon(**slot); return error; }
            (*slot)->aead=(*slot)->header=true; installed_|=bit; return 0;
        }
        auto update(std::uint8_t* rx_secret,std::uint8_t* tx_secret,ngtcp2::ngtcp2_crypto_aead_ctx& rx_context,std::uint8_t* rx_iv,
            ngtcp2::ngtcp2_crypto_aead_ctx& tx_context,std::uint8_t* tx_iv,
            std::span<std::uint8_t const> current_rx,std::span<std::uint8_t const> current_tx) -> int {
            using namespace ngtcp2;
            if (!suite_ || !application_keys_ready() || current_rx.size()!=current_tx.size() || current_rx.size()!=(*suite_==PacketSuite::aes256_gcm_sha384 ? 48u : 32u)) return err_crypto;
            try {
                auto hash=*suite_==PacketSuite::aes256_gcm_sha384 ? crypto::Hash::sha384 : crypto::Hash::sha256;
                auto rx=packet_key_detail::expand(hash,current_rx,"quic ku",current_rx.size()); if (!rx) return err_crypto;
                packet_key_detail::EraseBytes erase_rx{*rx};
                auto tx=packet_key_detail::expand(hash,current_tx,"quic ku",current_tx.size()); if (!tx) return err_crypto;
                packet_key_detail::EraseBytes erase_tx{*tx};
                auto first=acquire(*suite_,*rx); if (!first) return first.error();
                auto second=acquire(*suite_,*tx); if (!second) { abandon(**first); return second.error(); }
                std::ranges::copy(*rx,rx_secret); std::ranges::copy(*tx,tx_secret);
                std::ranges::copy((*first)->keys.iv(),rx_iv); std::ranges::copy((*second)->keys.iv(),tx_iv);
                rx_context=aead(**first); tx_context=aead(**second); (*first)->aead=(*second)->aead=true;
                // No header references: ngtcp2 retains the original HP contexts.
                return 0;
            } catch (std::bad_alloc const&) { return err_nomem; }
            catch (...) { return err_callback_failure; }
        }
    };
}
