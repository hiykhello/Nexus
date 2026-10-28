module;
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/nid.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/mem.h>
module nexus.tls.server_credential;
import std;
namespace nexus::tls {
    ServerCredential::ServerCredential(EVP_PKEY* key, std::uint16_t scheme, crypto::Bytes certificate) noexcept
        : key_(key), scheme_(scheme), certificate_(std::move(certificate)) {}
    ServerCredential::~ServerCredential() { EVP_PKEY_free(key_); }
    ServerCredential::ServerCredential(ServerCredential&& other) noexcept
        : key_(std::exchange(other.key_,nullptr)), scheme_(other.scheme_), certificate_(std::move(other.certificate_)), chain_(std::move(other.chain_)) {}
    auto ServerCredential::operator=(ServerCredential&& other) noexcept -> ServerCredential& {
        if (this!=&other) {
            EVP_PKEY_free(key_); key_=std::exchange(other.key_,nullptr);
            scheme_=other.scheme_; certificate_=std::move(other.certificate_); chain_=std::move(other.chain_);
        }
        return *this;
    }
    auto ServerCredential::create(std::span<std::uint8_t const> certificate, std::span<std::uint8_t const> private_key)
        -> std::expected<ServerCredential,ServerCredentialError> {
        if (certificate.empty() || certificate.size()>max_certificate_list_size-5) return std::unexpected(ServerCredentialError::invalid_certificate);
        if (private_key.empty() || private_key.size()>1048576) return std::unexpected(ServerCredentialError::invalid_private_key);
        auto cursor=certificate.data();
        std::unique_ptr<X509,decltype(&X509_free)> cert(d2i_X509(nullptr,&cursor,static_cast<long>(certificate.size())),X509_free);
        if (!cert || cursor!=certificate.data()+certificate.size()) return std::unexpected(ServerCredentialError::invalid_certificate);
        cursor=private_key.data();
        std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)> key(d2i_AutoPrivateKey(nullptr,&cursor,static_cast<long>(private_key.size())),EVP_PKEY_free);
        if (!key || cursor!=private_key.data()+private_key.size()) return std::unexpected(ServerCredentialError::invalid_private_key);
        if (X509_check_private_key(cert.get(),key.get())!=1) return std::unexpected(ServerCredentialError::key_mismatch);
        std::uint16_t scheme=0;
        if (EVP_PKEY_id(key.get())==EVP_PKEY_RSA && EVP_PKEY_bits(key.get())>=2048) scheme=0x0804;
        else if (EVP_PKEY_id(key.get())==EVP_PKEY_ED25519) scheme=0x0807;
        else if (EVP_PKEY_id(key.get())==EVP_PKEY_EC) {
            auto ec=EVP_PKEY_get0_EC_KEY(key.get()); auto group=ec ? EC_KEY_get0_group(ec) : nullptr;
            if (group && EC_GROUP_get_curve_name(group)==NID_X9_62_prime256v1) scheme=0x0403;
        }
        if (!scheme) return std::unexpected(ServerCredentialError::unsupported_key);
        crypto::Bytes encoded(certificate.begin(),certificate.end());
        return ServerCredential(key.release(),scheme,std::move(encoded));
    }
    auto ServerCredential::create_file_contents(std::span<std::uint8_t const> certificate,
            std::span<std::uint8_t const> private_key) -> std::expected<ServerCredential,ServerCredentialError> {
        constexpr std::size_t limit=1048576;
        if (certificate.empty() || certificate.size()>limit) return std::unexpected(ServerCredentialError::invalid_certificate);
        if (private_key.empty() || private_key.size()>limit) return std::unexpected(ServerCredentialError::invalid_private_key);
        auto text=[](std::span<std::uint8_t const> data) { return std::string_view(reinterpret_cast<char const*>(data.data()),data.size()); };
        auto trim=[](std::string_view value) {
            auto whitespace=[](char c) { return c==' ' || c=='\t' || c=='\r' || c=='\n'; };
            while (!value.empty() && whitespace(value.front())) value.remove_prefix(1);
            while (!value.empty() && whitespace(value.back())) value.remove_suffix(1);
            return value;
        };
        auto cert_text=trim(text(certificate)), key_text=trim(text(private_key));
        crypto::Bytes cert_der, key_der;
        struct Wipe { crypto::Bytes& bytes; ~Wipe() { if (!bytes.empty()) OPENSSL_cleanse(bytes.data(),bytes.size()); } } wipe{key_der};
        std::vector<crypto::Bytes> chain;
        if (cert_text.starts_with("-----BEGIN CERTIFICATE-----")) {
            constexpr std::string_view begin="-----BEGIN CERTIFICATE-----", end="-----END CERTIFICATE-----";
            while (!cert_text.empty()) {
                cert_text=trim(cert_text);
                if (!cert_text.starts_with(begin) || chain.size()>=16) return std::unexpected(ServerCredentialError::invalid_certificate);
                auto at=cert_text.find(end,begin.size());
                if (at==std::string_view::npos) return std::unexpected(ServerCredentialError::invalid_certificate);
                auto block=cert_text.substr(0,at+end.size());
                std::unique_ptr<BIO,decltype(&BIO_free)> bio(BIO_new_mem_buf(block.data(),static_cast<int>(block.size())),BIO_free);
                std::unique_ptr<X509,decltype(&X509_free)> cert(bio ? PEM_read_bio_X509(bio.get(),nullptr,nullptr,nullptr) : nullptr,X509_free);
                if (!cert || BIO_ctrl_pending(bio.get())!=0) return std::unexpected(ServerCredentialError::invalid_certificate);
                auto size=i2d_X509(cert.get(),nullptr);
                if (size<=0 || static_cast<std::size_t>(size)>limit) return std::unexpected(ServerCredentialError::invalid_certificate);
                crypto::Bytes der(size); auto cursor=der.data();
                if (i2d_X509(cert.get(),&cursor)!=size || std::ranges::find(chain,der)!=chain.end()) return std::unexpected(ServerCredentialError::invalid_certificate);
                chain.push_back(std::move(der)); cert_text.remove_prefix(block.size());
            }
            cert_der=std::move(chain.front()); chain.erase(chain.begin()); certificate=cert_der;
        }
        if (key_text.starts_with("-----BEGIN ")) {
            constexpr std::array labels{std::string_view{"PRIVATE KEY"},std::string_view{"RSA PRIVATE KEY"},std::string_view{"EC PRIVATE KEY"}};
            bool valid=false;
            for (auto label:labels) {
                auto begin=std::string("-----BEGIN ")+std::string(label)+"-----";
                auto end=std::string("-----END ")+std::string(label)+"-----";
                if (key_text.starts_with(begin) && key_text.ends_with(end) && key_text.find(end)==key_text.size()-end.size()) { valid=true; break; }
            }
            if (!valid) return std::unexpected(ServerCredentialError::invalid_private_key);
            std::unique_ptr<BIO,decltype(&BIO_free)> bio(BIO_new_mem_buf(key_text.data(),static_cast<int>(key_text.size())),BIO_free);
            auto no_password=[](char*,int,int,void*) -> int { return 0; };
            std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)> key(bio ? PEM_read_bio_PrivateKey(bio.get(),nullptr,no_password,nullptr) : nullptr,EVP_PKEY_free);
            if (!key || BIO_ctrl_pending(bio.get())!=0) return std::unexpected(ServerCredentialError::invalid_private_key);
            std::unique_ptr<PKCS8_PRIV_KEY_INFO,decltype(&PKCS8_PRIV_KEY_INFO_free)> pkcs8(EVP_PKEY2PKCS8(key.get()),PKCS8_PRIV_KEY_INFO_free);
            if (!pkcs8) return std::unexpected(ServerCredentialError::invalid_private_key);
            auto size=i2d_PKCS8_PRIV_KEY_INFO(pkcs8.get(),nullptr);
            if (size<=0 || static_cast<std::size_t>(size)>limit) return std::unexpected(ServerCredentialError::invalid_private_key);
            key_der.resize(size); auto cursor=key_der.data();
            if (i2d_PKCS8_PRIV_KEY_INFO(pkcs8.get(),&cursor)!=size) return std::unexpected(ServerCredentialError::invalid_private_key);
            private_key=key_der;
        }
        std::size_t list_size=certificate.size()+5;
        if (list_size>max_certificate_list_size) return std::unexpected(ServerCredentialError::invalid_certificate);
        for (auto const& item:chain) {
            if (item.empty() || item.size()>max_certificate_list_size-5 || list_size>max_certificate_list_size-item.size()-5)
                return std::unexpected(ServerCredentialError::invalid_certificate);
            list_size+=item.size()+5;
        }
        auto result=create(certificate,private_key);
        if (result) result->chain_=std::move(chain);
        return result;
    }
    auto ServerCredential::clone() const -> std::expected<ServerCredential,ServerCredentialError> {
        if (!key_) return std::unexpected(ServerCredentialError::invalid_state);
        auto certificate=certificate_; auto chain=chain_;
        if (EVP_PKEY_up_ref(key_)!=1) return std::unexpected(ServerCredentialError::crypto_error);
        ServerCredential result(key_,scheme_,std::move(certificate)); result.chain_=std::move(chain); return result;
    }
    auto ServerCredential::scheme() const noexcept -> std::optional<std::uint16_t> {
        if (!key_) return {}; return scheme_;
    }
    auto ServerCredential::certificate() const noexcept -> std::span<std::uint8_t const> {
        return key_ ? std::span<std::uint8_t const>{certificate_} : std::span<std::uint8_t const>{};
    }
    auto ServerCredential::chain() const noexcept -> std::span<crypto::Bytes const> { return key_ ? std::span<crypto::Bytes const>{chain_} : std::span<crypto::Bytes const>{}; }
    auto ServerCredential::sign(crypto::Hash hash, std::span<std::uint8_t const> transcript_hash) const
        -> std::expected<crypto::Bytes,ServerCredentialError> {
        if (!key_) return std::unexpected(ServerCredentialError::invalid_state);
        auto length=hash==crypto::Hash::sha256 ? 32u : hash==crypto::Hash::sha384 ? 48u : 0u;
        if (!length || transcript_hash.size()!=length) return std::unexpected(ServerCredentialError::invalid_transcript);
        std::unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(),EVP_MD_CTX_free); EVP_PKEY_CTX* pctx=nullptr;
        auto md=scheme_==0x0807 ? nullptr : EVP_sha256();
        if (!ctx || EVP_DigestSignInit(ctx.get(),&pctx,md,nullptr,key_)!=1 || !pctx)
            return std::unexpected(ServerCredentialError::crypto_error);
        if (scheme_==0x0804 && (EVP_PKEY_CTX_set_rsa_padding(pctx,RSA_PKCS1_PSS_PADDING)!=1 ||
            EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx,32)!=1 || EVP_PKEY_CTX_set_rsa_mgf1_md(pctx,EVP_sha256())!=1))
            return std::unexpected(ServerCredentialError::crypto_error);
        constexpr std::string_view context="TLS 1.3, server CertificateVerify";
        crypto::Bytes input(64,0x20); input.insert(input.end(),context.begin(),context.end()); input.push_back(0);
        input.insert(input.end(),transcript_hash.begin(),transcript_hash.end());
        std::size_t size=0;
        if (EVP_DigestSign(ctx.get(),nullptr,&size,input.data(),input.size())!=1 || size==0 || size>65535)
            return std::unexpected(ServerCredentialError::crypto_error);
        crypto::Bytes signature(size);
        if (EVP_DigestSign(ctx.get(),signature.data(),&size,input.data(),input.size())!=1 || size==0 || size>signature.size())
            return std::unexpected(ServerCredentialError::crypto_error);
        signature.resize(size); auto body_size=4+size;
        crypto::Bytes message{15,static_cast<std::uint8_t>(body_size>>16),static_cast<std::uint8_t>(body_size>>8),static_cast<std::uint8_t>(body_size),
            static_cast<std::uint8_t>(scheme_>>8),static_cast<std::uint8_t>(scheme_),static_cast<std::uint8_t>(size>>8),static_cast<std::uint8_t>(size)};
        message.insert(message.end(),signature.begin(),signature.end()); return message;
    }
}
