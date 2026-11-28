module tls.server_credential;
import boringssl;
import std;
import tls.signature;
using namespace boringssl;
namespace tls {
    ServerCredential::ServerCredential(EVP_PKEY* key, std::uint16_t scheme, Certificates&& certificates) noexcept
        : key_(key), scheme_(scheme), certificates_(std::move(certificates)) {}
    ServerCredential::~ServerCredential() { EVP_PKEY_free(key_); }
    ServerCredential::ServerCredential(ServerCredential&& other) noexcept
        : key_(std::exchange(other.key_,nullptr)), scheme_(other.scheme_), certificates_(std::move(other.certificates_)) {}
    auto ServerCredential::operator=(ServerCredential&& other) noexcept -> ServerCredential& {
        if (this!=&other) {
            EVP_PKEY_free(key_); key_=std::exchange(other.key_,nullptr);
            scheme_=other.scheme_; certificates_=std::move(other.certificates_);
        }
        return *this;
    }
    auto ServerCredential::generate_ed25519() -> std::expected<ServerCredential,ServerCredentialError> {
        std::unique_ptr<EVP_PKEY_CTX,decltype(&EVP_PKEY_CTX_free)> context(EVP_PKEY_CTX_new_id(evp_pkey_ed25519,nullptr),EVP_PKEY_CTX_free);
        if (!context || EVP_PKEY_keygen_init(context.get())!=1) return std::unexpected(ServerCredentialError::crypto_error);
        EVP_PKEY* raw=nullptr; auto generated=EVP_PKEY_keygen(context.get(),&raw);
        std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)> key(raw,EVP_PKEY_free);
        if (generated!=1 || !key) return std::unexpected(ServerCredentialError::crypto_error);
        std::unique_ptr<X509,decltype(&X509_free)> certificate(X509_new(),X509_free);
        if (!certificate || X509_set_version(certificate.get(),2)!=1 || ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()),1)!=1 ||
            !X509_gmtime_adj(X509_getm_notBefore(certificate.get()),-60) ||
            !X509_gmtime_adj(X509_getm_notAfter(certificate.get()),31536000) ||
            X509_set_pubkey(certificate.get(),key.get())!=1 ||
            X509_set_issuer_name(certificate.get(),X509_get_subject_name(certificate.get()))!=1 ||
            X509_sign(certificate.get(),key.get(),nullptr)<=0) return std::unexpected(ServerCredentialError::crypto_error);
        auto size=i2d_X509(certificate.get(),nullptr);
        if (size<=0 || static_cast<std::size_t>(size)>max_certificate_list_size-5) return std::unexpected(ServerCredentialError::invalid_certificate);
        crypto::Bytes encoded(size); auto cursor=encoded.data();
        if (i2d_X509(certificate.get(),&cursor)!=size) return std::unexpected(ServerCredentialError::crypto_error);
        return ServerCredential(key.release(),0x0807,Certificates{std::move(encoded),{}});
    }
    auto ServerCredential::generate_mldsa(std::uint16_t scheme) -> std::expected<ServerCredential,ServerCredentialError> {
        int key_id=scheme==0x0904 ? evp_pkey_ml_dsa_44 : scheme==0x0905 ? evp_pkey_ml_dsa_65 : scheme==0x0906 ? evp_pkey_ml_dsa_87 : 0;
        if (!key_id) return std::unexpected(ServerCredentialError::unsupported_key);
        std::unique_ptr<EVP_PKEY_CTX,decltype(&EVP_PKEY_CTX_free)> context(EVP_PKEY_CTX_new_id(key_id,nullptr),EVP_PKEY_CTX_free);
        if (!context || EVP_PKEY_keygen_init(context.get())!=1) return std::unexpected(ServerCredentialError::crypto_error);
        EVP_PKEY* raw=nullptr; auto generated=EVP_PKEY_keygen(context.get(),&raw);
        std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)> key(raw,EVP_PKEY_free);
        if (generated!=1 || !key) return std::unexpected(ServerCredentialError::crypto_error);
        std::unique_ptr<X509,decltype(&X509_free)> certificate(X509_new(),X509_free);
        if (!certificate || X509_set_version(certificate.get(),2)!=1 || ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()),1)!=1 ||
            !X509_gmtime_adj(X509_getm_notBefore(certificate.get()),-60) ||
            !X509_gmtime_adj(X509_getm_notAfter(certificate.get()),31536000) ||
            X509_set_pubkey(certificate.get(),key.get())!=1 ||
            X509_set_issuer_name(certificate.get(),X509_get_subject_name(certificate.get()))!=1 ||
            X509_sign(certificate.get(),key.get(),nullptr)<=0) return std::unexpected(ServerCredentialError::crypto_error);
        auto size=i2d_X509(certificate.get(),nullptr);
        if (size<=0 || static_cast<std::size_t>(size)>max_certificate_list_size-5) return std::unexpected(ServerCredentialError::invalid_certificate);
        crypto::Bytes encoded(size); auto cursor=encoded.data();
        if (i2d_X509(certificate.get(),&cursor)!=size) return std::unexpected(ServerCredentialError::crypto_error);
        return ServerCredential(key.release(),scheme,Certificates{std::move(encoded),{}});
    }
    auto ServerCredential::with_certificate(std::span<std::uint8_t const> certificate) const -> std::expected<ServerCredential,ServerCredentialError> {
        if (!key_) return std::unexpected(ServerCredentialError::invalid_state);
        if (certificate.empty() || certificate.size()>max_certificate_list_size-5) return std::unexpected(ServerCredentialError::invalid_certificate);
        auto cursor=certificate.data();
        std::unique_ptr<X509,decltype(&X509_free)> cert(d2i_X509(nullptr,&cursor,static_cast<long>(certificate.size())),X509_free);
        if (!cert || cursor!=certificate.data()+certificate.size()) return std::unexpected(ServerCredentialError::invalid_certificate);
        if (X509_check_private_key(cert.get(),key_)!=1) return std::unexpected(ServerCredentialError::key_mismatch);
        Certificates certificates{crypto::Bytes(certificate.begin(),certificate.end()),{}};
        if (EVP_PKEY_up_ref(key_)!=1) return std::unexpected(ServerCredentialError::crypto_error);
        return ServerCredential(key_,scheme_,std::move(certificates));
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
        if (EVP_PKEY_id(key.get())==evp_pkey_rsa && EVP_PKEY_bits(key.get())>=2048) scheme=0x0804;
        else if (EVP_PKEY_id(key.get())==evp_pkey_ed25519) scheme=0x0807;
        else if (EVP_PKEY_id(key.get())==evp_pkey_ml_dsa_44) scheme=0x0904;
        else if (EVP_PKEY_id(key.get())==evp_pkey_ml_dsa_65) scheme=0x0905;
        else if (EVP_PKEY_id(key.get())==evp_pkey_ml_dsa_87) scheme=0x0906;
        else if (EVP_PKEY_id(key.get())==evp_pkey_ec) {
            auto ec=EVP_PKEY_get0_EC_KEY(key.get()); auto group=ec ? EC_KEY_get0_group(ec) : nullptr;
            if (group) {
                auto curve=EC_GROUP_get_curve_name(group);
                if (curve==nid_x9_62_prime256v1) scheme=0x0403;
                else if (curve==nid_secp384r1) scheme=0x0503;
                else if (curve==nid_secp521r1) scheme=0x0603;
            }
        }
        if (!scheme) return std::unexpected(ServerCredentialError::unsupported_key);
        crypto::Bytes encoded(certificate.begin(),certificate.end());
        Certificates certificates{std::move(encoded),{}};
        return ServerCredential(key.release(),scheme,std::move(certificates));
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
        if (result) result->certificates_.chain=std::move(chain);
        return result;
    }
    auto ServerCredential::clone() const -> std::expected<ServerCredential,ServerCredentialError> {
        if (!key_) return std::unexpected(ServerCredentialError::invalid_state);
        Certificates copy=certificates_;
        if (EVP_PKEY_up_ref(key_)!=1) return std::unexpected(ServerCredentialError::crypto_error);
        return ServerCredential(key_,scheme_,std::move(copy));
    }
    auto ServerCredential::scheme() const noexcept -> std::optional<std::uint16_t> {
        if (!key_) return {}; return scheme_;
    }
    auto ServerCredential::signature_schemes() const noexcept -> std::span<std::uint16_t const> {
        if (!key_) return {};
        static constexpr std::array<std::uint16_t,3> rsa{0x0804,0x0805,0x0806};
        if (scheme_==0x0804) return rsa;
        return {&scheme_,1};
    }
    auto ServerCredential::max_signature_size() const noexcept -> std::optional<std::size_t> {
        if (!key_) return {};
        auto size=EVP_PKEY_size(key_);
        if (size<=0 || size>65535) return {};
        return static_cast<std::size_t>(size);
    }
    auto ServerCredential::certificate() const noexcept -> std::span<std::uint8_t const> {
        return key_ ? std::span<std::uint8_t const>{certificates_.leaf} : std::span<std::uint8_t const>{};
    }
    auto ServerCredential::chain() const noexcept -> std::span<crypto::Bytes const> { return key_ ? std::span<crypto::Bytes const>{certificates_.chain} : std::span<crypto::Bytes const>{}; }
    auto ServerCredential::sign(crypto::Hash hash, std::span<std::uint8_t const> transcript_hash) const
        -> std::expected<crypto::Bytes,ServerCredentialError> {
        return sign(scheme_,hash,transcript_hash);
    }
    auto ServerCredential::sign(std::uint16_t scheme,crypto::Hash hash,std::span<std::uint8_t const> transcript_hash) const
        -> std::expected<crypto::Bytes,ServerCredentialError> {
        if (!key_) return std::unexpected(ServerCredentialError::invalid_state);
        auto parameters=signature_parameters(scheme);
        if (!parameters || !signature_key_matches(*parameters,key_)) return std::unexpected(ServerCredentialError::unsupported_key);
        auto length=hash==crypto::Hash::sha256 ? 32u : hash==crypto::Hash::sha384 ? 48u : 0u;
        if (!length || transcript_hash.size()!=length) return std::unexpected(ServerCredentialError::invalid_transcript);
        std::unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(),EVP_MD_CTX_free); EVP_PKEY_CTX* pctx=nullptr;
        auto md=parameters->digest;
        if (!ctx || EVP_DigestSignInit(ctx.get(),&pctx,md,nullptr,key_)!=1 || !pctx)
            return std::unexpected(ServerCredentialError::crypto_error);
        if (parameters->pss_salt && (EVP_PKEY_CTX_set_rsa_padding(pctx,rsa_pkcs1_pss_padding)!=1 ||
            EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx,parameters->pss_salt)!=1 || EVP_PKEY_CTX_set_rsa_mgf1_md(pctx,md)!=1))
            return std::unexpected(ServerCredentialError::crypto_error);
        constexpr std::string_view context="TLS 1.3, server CertificateVerify";
        std::array<std::uint8_t,64+context.size()+1+48> input{};
        std::fill_n(input.begin(),64,0x20);
        std::ranges::copy(context,input.begin()+64);
        std::ranges::copy(transcript_hash,input.begin()+64+context.size()+1);
        auto input_size=64+context.size()+1+transcript_hash.size();
        std::size_t size=0;
        if (EVP_DigestSign(ctx.get(),nullptr,&size,input.data(),input_size)!=1 || size==0 || size>65535)
            return std::unexpected(ServerCredentialError::crypto_error);
        crypto::Bytes message(8+size);
        auto capacity=size;
        if (EVP_DigestSign(ctx.get(),message.data()+8,&size,input.data(),input_size)!=1 || size==0 || size>capacity)
            return std::unexpected(ServerCredentialError::crypto_error);
        message.resize(8+size); auto body_size=4+size;
        message[0]=15; message[1]=static_cast<std::uint8_t>(body_size>>16); message[2]=static_cast<std::uint8_t>(body_size>>8); message[3]=static_cast<std::uint8_t>(body_size);
        message[4]=static_cast<std::uint8_t>(scheme>>8); message[5]=static_cast<std::uint8_t>(scheme); message[6]=static_cast<std::uint8_t>(size>>8); message[7]=static_cast<std::uint8_t>(size);
        return message;
    }

    auto AtomicServerCredential::update(ServerCredential credential) -> std::uint64_t {
        auto next = std::make_shared<ServerCredential const>(std::move(credential));
        std::lock_guard lock(mutex_);
        current_ = std::move(next);
        return generation_.fetch_add(1, std::memory_order_acq_rel) + 1;
    }

    auto AtomicServerCredential::update_pem(std::string_view cert_pem, std::string_view key_pem)
        -> std::expected<std::uint64_t, ServerCredentialError> {
        auto parsed = ServerCredential::create_file_contents(
            {reinterpret_cast<std::uint8_t const*>(cert_pem.data()), cert_pem.size()},
            {reinterpret_cast<std::uint8_t const*>(key_pem.data()), key_pem.size()});
        if (!parsed) return std::unexpected(parsed.error());
        return update(std::move(*parsed));
    }

    auto AtomicServerCredential::clone_current() const -> std::expected<ServerCredential, ServerCredentialError> {
        std::shared_ptr<ServerCredential const> snap;
        {
            std::lock_guard lock(mutex_);
            snap = current_;
        }
        if (!snap) return std::unexpected(ServerCredentialError::invalid_state);
        return snap->clone();
    }
}
