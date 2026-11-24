module tls.certificate_verify;
import boringssl;
import tls.signature;
import crypto.backend_errors;
import std;
using namespace boringssl;

namespace tls {
    auto ed25519_certificate_fields(std::span<std::uint8_t const> der) -> std::expected<Ed25519CertificateFields,CertificateVerifyError> {
        if (der.empty() || der.size()>1048576) return std::unexpected(CertificateVerifyError::invalid_certificate);
        crypto::BackendErrors backend_errors;
        auto cursor=der.data(); std::unique_ptr<X509,decltype(&X509_free)> cert(d2i_X509(nullptr,&cursor,static_cast<long>(der.size())),X509_free);
        if (backend_errors.allocation_failed()) return std::unexpected(CertificateVerifyError::crypto_error);
        if (!cert || cursor!=der.data()+der.size()) return std::unexpected(CertificateVerifyError::invalid_certificate);
        std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)> key(X509_get_pubkey(cert.get()),EVP_PKEY_free);
        if (!key || EVP_PKEY_id(key.get())!=evp_pkey_ed25519) return std::unexpected(backend_errors.allocation_failed() ? CertificateVerifyError::crypto_error : CertificateVerifyError::invalid_certificate);
        Ed25519CertificateFields result{}; std::size_t size=result.public_key.size();
        if (EVP_PKEY_get_raw_public_key(key.get(),result.public_key.data(),&size)!=1 || size!=result.public_key.size()) return std::unexpected(CertificateVerifyError::invalid_certificate);
        ASN1_BIT_STRING const* sig=nullptr; X509_get0_signature(&sig,nullptr,cert.get());
        if (!sig || ASN1_BIT_STRING_unused_bits(sig)!=0 || ASN1_STRING_length(sig)!=64) return std::unexpected(CertificateVerifyError::invalid_certificate);
        std::copy_n(ASN1_STRING_get0_data(sig),result.signature.size(),result.signature.begin()); return result;
    }
    auto verify_server_certificate_signature(std::span<std::uint8_t const> der, crypto::Hash hash,
        std::span<std::uint8_t const> transcript_hash, std::span<std::uint16_t const> offered,
        std::span<std::uint8_t const> message) -> std::expected<void,CertificateVerifyError> {
        auto digest_size=hash==crypto::Hash::sha256 ? 32u : hash==crypto::Hash::sha384 ? 48u : 0u;
        if (!digest_size || transcript_hash.size()!=digest_size) return std::unexpected(CertificateVerifyError::invalid_transcript);
        if (message.size()<8 || message[0]!=15) return std::unexpected(CertificateVerifyError::invalid_message);
        auto length=(std::size_t{message[1]}<<16)|(std::size_t{message[2]}<<8)|message[3];
        auto signature_length=(std::size_t{message[6]}<<8)|message[7];
        if (length!=message.size()-4 || signature_length==0 || signature_length!=message.size()-8) return std::unexpected(CertificateVerifyError::invalid_message);
        auto scheme=static_cast<std::uint16_t>((std::uint16_t{message[4]}<<8)|message[5]);
        auto parameters=signature_parameters(scheme);
        if (!parameters) return std::unexpected(CertificateVerifyError::unsupported_scheme);
        if (!std::ranges::contains(offered,scheme)) return std::unexpected(CertificateVerifyError::unoffered_scheme);
        if (der.empty() || der.size()>1048576) return std::unexpected(CertificateVerifyError::invalid_certificate);
        crypto::BackendErrors backend_errors;
        auto cursor=der.data(); std::unique_ptr<X509,decltype(&X509_free)> cert(d2i_X509(nullptr,&cursor,static_cast<long>(der.size())),X509_free);
        if (backend_errors.allocation_failed()) return std::unexpected(CertificateVerifyError::crypto_error);
        if (!cert || cursor!=der.data()+der.size()) return std::unexpected(CertificateVerifyError::invalid_certificate);
        std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)> key(X509_get_pubkey(cert.get()),EVP_PKEY_free);
        if (!key) return std::unexpected(backend_errors.allocation_failed() ? CertificateVerifyError::crypto_error : CertificateVerifyError::invalid_certificate);
        if (!signature_key_matches(*parameters,key.get())) return std::unexpected(CertificateVerifyError::invalid_certificate);
        std::unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(),EVP_MD_CTX_free); EVP_PKEY_CTX* pctx=nullptr;
        auto md=parameters->digest;
        if (!ctx || EVP_DigestVerifyInit(ctx.get(),&pctx,md,nullptr,key.get())!=1 || !pctx)
            return std::unexpected(CertificateVerifyError::crypto_error);
        if (parameters->pss_salt && (EVP_PKEY_CTX_set_rsa_padding(pctx,rsa_pkcs1_pss_padding)!=1 ||
            EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx,parameters->pss_salt)!=1 || EVP_PKEY_CTX_set_rsa_mgf1_md(pctx,md)!=1))
            return std::unexpected(CertificateVerifyError::crypto_error);
        constexpr std::string_view context="TLS 1.3, server CertificateVerify";
        std::vector<std::uint8_t> input(64,0x20); input.insert(input.end(),context.begin(),context.end()); input.push_back(0);
        input.insert(input.end(),transcript_hash.begin(),transcript_hash.end());
        if (EVP_DigestVerify(ctx.get(),message.data()+8,signature_length,input.data(),input.size())!=1)
            return std::unexpected(backend_errors.allocation_failed() ? CertificateVerifyError::crypto_error : CertificateVerifyError::invalid_signature);
        return {};
    }
}
