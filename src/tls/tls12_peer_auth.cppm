module;
#include <openssl/x509.h>

export module tls.tls12_peer_auth;
import std;
import tls.signature;
import boringssl;
import tls.certificate_trust;

export namespace tls {
    [[nodiscard]] auto verify_tls12_key_signature(std::span<std::uint8_t const> leaf,
        std::uint16_t scheme,bool ecdsa,std::span<std::uint8_t const> signature,std::span<std::uint8_t const> input)
        -> std::expected<void, CertificateTrustError>;
}

module :private;

namespace tls {
    auto verify_tls12_key_signature(std::span<std::uint8_t const> leaf,
        std::uint16_t scheme,bool ecdsa,std::span<std::uint8_t const> signature,std::span<std::uint8_t const> input)
        -> std::expected<void, CertificateTrustError> {
        using namespace boringssl;
        auto parameters=signature_parameters(scheme);
        if (scheme==0x0401) parameters=SignatureParameters{EVP_sha256(),evp_pkey_rsa};
        if (scheme==0x0501) parameters=SignatureParameters{EVP_sha384(),evp_pkey_rsa};
        if (scheme==0x0601) parameters=SignatureParameters{EVP_sha512(),evp_pkey_rsa};
        if (!parameters || parameters->key_type!=(ecdsa ? evp_pkey_ec : evp_pkey_rsa))
            return std::unexpected(CertificateTrustError::verification_failed);
        auto cursor=leaf.data();
        std::unique_ptr<X509,decltype(&X509_free)> certificate(d2i_X509(nullptr,&cursor,static_cast<long>(leaf.size())),X509_free);
        if (!certificate || cursor!=leaf.data()+leaf.size() ||
            !(::X509_get_key_usage(certificate.get()) & X509v3_KU_DIGITAL_SIGNATURE))
            return std::unexpected(CertificateTrustError::verification_failed);
        std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)> key(X509_get_pubkey(certificate.get()),EVP_PKEY_free);
        if (!key || EVP_PKEY_id(key.get())!=parameters->key_type)
            return std::unexpected(CertificateTrustError::verification_failed);
        if (ecdsa) {
            // TLS 1.2 couples the hash to the signature scheme, but not to the certificate curve.
            auto* ec=EVP_PKEY_get0_EC_KEY(key.get());
            auto* group=ec ? EC_KEY_get0_group(ec) : nullptr;
            auto curve=group ? EC_GROUP_get_curve_name(group) : 0;
            if (curve!=nid_x9_62_prime256v1 && curve!=nid_secp384r1 && curve!=nid_secp521r1)
                return std::unexpected(CertificateTrustError::verification_failed);
        }
        std::unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(),EVP_MD_CTX_free);
        EVP_PKEY_CTX* signing=nullptr;
        auto digest=parameters->digest;
        if (!context || EVP_DigestVerifyInit(context.get(),&signing,digest,nullptr,key.get())!=1 || !signing)
            return std::unexpected(CertificateTrustError::crypto_error);
        if (parameters->pss_salt && (EVP_PKEY_CTX_set_rsa_padding(signing,rsa_pkcs1_pss_padding)!=1 ||
            EVP_PKEY_CTX_set_rsa_pss_saltlen(signing,parameters->pss_salt)!=1 ||
            EVP_PKEY_CTX_set_rsa_mgf1_md(signing,digest)!=1))
            return std::unexpected(CertificateTrustError::crypto_error);
        if (EVP_DigestVerify(context.get(),signature.data(),signature.size(),input.data(),input.size())!=1)
            return std::unexpected(CertificateTrustError::verification_failed);
        return {};
    }
}
