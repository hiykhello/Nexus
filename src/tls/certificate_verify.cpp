module;
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/nid.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
module nexus.tls.certificate_verify;
import std;

namespace nexus::tls {
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
        if (scheme!=0x0804 && scheme!=0x0403 && scheme!=0x0807) return std::unexpected(CertificateVerifyError::unsupported_scheme);
        if (!std::ranges::contains(offered,scheme)) return std::unexpected(CertificateVerifyError::unoffered_scheme);
        if (der.empty() || der.size()>1048576) return std::unexpected(CertificateVerifyError::invalid_certificate);
        auto cursor=der.data(); std::unique_ptr<X509,decltype(&X509_free)> cert(d2i_X509(nullptr,&cursor,static_cast<long>(der.size())),X509_free);
        if (!cert || cursor!=der.data()+der.size()) return std::unexpected(CertificateVerifyError::invalid_certificate);
        std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)> key(X509_get_pubkey(cert.get()),EVP_PKEY_free);
        if (!key) return std::unexpected(CertificateVerifyError::invalid_certificate);
        if ((scheme==0x0804 && EVP_PKEY_id(key.get())!=EVP_PKEY_RSA) ||
            (scheme==0x0403 && EVP_PKEY_id(key.get())!=EVP_PKEY_EC) ||
            (scheme==0x0807 && EVP_PKEY_id(key.get())!=EVP_PKEY_ED25519))
            return std::unexpected(CertificateVerifyError::invalid_certificate);
        if (scheme==0x0403) {
            auto ec=EVP_PKEY_get0_EC_KEY(key.get());
            auto group=ec ? EC_KEY_get0_group(ec) : nullptr;
            if (!group || EC_GROUP_get_curve_name(group)!=NID_X9_62_prime256v1)
                return std::unexpected(CertificateVerifyError::invalid_certificate);
        }
        std::unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(),EVP_MD_CTX_free); EVP_PKEY_CTX* pctx=nullptr;
        auto md=scheme==0x0807 ? nullptr : EVP_sha256();
        if (!ctx || EVP_DigestVerifyInit(ctx.get(),&pctx,md,nullptr,key.get())!=1 || !pctx)
            return std::unexpected(CertificateVerifyError::crypto_error);
        if (scheme==0x0804 && (EVP_PKEY_CTX_set_rsa_padding(pctx,RSA_PKCS1_PSS_PADDING)!=1 ||
            EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx,32)!=1 || EVP_PKEY_CTX_set_rsa_mgf1_md(pctx,EVP_sha256())!=1))
            return std::unexpected(CertificateVerifyError::crypto_error);
        constexpr std::string_view context="TLS 1.3, server CertificateVerify";
        std::vector<std::uint8_t> input(64,0x20); input.insert(input.end(),context.begin(),context.end()); input.push_back(0);
        input.insert(input.end(),transcript_hash.begin(),transcript_hash.end());
        if (EVP_DigestVerify(ctx.get(),message.data()+8,signature_length,input.data(),input.size())!=1)
            return std::unexpected(CertificateVerifyError::invalid_signature);
        return {};
    }
}
