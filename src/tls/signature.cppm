export module tls.signature;
import std;
import boringssl;

export namespace tls {
    struct SignatureParameters {
        boringssl::EVP_MD const* digest;
        int key_type,curve=0,pss_salt=0;
    };
    // TLS1.3 CertificateVerify schemes only. Legacy PKCS#1/SHA1 identifiers
    // never become usable for handshake signatures by appearing in a profile.
    [[nodiscard]] inline auto signature_parameters(std::uint16_t scheme) noexcept -> std::optional<SignatureParameters> {
        using namespace boringssl;
        switch (scheme) {
        case 0x0804:return SignatureParameters{EVP_sha256(),evp_pkey_rsa,0,32};
        case 0x0805:return SignatureParameters{EVP_sha384(),evp_pkey_rsa,0,48};
        case 0x0806:return SignatureParameters{EVP_sha512(),evp_pkey_rsa,0,64};
        case 0x0403:return SignatureParameters{EVP_sha256(),evp_pkey_ec,nid_x9_62_prime256v1};
        case 0x0503:return SignatureParameters{EVP_sha384(),evp_pkey_ec,nid_secp384r1};
        case 0x0603:return SignatureParameters{EVP_sha512(),evp_pkey_ec,nid_secp521r1};
        case 0x0807:return SignatureParameters{nullptr,evp_pkey_ed25519};
        case 0x0904:return SignatureParameters{nullptr,evp_pkey_ml_dsa_44};
        case 0x0905:return SignatureParameters{nullptr,evp_pkey_ml_dsa_65};
        case 0x0906:return SignatureParameters{nullptr,evp_pkey_ml_dsa_87};
        default:return {};
        }
    }
    [[nodiscard]] inline auto signature_key_matches(SignatureParameters const& scheme,boringssl::EVP_PKEY const* key) noexcept -> bool {
        using namespace boringssl;
        if (!key || EVP_PKEY_id(key)!=scheme.key_type) return false;
        if (!scheme.curve) return true;
        auto* ec=EVP_PKEY_get0_EC_KEY(key);
        auto* group=ec ? EC_KEY_get0_group(ec) : nullptr;
        return group && EC_GROUP_get_curve_name(group)==scheme.curve;
    }
}
