module;
#include <openssl/aead.h>
#include <openssl/aes.h>
#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/bytestring.h>
#include <openssl/blake2.h>
#include <openssl/crypto.h>
#include <openssl/curve25519.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
#include <openssl/mem.h>
#include <openssl/mlkem.h>
#include <openssl/nid.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/stack.h>
#include <openssl/x509.h>

// Exact C declarations checked by tests/boringssl_poly1305_boundary.py against
// the pinned public header, without adding another textual include boundary.
namespace boringssl_poly1305_abi {
    using State=uint8_t[512];
    extern "C" void CRYPTO_poly1305_init(State*,uint8_t const[32]);
    extern "C" void CRYPTO_poly1305_update(State*,uint8_t const*,size_t);
    extern "C" void CRYPTO_poly1305_finish(State*,uint8_t[16]);
}

// Exact C ABI checked against the pinned chacha.h by the boundary probe.
namespace boringssl_chacha_abi {
    extern "C" void CRYPTO_chacha_20(uint8_t*,uint8_t const*,size_t,uint8_t const[32],uint8_t const[12],uint32_t);
}

// Exact C ABI checked against the pinned ecdh.h by the boundary probe.
namespace boringssl_ecdh_abi {
    extern "C" int ECDH_compute_key(void*,size_t,EC_POINT const*,EC_KEY const*,void*(*)(void const*,size_t,void*,size_t*));
}

export module boringssl;
export namespace boringssl {
    using ::BLAKE2B_CTX;
    using ::BLAKE2B256_Init;
    using ::BLAKE2B256_Update;
    using ::BLAKE2B256_Final;
    using boringssl_chacha_abi::CRYPTO_chacha_20;
    using ::X25519;
    using ::AES_KEY;
    using ::AES_decrypt;
    using ::AES_encrypt;
    using ::AES_set_decrypt_key;
    using ::AES_set_encrypt_key;
    using ::ASN1_INTEGER_set;
    using ::ASN1_BIT_STRING;
    using ::ASN1_BIT_STRING_unused_bits;
    using ::ASN1_STRING_get0_data;
    using ::ASN1_STRING_length;
    using ::BIGNUM;
    using ::BN_bin2bn;
    using ::BN_bn2bin;
    using ::BN_free;
    using ::BN_num_bytes;
    using ::BIO;
    using ::BIO_ctrl_pending;
    using ::BIO_free;
    using ::BIO_new_mem_buf;
    using ::CBB;
    using ::CBB_cleanup;
    using ::CBB_data;
    using ::CBB_init;
    using ::CBB_len;
    using ::CBS;
    using ::CBS_init;
    using ::CRYPTO_memcmp;
    using ::ED25519_keypair;
    using ::ED25519_keypair_from_seed;
    using ::ED25519_sign;
    using ::ED25519_verify;
    using poly1305_state=::boringssl_poly1305_abi::State;
    using ::boringssl_poly1305_abi::CRYPTO_poly1305_init;
    using ::boringssl_poly1305_abi::CRYPTO_poly1305_update;
    using ::boringssl_poly1305_abi::CRYPTO_poly1305_finish;
    using ::ERR_clear_error;
    using ::ERR_get_error;
    inline auto error_is_allocation_failure(uint32_t error) noexcept -> bool { return ERR_GET_REASON(error)==ERR_R_MALLOC_FAILURE || ERR_equals(error,ERR_LIB_BN,BN_R_TOO_MANY_TEMPORARY_VARIABLES); }
    using ::ERR_peek_last_error;
    inline auto is_bad_decrypt(uint32_t error) noexcept -> bool { return ERR_equals(error,ERR_LIB_CIPHER,CIPHER_R_BAD_DECRYPT); }
    using ::EC_KEY;
    using ::EC_POINT;
    using ::EC_KEY_new_by_curve_name;
    using ::EC_KEY_free;
    using ::EC_KEY_generate_key;
    using ::EC_KEY_get0_private_key;
    using ::EC_KEY_get0_public_key;
    using ::EC_KEY_set_private_key;
    using ::EC_KEY_set_public_key;
    using ::EC_POINT_new;
    using ::EC_POINT_free;
    using ::EC_POINT_mul;
    using ::EC_POINT_point2oct;
    using ::EC_POINT_oct2point;
    using ::EC_POINT_is_at_infinity;
    using ::EC_POINT_is_on_curve;
    using ::ECDSA_SIG;
    using ::ECDSA_SIG_free;
    using ::ECDSA_SIG_get0;
    using ::ECDSA_SIG_new;
    using ::ECDSA_SIG_set0;
    using ::ECDSA_do_sign;
    using ::ECDSA_do_verify;
    using boringssl_ecdh_abi::ECDH_compute_key;
    inline constexpr auto point_conversion_uncompressed=POINT_CONVERSION_UNCOMPRESSED;
    using ::EC_GROUP_get_curve_name;
    using ::EC_KEY_get0_group;
    using ::EVP_AEAD;
    using ::EVP_AEAD_CTX;
    using ::EVP_AEAD_CTX_free;
    using ::EVP_AEAD_CTX_new;
    using ::EVP_AEAD_CTX_init;
    using ::EVP_AEAD_CTX_cleanup;
    using ::EVP_AEAD_CTX_open;
    using ::EVP_AEAD_CTX_seal;
    using ::EVP_AEAD_CTX_seal_scatter;
    using ::EVP_AEAD_key_length;
    using ::EVP_AEAD_max_overhead;
    using ::EVP_AEAD_nonce_length;
    using ::EVP_Digest;
    using ::EVP_DigestFinal_ex;
    using ::EVP_DigestInit_ex;
    using ::EVP_DigestSign;
    using ::EVP_DigestSignInit;
    using ::EVP_DigestUpdate;
    using ::EVP_DigestVerify;
    using ::EVP_DigestVerifyInit;
    using ::EVP_MD;
    using ::EVP_MD_CTX;
    using ::EVP_MD_CTX_copy_ex;
    using ::EVP_MD_CTX_free;
    using ::EVP_MD_CTX_new;
    using ::EVP_MD_size;
    using ::EVP_PKEY;
    using ::EVP_PKEY2PKCS8;
    using ::EVP_PKEY_CTX;
    using ::EVP_PKEY_CTX_new_id;
    using ::EVP_PKEY_CTX_free;
    using ::EVP_PKEY_keygen_init;
    using ::EVP_PKEY_keygen;
    using ::EVP_PKEY_CTX_set_rsa_mgf1_md;
    using ::EVP_PKEY_CTX_set_rsa_padding;
    using ::EVP_PKEY_CTX_set_rsa_pss_saltlen;
    using ::EVP_PKEY_bits;
    using ::EVP_PKEY_free;
    using ::EVP_PKEY_get0_EC_KEY;
    using ::EVP_PKEY_get_raw_private_key;
    using ::EVP_PKEY_get_raw_public_key;
    using ::EVP_PKEY_id;
    using ::EVP_PKEY_new_raw_private_key;
    using ::EVP_PKEY_new_raw_public_key;
    using ::EVP_PKEY_size;
    using ::EVP_PKEY_up_ref;
    using ::EVP_aead_aes_128_gcm;
    using ::EVP_aead_aes_256_gcm;
    using ::EVP_aead_chacha20_poly1305;
    using ::EVP_aead_xchacha20_poly1305;
    using ::EVP_sha224;
    using ::EVP_md5;
    using ::EVP_sha1;
    using ::EVP_sha256;
    using ::EVP_sha384;
    using ::EVP_sha512;
    using ::HKDF_expand;
    using ::HKDF_extract;
    using ::HMAC;
    using ::HMAC_CTX;
    using ::HMAC_CTX_copy;
    using ::HMAC_CTX_free;
    using ::HMAC_CTX_new;
    using ::HMAC_Final;
    using ::HMAC_Init_ex;
    using ::HMAC_Update;
    using ::MLKEM768_decap;
    using ::MLKEM768_encap;
    using ::MLKEM768_generate_key;
    using ::MLKEM768_marshal_public_key;
    using ::MLKEM768_parse_public_key;
    using ::MLKEM768_private_key;
    using ::MLKEM768_private_key_from_seed;
    using ::MLKEM768_public_from_private;
    using ::MLKEM768_public_key;
    using ::OPENSSL_cleanse;
    using ::OPENSSL_free;
    using ::PEM_bytes_read_bio;
    using ::PEM_read_bio_PrivateKey;
    using ::PEM_read_bio_X509;
    using ::PKCS8_PRIV_KEY_INFO;
    using ::PKCS8_PRIV_KEY_INFO_free;
    using ::RAND_bytes;
    using ::X25519_public_from_private;
    using ::X509;
    using ::X509_new;
    using ::X509_set_version;
    using ::X509_get_serialNumber;
    using ::X509_gmtime_adj;
    using ::X509_getm_notBefore;
    using ::X509_getm_notAfter;
    using ::X509_set_pubkey;
    using ::X509_get_subject_name;
    using ::X509_set_issuer_name;
    using ::X509_sign;
    using ::X509_STORE;
    using ::X509_STORE_CTX;
    using ::X509_STORE_CTX_free;
    using ::X509_STORE_CTX_get0_param;
    using ::X509_STORE_CTX_get_error;
    inline constexpr auto x509_v_err_out_of_mem=X509_V_ERR_OUT_OF_MEM;
    using ::X509_STORE_CTX_init;
    using ::X509_STORE_CTX_new;
    using ::X509_STORE_add_cert;
    using ::X509_STORE_free;
    using ::X509_STORE_new;
    using ::X509_VERIFY_PARAM_set1_host;
    using ::X509_VERIFY_PARAM_set1_ip;
    using ::X509_VERIFY_PARAM_set_depth;
    using ::X509_VERIFY_PARAM_set_hostflags;
    using ::X509_VERIFY_PARAM_set_purpose;
    using ::X509_VERIFY_PARAM_set_time_posix;
    using ::X509_check_private_key;
    using ::X509_free;
    using ::X509_get0_signature;
    using ::X509_get_pubkey;
    using ::X509_verify_cert;
    using ::d2i_AutoPrivateKey;
    using ::d2i_X509;
    using ::env_md_ctx_st;
    using ::hmac_ctx_st;
    using ::evp_pkey_st;
    using ::i2d_PKCS8_PRIV_KEY_INFO;
    using ::i2d_X509;
    using ::sk_X509_free;
    using ::sk_X509_new_null;
    using ::sk_X509_push;
    using X509Stack = STACK_OF(X509);
    inline constexpr auto evp_aead_default_tag_length = EVP_AEAD_DEFAULT_TAG_LENGTH;
    inline constexpr auto evp_pkey_ec = EVP_PKEY_EC;
    inline constexpr auto evp_pkey_ed25519 = EVP_PKEY_ED25519;
    inline constexpr auto evp_pkey_rsa = EVP_PKEY_RSA;
    inline constexpr auto nid_x9_62_prime256v1 = NID_X9_62_prime256v1;
    inline constexpr auto nid_secp384r1 = NID_secp384r1;
    inline constexpr auto nid_secp521r1 = NID_secp521r1;
    inline constexpr auto rsa_pkcs1_pss_padding = RSA_PKCS1_PSS_PADDING;
    inline constexpr auto x509_check_flag_never_check_subject = X509_CHECK_FLAG_NEVER_CHECK_SUBJECT;
    inline constexpr auto x509_purpose_ssl_server = X509_PURPOSE_SSL_SERVER;
    inline constexpr auto pem_string_x509 = PEM_STRING_X509;
}
