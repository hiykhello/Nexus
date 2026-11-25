module;
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/mem.h>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wincrypt.h>
#ifdef _MSC_VER
#pragma comment(lib, "crypt32.lib")
#endif
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#ifdef __APPLE__
#include <TargetConditionals.h>
#if TARGET_OS_OSX
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#endif
#endif
#endif
module tls.certificate_trust;
import crypto.backend_errors;
import crypto;
import std;

namespace tls {
    namespace {
        auto parse_trust_bundle_impl(std::string_view pem, bool skip_duplicates)
            -> std::expected<std::vector<std::vector<std::uint8_t>>, TrustBundleError> {
            constexpr std::size_t max_bytes=4194304, max_cert=1048576, max_count=1024;
            constexpr std::string_view begin="-----BEGIN CERTIFICATE-----", end="-----END CERTIFICATE-----";
            if (pem.empty()) return std::unexpected(TrustBundleError::invalid_input);
            if (pem.size()>max_bytes) return std::unexpected(TrustBundleError::limit_exceeded);
            auto whitespace=[](char c) { return c==' ' || c=='\t' || c=='\r' || c=='\n'; };
            std::vector<std::vector<std::uint8_t>> result; std::size_t total=0;
            while (true) {
                while (true) {
                    while (!pem.empty() && whitespace(pem.front())) pem.remove_prefix(1);
                    if (pem.empty() || pem.front()!='#') break;
                    auto newline=pem.find('\n'); auto comment=pem.substr(0,newline);
                    if (std::ranges::any_of(comment,[](unsigned char c) { return c<0x20 && c!='\t' && c!='\r'; })) return std::unexpected(TrustBundleError::invalid_pem);
                    pem.remove_prefix(newline==std::string_view::npos ? pem.size() : newline+1);
                }
                if (pem.empty()) break;
                if (!pem.starts_with(begin)) return std::unexpected(TrustBundleError::invalid_pem);
                auto pos=pem.find(end,begin.size());
                if (pos==std::string_view::npos) return std::unexpected(TrustBundleError::invalid_pem);
                auto block=pem.substr(0,pos+end.size());
                auto body=block.substr(begin.size(),pos-begin.size());
                if (std::ranges::any_of(body,[&](char c) { return !whitespace(c) && !(c>='A' && c<='Z') && !(c>='a' && c<='z') && !(c>='0' && c<='9') && c!='+' && c!='/' && c!='='; }))
                    return std::unexpected(TrustBundleError::invalid_pem);
                if (result.size()==max_count || block.size()>max_cert*2) return std::unexpected(TrustBundleError::limit_exceeded);
                std::unique_ptr<BIO,decltype(&BIO_free)> bio(BIO_new_mem_buf(block.data(),static_cast<int>(block.size())),BIO_free);
                if (!bio) return std::unexpected(TrustBundleError::io_error);
                std::uint8_t* raw=nullptr; long raw_size=0;
                if (!PEM_bytes_read_bio(&raw,&raw_size,nullptr,PEM_STRING_X509,bio.get(),nullptr,nullptr)) return std::unexpected(TrustBundleError::invalid_certificate);
                std::unique_ptr<std::uint8_t,decltype(&OPENSSL_free)> decoded(raw,OPENSSL_free);
                if (raw_size<=0) return std::unexpected(TrustBundleError::invalid_certificate);
                if (static_cast<std::size_t>(raw_size)>max_cert) return std::unexpected(TrustBundleError::limit_exceeded);
                auto read_cursor=static_cast<std::uint8_t const*>(decoded.get());
                std::unique_ptr<X509,decltype(&X509_free)> cert(d2i_X509(nullptr,&read_cursor,raw_size),X509_free);
                if (!cert || read_cursor!=decoded.get()+raw_size) return std::unexpected(TrustBundleError::invalid_certificate);
                auto size=i2d_X509(cert.get(),nullptr);
                if (size<=0) return std::unexpected(TrustBundleError::invalid_certificate);
                if (static_cast<std::size_t>(size)>max_cert || static_cast<std::size_t>(size)>max_bytes-total) return std::unexpected(TrustBundleError::limit_exceeded);
                std::vector<std::uint8_t> der(static_cast<std::size_t>(size)); auto cursor=der.data();
                if (i2d_X509(cert.get(),&cursor)!=size) return std::unexpected(TrustBundleError::invalid_certificate);
                if (std::ranges::find(result,der)!=result.end()) {
                    if (!skip_duplicates) return std::unexpected(TrustBundleError::invalid_certificate);
                } else {
                    total+=der.size(); result.push_back(std::move(der));
                }
                pem.remove_prefix(block.size());
            }
            if (result.empty()) return std::unexpected(TrustBundleError::invalid_input);
            return result;
        }

        auto load_trust_bundle_impl(std::string_view path, bool skip_duplicates)
            -> std::expected<std::vector<std::vector<std::uint8_t>>, TrustBundleError> {
            constexpr std::size_t max_bytes=4194304;
            if (path.empty() || path.find('\0')!=std::string_view::npos) return std::unexpected(TrustBundleError::invalid_input);
#ifdef _WIN32
            (void)skip_duplicates;
            (void)max_bytes;
            return std::unexpected(TrustBundleError::io_error);
#else
            std::string name(path); int fd=::open(name.c_str(),O_RDONLY|O_CLOEXEC|O_NONBLOCK);
            if (fd<0) return std::unexpected(TrustBundleError::io_error);
            struct Fd { int value; ~Fd() { ::close(value); } } guard{fd};
            struct stat st{}; if (::fstat(fd,&st)!=0 || !S_ISREG(st.st_mode)) return std::unexpected(TrustBundleError::io_error);
            std::string bytes; std::array<char,8192> chunk{};
            while (true) {
                auto n=::read(fd,chunk.data(),chunk.size());
                if (n<0 && errno==EINTR) continue;
                if (n<0) return std::unexpected(TrustBundleError::io_error);
                if (!n) break;
                if (static_cast<std::size_t>(n)>max_bytes-bytes.size()) return std::unexpected(TrustBundleError::limit_exceeded);
                bytes.append(chunk.data(),static_cast<std::size_t>(n));
            }
            return parse_trust_bundle_impl(bytes, skip_duplicates);
#endif
        }
    }

    auto parse_trust_bundle(std::string_view pem) -> std::expected<std::vector<std::vector<std::uint8_t>>, TrustBundleError> {
        return parse_trust_bundle_impl(pem, false);
    }
    auto load_trust_bundle(std::string_view path) -> std::expected<std::vector<std::vector<std::uint8_t>>, TrustBundleError> {
        return load_trust_bundle_impl(path, false);
    }
    auto load_system_trust_bundle() -> std::expected<std::vector<std::vector<std::uint8_t>>, TrustBundleError> {
#ifdef _WIN32
        constexpr std::size_t max_bytes = 4194304, max_count = 1024;
        HCERTSTORE store = ::CertOpenSystemStoreW(0, L"ROOT");
        if (!store) return std::unexpected(TrustBundleError::io_error);
        std::vector<std::vector<std::uint8_t>> result;
        std::size_t total = 0;
        PCCERT_CONTEXT ctx = nullptr;
        while ((ctx = ::CertEnumCertificatesInStore(store, ctx)) != nullptr) {
            if (!ctx->pbCertEncoded || !ctx->cbCertEncoded) continue;
            if (result.size() >= max_count || ctx->cbCertEncoded > max_bytes - total) break;
            std::vector<std::uint8_t> der(ctx->pbCertEncoded, ctx->pbCertEncoded + ctx->cbCertEncoded);
            if (std::ranges::find(result, der) == result.end()) {
                total += der.size();
                result.push_back(std::move(der));
            }
        }
        ::CertCloseStore(store, 0);
        if (result.empty()) return std::unexpected(TrustBundleError::io_error);
        return result;
#elif defined(__APPLE__)
        if (char const* env = std::getenv("SSL_CERT_FILE"); env && env[0] == '/') {
            if (auto loaded = load_trust_bundle_impl(env, true); loaded && !loaded->empty()) return loaded;
        }
#if TARGET_OS_OSX
        constexpr std::size_t max_bytes = 4194304, max_count = 1024;
        struct CfDeleter {
            auto operator()(CFTypeRef ref) const noexcept -> void { if (ref) CFRelease(ref); }
        };
        using CfArray = std::unique_ptr<std::remove_pointer_t<CFArrayRef>, CfDeleter>;
        using CfData = std::unique_ptr<std::remove_pointer_t<CFDataRef>, CfDeleter>;
        using CfDict = std::unique_ptr<std::remove_pointer_t<CFDictionaryRef>, CfDeleter>;
        enum class TrustDecision : std::uint8_t { none, trusted, denied, restricted };
        auto domain_decision = [](SecCertificateRef cert, SecTrustSettingsDomain domain) noexcept -> TrustDecision {
            CFArrayRef raw_settings = nullptr;
            if (SecTrustSettingsCopyTrustSettings(cert, domain, &raw_settings) != errSecSuccess || !raw_settings)
                return TrustDecision::none;
            CfArray settings(raw_settings);
            auto const count = CFArrayGetCount(settings.get());
            if (count == 0) return TrustDecision::trusted;
            bool trusted = false;
            for (CFIndex i = 0; i < count; ++i) {
                auto const* entry = CFArrayGetValueAtIndex(settings.get(), i);
                if (!entry || CFGetTypeID(entry) != CFDictionaryGetTypeID()) continue;
                auto dict = static_cast<CFDictionaryRef>(entry);
                if (CFDictionaryGetValue(dict, kSecTrustSettingsPolicyString) != nullptr ||
                    CFDictionaryGetValue(dict, kSecTrustSettingsAllowedError) != nullptr)
                    continue;
                if (auto const* policy_val = CFDictionaryGetValue(dict, kSecTrustSettingsPolicy)) {
                    if (CFGetTypeID(policy_val) != SecPolicyGetTypeID()) continue;
                    auto policy = static_cast<SecPolicyRef>(const_cast<void*>(policy_val));
                    CfDict props(SecPolicyCopyProperties(policy));
                    if (!props || CFDictionaryGetValue(props.get(), kSecPolicyName) != nullptr) continue;
                    if (auto const* client = CFDictionaryGetValue(props.get(), kSecPolicyClient); client && CFEqual(client, kCFBooleanTrue)) continue;
                    auto const* oid = CFDictionaryGetValue(props.get(), kSecPolicyOid);
                    if (!oid || !CFEqual(oid, kSecPolicyAppleSSL)) continue;
                }
                auto const* val = CFDictionaryGetValue(dict, kSecTrustSettingsResult);
                if (!val) {
                    trusted = true;
                    continue;
                }
                if (CFGetTypeID(val) != CFNumberGetTypeID()) continue;
                std::int32_t res = 0;
                if (!CFNumberGetValue(static_cast<CFNumberRef>(val), kCFNumberSInt32Type, &res) || res < 0) continue;
                auto const ures = static_cast<std::uint32_t>(res);
                if (ures == kSecTrustSettingsResultDeny) return TrustDecision::denied;
                if (ures == kSecTrustSettingsResultTrustRoot || ures == kSecTrustSettingsResultTrustAsRoot)
                    trusted = true;
            }
            return trusted ? TrustDecision::trusted : TrustDecision::restricted;
        };
        std::vector<std::vector<std::uint8_t>> result;
        std::size_t total = 0;
        auto append_cert = [&](SecCertificateRef cert) {
            if (!cert || result.size() >= max_count) return;
            CfData data(SecCertificateCopyData(cert));
            if (!data) return;
            auto const len = CFDataGetLength(data.get());
            auto const* ptr = reinterpret_cast<std::uint8_t const*>(CFDataGetBytePtr(data.get()));
            if (!ptr || len <= 0 || static_cast<std::size_t>(len) > max_bytes - total) return;
            std::vector<std::uint8_t> der(ptr, ptr + static_cast<std::size_t>(len));
            if (std::ranges::find(result, der) == result.end()) {
                total += der.size();
                result.push_back(std::move(der));
            }
        };
        auto as_cert = [](void const* item) noexcept -> SecCertificateRef {
            if (!item || CFGetTypeID(item) != SecCertificateGetTypeID()) return nullptr;
            return static_cast<SecCertificateRef>(const_cast<void*>(item));
        };
        for (SecTrustSettingsDomain domain : {kSecTrustSettingsDomainUser, kSecTrustSettingsDomainAdmin}) {
            CFArrayRef raw_certs = nullptr;
            if (SecTrustSettingsCopyCertificates(domain, &raw_certs) != errSecSuccess || !raw_certs) continue;
            CfArray certs(raw_certs);
            auto const count = CFArrayGetCount(certs.get());
            for (CFIndex i = 0; i < count; ++i) {
                auto cert = as_cert(CFArrayGetValueAtIndex(certs.get(), i));
                if (!cert) continue;
                if (domain == kSecTrustSettingsDomainAdmin &&
                    domain_decision(cert, kSecTrustSettingsDomainUser) == TrustDecision::denied) continue;
                if (domain_decision(cert, domain) == TrustDecision::trusted) append_cert(cert);
            }
        }
        CFArrayRef raw_anchors = nullptr;
        if (SecTrustCopyAnchorCertificates(&raw_anchors) == errSecSuccess && raw_anchors) {
            CfArray anchors(raw_anchors);
            auto const count = CFArrayGetCount(anchors.get());
            for (CFIndex i = 0; i < count; ++i) {
                auto cert = as_cert(CFArrayGetValueAtIndex(anchors.get(), i));
                if (!cert) continue;
                auto const user = domain_decision(cert, kSecTrustSettingsDomainUser);
                if (user == TrustDecision::denied) continue;
                if (user == TrustDecision::trusted) { append_cert(cert); continue; }
                auto const admin = domain_decision(cert, kSecTrustSettingsDomainAdmin);
                if (admin == TrustDecision::denied) continue;
                if (admin == TrustDecision::trusted) { append_cert(cert); continue; }
                auto const sys = domain_decision(cert, kSecTrustSettingsDomainSystem);
                if (sys == TrustDecision::denied || sys == TrustDecision::restricted) continue;
                append_cert(cert);
            }
        }
        if (!result.empty()) return result;
#endif
        if (auto loaded = load_trust_bundle_impl("/etc/ssl/cert.pem", true); loaded && !loaded->empty()) return loaded;
        return std::unexpected(TrustBundleError::io_error);
#else
        if (char const* env = std::getenv("SSL_CERT_FILE"); env && env[0] == '/') {
            if (auto loaded = load_trust_bundle_impl(env, true)) return loaded;
        }
        constexpr std::array<std::string_view, 5> kCandidates{
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/ca-bundle.pem",
            "/etc/ssl/cert.pem",
            "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        };
        for (auto path : kCandidates) {
            if (auto loaded = load_trust_bundle_impl(path, true); loaded && !loaded->empty()) return loaded;
        }
        return std::unexpected(TrustBundleError::io_error);
#endif
    }
    auto verify_server_certificate_chain(std::span<std::span<std::uint8_t const> const> chain,
        std::span<std::span<std::uint8_t const> const> anchors, PeerNameKind kind,
        std::span<std::uint8_t const> name, std::int64_t now,std::span<std::array<std::uint8_t,32> const> pins) -> std::expected<void, CertificateTrustError> {
        constexpr std::size_t max_cert = 1048576, max_total = 4194304;
        if (chain.empty() || chain.size() > 16 || anchors.empty() || anchors.size() > 1024 || name.empty())
            return std::unexpected(CertificateTrustError::invalid_input);
        if (kind == PeerNameKind::dns) {
            if (name.size() > 253 || std::ranges::any_of(name, [](auto c) { return c <= 0x20 || c >= 0x7f; }))
                return std::unexpected(CertificateTrustError::invalid_input);
        } else if (kind != PeerNameKind::ip || (name.size() != 4 && name.size() != 16))
            return std::unexpected(CertificateTrustError::invalid_input);
        std::size_t total = 0;
        for (auto group : {chain, anchors}) for (auto der : group) {
            if (der.empty() || der.size() > max_cert || der.size() > max_total - total)
                return std::unexpected(CertificateTrustError::invalid_input);
            total += der.size();
        }
        crypto::BackendErrors backend_errors;
        using Cert = std::unique_ptr<X509, decltype(&X509_free)>;
        std::vector<Cert> certs;
        bool parse_allocation_failed=false;
        auto parse = [&](auto der) {
            auto cursor = der.data();
            Cert cert(d2i_X509(nullptr, &cursor, static_cast<long>(der.size())), X509_free);
            parse_allocation_failed=backend_errors.allocation_failed();
            if (parse_allocation_failed || !cert || cursor != der.data() + der.size()) return false;
            certs.push_back(std::move(cert)); return true;
        };
        for (auto der : chain) if (!parse(der)) return std::unexpected(parse_allocation_failed || backend_errors.allocation_failed() ? CertificateTrustError::crypto_error : CertificateTrustError::invalid_certificate);
        auto chain_size = certs.size();
        for (auto der : anchors) if (!parse(der)) return std::unexpected(parse_allocation_failed || backend_errors.allocation_failed() ? CertificateTrustError::crypto_error : CertificateTrustError::invalid_certificate);
        std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)> store(X509_STORE_new(), X509_STORE_free);
        std::unique_ptr<STACK_OF(X509), decltype(&sk_X509_free)> intermediates(sk_X509_new_null(), sk_X509_free);
        std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)> ctx(X509_STORE_CTX_new(), X509_STORE_CTX_free);
        if (!store || !intermediates || !ctx) return std::unexpected(CertificateTrustError::crypto_error);
        for (std::size_t i = chain_size; i < certs.size(); ++i)
            if (X509_STORE_add_cert(store.get(), certs[i].get()) != 1) return std::unexpected(CertificateTrustError::crypto_error);
        for (std::size_t i = 1; i < chain_size; ++i)
            if (!sk_X509_push(intermediates.get(), certs[i].get())) return std::unexpected(CertificateTrustError::crypto_error);
        if (X509_STORE_CTX_init(ctx.get(), store.get(), certs[0].get(), intermediates.get()) != 1)
            return std::unexpected(CertificateTrustError::crypto_error);
        auto param = X509_STORE_CTX_get0_param(ctx.get());
        X509_VERIFY_PARAM_set_depth(param, 8);
        X509_VERIFY_PARAM_set_time_posix(param, now);
        X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
        if (X509_VERIFY_PARAM_set_purpose(param, X509_PURPOSE_SSL_SERVER) != 1 ||
            (kind == PeerNameKind::dns ? X509_VERIFY_PARAM_set1_host(param, reinterpret_cast<char const*>(name.data()), name.size())
                                       : X509_VERIFY_PARAM_set1_ip(param, name.data(), name.size())) != 1)
            return std::unexpected(CertificateTrustError::crypto_error);
        if (X509_verify_cert(ctx.get()) != 1) return std::unexpected(
            X509_STORE_CTX_get_error(ctx.get())==X509_V_ERR_OUT_OF_MEM || backend_errors.allocation_failed() ?
                CertificateTrustError::crypto_error : CertificateTrustError::verification_failed);
        if (!pins.empty()) {
            auto* verified=X509_STORE_CTX_get0_chain(ctx.get());
            if (!verified) return std::unexpected(CertificateTrustError::crypto_error);
            bool matched=false;
            auto match=[&](auto encode,auto* value) -> bool {
                std::uint8_t* bytes=nullptr;
                auto size=encode(value,&bytes);
                std::unique_ptr<std::uint8_t,decltype(&OPENSSL_free)> memory(bytes,OPENSSL_free);
                if (size<=0 || !bytes) return false;
                auto hash=crypto::digest(crypto::Hash::sha256,{bytes,static_cast<std::size_t>(size)});
                if (!hash) return false;
                for (auto const& pin:pins) matched|=crypto::constant_time_equal(pin,*hash);
                return true;
            };
            for (std::size_t i=0;i<sk_X509_num(verified);++i) {
                auto* cert=sk_X509_value(verified,i);
                if (!match(i2d_X509,cert) || !match(i2d_X509_PUBKEY,X509_get_X509_PUBKEY(cert)))
                    return std::unexpected(CertificateTrustError::crypto_error);
            }
            if (!matched) return std::unexpected(CertificateTrustError::verification_failed);
        }
        return {};
    }
}
