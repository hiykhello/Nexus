module;
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/mem.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
module tls.certificate_trust;
import crypto.backend_errors;
import crypto;
import std;

namespace tls {
    auto parse_trust_bundle(std::string_view pem) -> std::expected<std::vector<std::vector<std::uint8_t>>, TrustBundleError> {
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
            if (std::ranges::find(result,der)!=result.end()) return std::unexpected(TrustBundleError::invalid_certificate);
            total+=der.size(); result.push_back(std::move(der)); pem.remove_prefix(block.size());
        }
        if (result.empty()) return std::unexpected(TrustBundleError::invalid_input);
        return result;
    }
    auto load_trust_bundle(std::string_view path) -> std::expected<std::vector<std::vector<std::uint8_t>>, TrustBundleError> {
        constexpr std::size_t max_bytes=4194304;
        if (path.empty() || path.find('\0')!=std::string_view::npos) return std::unexpected(TrustBundleError::invalid_input);
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
        return parse_trust_bundle(bytes);
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
