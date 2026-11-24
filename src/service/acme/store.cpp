module acme.store;
import std;
import acme.jws;
import rulefile;

namespace acme {
    auto CertificateStore::install(CertificateBundle bundle) -> void {
        auto ptr = std::make_shared<CertificateBundle const>(std::move(bundle));
        std::lock_guard lock(mutex_);
        active_ = std::move(ptr);
    }

    auto CertificateStore::current() const noexcept -> std::shared_ptr<CertificateBundle const> {
        std::lock_guard lock(mutex_);
        return active_;
    }

    auto CertificateStore::needs_renewal(std::int64_t now_epoch, std::int64_t renew_before_seconds) const noexcept -> bool {
        auto snap = current();
        if (!snap || snap->cert_pem.empty() || snap->key_pem.empty()) return true;
        return now_epoch + renew_before_seconds >= snap->not_after_epoch;
    }

    auto CertificateStore::save_to_dir(std::filesystem::path const& dir, CertificateBundle const& bundle)
        -> std::expected<void, std::string> {
        if (dir.empty()) return std::unexpected("ACME state_dir is empty");
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        if (ec) return std::unexpected("cannot create ACME state_dir: " + ec.message());
        if (auto r = rulefile::replace_file((dir / "fullchain.pem").string(), bundle.cert_pem); !r) return r;
        return rulefile::replace_file((dir / "privkey.pem").string(), bundle.key_pem);
    }

    auto CertificateStore::load_from_dir(std::filesystem::path const& dir)
        -> std::expected<CertificateBundle, std::string> {
        if (dir.empty()) return std::unexpected("ACME state_dir is empty");
        auto cert = rulefile::read_regular_file((dir / "fullchain.pem").string());
        if (!cert) return std::unexpected(cert.error());
        auto key = rulefile::read_private_file((dir / "privkey.pem").string());
        if (!key) return std::unexpected(key.error());
        auto validity = parse_cert_validity(*cert);
        if (!validity) return std::unexpected(validity.error());
        return CertificateBundle{
            .cert_pem = std::move(*cert),
            .key_pem = std::string(key->bytes().data(), key->bytes().size()),
            .not_before_epoch = validity->not_before_epoch,
            .not_after_epoch = validity->not_after_epoch,
        };
    }
}
