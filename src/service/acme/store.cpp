module acme.store;
import std;
import crypto;
import acme.jws;
import rulefile;

namespace acme {
    namespace {
        struct WipeString {
            std::string& s;
            ~WipeString() {
                if (!s.empty())
                    crypto::cleanse(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(s.data()), s.size()));
            }
        };

        auto split_paired_pem(std::string_view combined)
            -> std::expected<std::pair<std::string, std::string>, std::string> {
            std::string key_pem, cert_pem;
            std::size_t key_blocks = 0, cert_blocks = 0;
            std::size_t pos = 0;
            while (pos < combined.size()) {
                auto begin = combined.find("-----BEGIN ", pos);
                if (begin == std::string_view::npos) break;
                auto hdr_end = combined.find("-----", begin + 11);
                if (hdr_end == std::string_view::npos) return std::unexpected("malformed PEM header in ACME credential");
                auto label = combined.substr(begin + 11, hdr_end - (begin + 11));
                auto end_marker = std::format("-----END {}-----", label);
                auto end = combined.find(end_marker, hdr_end + 5);
                if (end == std::string_view::npos) return std::unexpected("unterminated PEM block in ACME credential");
                auto block_end = end + end_marker.size();
                if (block_end < combined.size() && combined[block_end] == '\r') ++block_end;
                if (block_end < combined.size() && combined[block_end] == '\n') ++block_end;
                auto block = combined.substr(begin, block_end - begin);
                if (label.contains("PRIVATE KEY")) {
                    ++key_blocks;
                    key_pem.append(block);
                } else if (label == "CERTIFICATE") {
                    ++cert_blocks;
                    cert_pem.append(block);
                } else {
                    return std::unexpected("unexpected PEM block in ACME credential");
                }
                pos = block_end;
            }
            if (key_blocks != 1 || cert_blocks == 0)
                return std::unexpected("ACME paired credential missing private key or certificate");
            return std::pair{std::move(cert_pem), std::move(key_pem)};
        }
    }

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
        if (auto ok = verify_cert_key_pair(bundle.cert_pem, bundle.key_pem); !ok)
            return std::unexpected(ok.error());
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        if (ec) return std::unexpected("cannot create ACME state_dir: " + ec.message());
        // Persist private key + fullchain atomically as a single paired 0600 file so a crash
        // or write failure can never leave a mixed generation of cert and key on disk.
        std::string paired;
        WipeString wipe{paired};
        paired.reserve(bundle.key_pem.size() + bundle.cert_pem.size() + 2);
        paired.append(bundle.key_pem);
        if (!paired.empty() && paired.back() != '\n') paired.push_back('\n');
        paired.append(bundle.cert_pem);
        if (!paired.empty() && paired.back() != '\n') paired.push_back('\n');
        return rulefile::replace_file((dir / "credential.pem").string(), paired);
    }

    auto CertificateStore::load_from_dir(std::filesystem::path const& dir)
        -> std::expected<CertificateBundle, std::string> {
        if (dir.empty()) return std::unexpected("ACME state_dir is empty");
        auto paired_path = dir / "credential.pem";
        std::error_code ec;
        if (std::filesystem::exists(paired_path, ec) && !ec) {
            auto raw = rulefile::read_private_file(paired_path.string());
            if (!raw) return std::unexpected(raw.error());
            auto split = split_paired_pem({raw->bytes().data(), raw->bytes().size()});
            if (!split) return std::unexpected(split.error());
            auto validity = verify_cert_key_pair(split->first, split->second);
            if (!validity) return std::unexpected(validity.error());
            return CertificateBundle{
                .cert_pem = std::move(split->first),
                .key_pem = std::move(split->second),
                .not_before_epoch = validity->not_before_epoch,
                .not_after_epoch = validity->not_after_epoch,
            };
        }
        // Legacy fallback for pre-existing fullchain.pem + privkey.pem layouts:
        // strictly verify cryptographic cert/key match before accepting.
        auto cert = rulefile::read_regular_file((dir / "fullchain.pem").string());
        if (!cert) return std::unexpected(cert.error());
        auto key = rulefile::read_private_file((dir / "privkey.pem").string());
        if (!key) return std::unexpected(key.error());
        std::string key_pem(key->bytes().data(), key->bytes().size());
        auto validity = verify_cert_key_pair(*cert, key_pem);
        if (!validity) {
            crypto::cleanse(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(key_pem.data()), key_pem.size()));
            return std::unexpected(validity.error());
        }
        return CertificateBundle{
            .cert_pem = std::move(*cert),
            .key_pem = std::move(key_pem),
            .not_before_epoch = validity->not_before_epoch,
            .not_after_epoch = validity->not_after_epoch,
        };
    }
}
