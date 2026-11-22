export module acme.store;
import std;
export import acme.types;

export namespace acme {
    class CertificateStore {
        mutable std::mutex mutex_;
        std::shared_ptr<CertificateBundle const> active_;
    public:
        auto install(CertificateBundle bundle) -> void;
        [[nodiscard]] auto current() const noexcept -> std::shared_ptr<CertificateBundle const>;
        [[nodiscard]] auto needs_renewal(std::int64_t now_epoch, std::int64_t renew_before_seconds) const noexcept -> bool;
        [[nodiscard]] static auto save_to_dir(std::filesystem::path const& dir, CertificateBundle const& bundle)
            -> std::expected<void, std::string>;
        [[nodiscard]] static auto load_from_dir(std::filesystem::path const& dir)
            -> std::expected<CertificateBundle, std::string>;
    };
}
