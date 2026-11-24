export module acme.client;
import std;
export import acme.types;
export import acme.jws;
export import acme.store;

export namespace acme {
    [[nodiscard]] auto fetch_directory(std::string_view url, HttpExchangeFn http)
        -> std::expected<AcmeDirectory, std::string>;
    [[nodiscard]] auto fetch_nonce(std::string_view new_nonce_url, HttpExchangeFn http)
        -> std::expected<std::string, std::string>;
    [[nodiscard]] auto register_account(AcmeDirectory const& dir, EcAccountKey const& key,
                                        std::string_view email, std::string& nonce, HttpExchangeFn http)
        -> std::expected<std::string, std::string>;
    [[nodiscard]] auto create_order(AcmeDirectory const& dir, EcAccountKey const& key, std::string_view kid,
                                    std::span<std::string const> domains, std::string& nonce, HttpExchangeFn http)
        -> std::expected<AcmeOrder, std::string>;
    [[nodiscard]] auto prepare_challenge(AcmeOrder const& order, ChallengeType preferred, EcAccountKey const& key,
                                         std::string_view kid, std::string& nonce, HttpExchangeFn http)
        -> std::expected<std::vector<AcmeChallenge>, std::string>;
    [[nodiscard]] auto ensure_certificate(AcmeConfig const& cfg, CertificateStore& store, EcAccountKey const& key,
                                          HttpExchangeFn http, ChallengeHooks const& hooks, std::int64_t now_epoch)
        -> std::expected<bool, std::string>;
}
