module acme.client;
import std;
import glaze;

namespace acme {
    namespace detail {
        struct DirectoryWire { std::string newNonce, newAccount, newOrder; };
        struct IdentifierWire { std::string type, value; };
        struct OrderReqWire { std::vector<IdentifierWire> identifiers; };
        struct ChallengeWire { std::string type, url, token, status; };
        struct AuthzWire { IdentifierWire identifier; std::string status; std::vector<ChallengeWire> challenges; };
        struct OrderWire {
            std::string status, finalize, certificate;
            std::vector<std::string> authorizations;
        };
    }

    namespace {
        using detail::DirectoryWire;
        using detail::IdentifierWire;
        using detail::OrderReqWire;
        using detail::ChallengeWire;
        using detail::AuthzWire;
        using detail::OrderWire;

        auto type_name(ChallengeType t) noexcept -> std::string_view {
            switch (t) {
            case ChallengeType::http01: return "http-01";
            case ChallengeType::tls_alpn01: return "tls-alpn-01";
            case ChallengeType::dns01: return "dns-01";
            }
            return "http-01";
        }

        template<class T>
        auto parse_json(std::string_view body) -> std::expected<T, std::string> {
            T out{};
            auto err = glaze::read<glaze::opts{.error_on_unknown_keys = false}>(out, body);
            if (err) return std::unexpected("ACME JSON decode failed");
            return out;
        }

        auto valid_json_text(std::string_view s) noexcept -> bool {
            return std::ranges::none_of(s, [](unsigned char c) {
                return c <= 0x20 || c >= 0x7f || c == '"' || c == '\\';
            });
        }

        auto iequal_ascii(std::string_view a, std::string_view b) noexcept -> bool {
            if (a.size() != b.size()) return false;
            for (std::size_t i = 0; i < a.size(); ++i) {
                auto ca = static_cast<unsigned char>(a[i]);
                auto cb = static_cast<unsigned char>(b[i]);
                if (ca >= 'A' && ca <= 'Z') ca = static_cast<unsigned char>(ca - 'A' + 'a');
                if (cb >= 'A' && cb <= 'Z') cb = static_cast<unsigned char>(cb - 'A' + 'a');
                if (ca != cb) return false;
            }
            return true;
        }

        auto post_jws(EcAccountKey const& key, std::string_view url, std::string_view payload,
                      std::string_view kid, AcmeDirectory const& dir, std::string& nonce, HttpExchangeFn http)
            -> std::expected<HttpResponse, std::string> {
            if (nonce.empty()) {
                if (dir.new_nonce.empty()) return std::unexpected("ACME missing Replay-Nonce and directory newNonce");
                auto fresh = fetch_nonce(dir.new_nonce, http);
                if (!fresh) return std::unexpected(fresh.error());
                nonce = std::move(*fresh);
            }
            auto body = sign_jws(key, url, nonce, payload, kid);
            if (!body) return std::unexpected(body.error());
            nonce.clear();
            auto resp = http({"POST", url, "application/jose+json", *body});
            if (!resp) return std::unexpected(resp.error());
            if (!resp->replay_nonce.empty()) nonce = resp->replay_nonce;
            return resp;
        }

        auto prepare_challenges_with_dir(AcmeDirectory const& dir, AcmeOrder const& order, ChallengeType preferred,
                                         EcAccountKey const& key, std::string_view kid, std::string& nonce,
                                         HttpExchangeFn http)
            -> std::expected<std::vector<std::pair<std::string, AcmeChallenge>>, std::string> {
            std::vector<std::pair<std::string, AcmeChallenge>> out;
            for (auto const& authz_url : order.authorizations) {
                auto resp = post_jws(key, authz_url, {}, kid, dir, nonce, http);
                if (!resp) return std::unexpected(resp.error());
                if (resp->status < 200 || resp->status >= 300)
                    return std::unexpected(std::format("ACME authz fetch failed (HTTP {})", resp->status));
                auto authz = parse_json<AuthzWire>(resp->body);
                if (!authz) return std::unexpected(authz.error());
                auto want = type_name(preferred);
                auto it = std::ranges::find_if(authz->challenges, [&](auto const& c) { return c.type == want; });
                if (it == authz->challenges.end())
                    return std::unexpected(std::format("ACME authz {} lacks {}", authz->identifier.value, want));
                auto ka = key.key_authorization(it->token);
                if (!ka) return std::unexpected(ka.error());
                std::string record = authz->identifier.value;
                if (preferred == ChallengeType::dns01) {
                    auto txt = key.dns01_txt_value(it->token);
                    if (!txt) return std::unexpected(txt.error());
                    record = std::format("_acme-challenge.{}={}", authz->identifier.value, *txt);
                } else if (preferred == ChallengeType::http01) {
                    record = std::format("/.well-known/acme-challenge/{}", it->token);
                }
                out.emplace_back(authz->identifier.value,
                    AcmeChallenge{preferred, it->url, it->token, it->status, std::move(*ka), std::move(record)});
            }
            return out;
        }
    }

    auto fetch_directory(std::string_view url, HttpExchangeFn http) -> std::expected<AcmeDirectory, std::string> {
        auto resp = http({"GET", url, {}, {}});
        if (!resp) return std::unexpected(resp.error());
        if (resp->status < 200 || resp->status >= 300)
            return std::unexpected(std::format("ACME directory HTTP {}", resp->status));
        auto parsed = parse_json<DirectoryWire>(resp->body);
        if (!parsed) return std::unexpected(parsed.error());
        if (parsed->newNonce.empty() || parsed->newAccount.empty() || parsed->newOrder.empty())
            return std::unexpected("ACME directory missing required endpoints");
        return AcmeDirectory{std::move(parsed->newNonce), std::move(parsed->newAccount), std::move(parsed->newOrder)};
    }

    auto fetch_nonce(std::string_view new_nonce_url, HttpExchangeFn http) -> std::expected<std::string, std::string> {
        auto resp = http({"HEAD", new_nonce_url, {}, {}});
        if (!resp) return std::unexpected(resp.error());
        if (resp->replay_nonce.empty()) return std::unexpected("ACME newNonce returned empty Replay-Nonce");
        return resp->replay_nonce;
    }

    auto register_account(AcmeDirectory const& dir, EcAccountKey const& key,
                          std::string_view email, std::string& nonce, HttpExchangeFn http,
                          EabCredentials const* eab)
        -> std::expected<std::string, std::string> {
        if (!email.empty() && !valid_json_text(email)) return std::unexpected("invalid ACME contact email");
        std::string eab_part;
        if (eab && (!eab->kid.empty() || !eab->hmac_key.empty())) {
            auto eab_jws = sign_eab_jws(key, dir.new_account, eab->kid, eab->hmac_key);
            if (!eab_jws) return std::unexpected(eab_jws.error());
            eab_part = std::format(",\"externalAccountBinding\":{}", *eab_jws);
        }
        std::string payload = email.empty()
            ? std::format("{{\"termsOfServiceAgreed\":true{}}}", eab_part)
            : std::format("{{\"contact\":[\"mailto:{}\"],\"termsOfServiceAgreed\":true{}}}", email, eab_part);
        auto resp = post_jws(key, dir.new_account, payload, {}, dir, nonce, http);
        if (!resp) return std::unexpected(resp.error());
        if (resp->status < 200 || resp->status >= 300 || resp->location.empty())
            return std::unexpected(std::format("ACME account registration failed (HTTP {})", resp->status));
        return resp->location;
    }

    auto create_order(AcmeDirectory const& dir, EcAccountKey const& key, std::string_view kid,
                      std::span<std::string const> domains, std::string& nonce, HttpExchangeFn http)
        -> std::expected<AcmeOrder, std::string> {
        std::string ids;
        for (std::size_t i = 0; i < domains.size(); ++i) {
            if (domains[i].empty() || !valid_json_text(domains[i])) return std::unexpected("invalid ACME domain");
            if (i > 0) ids += ',';
            ids += std::format("{{\"type\":\"dns\",\"value\":\"{}\"}}", domains[i]);
        }
        auto payload = std::format("{{\"identifiers\":[{}]}}", ids);
        auto resp = post_jws(key, dir.new_order, payload, kid, dir, nonce, http);
        if (!resp) return std::unexpected(resp.error());
        if (resp->status < 200 || resp->status >= 300)
            return std::unexpected(std::format("ACME newOrder failed (HTTP {})", resp->status));
        auto wire = parse_json<OrderWire>(resp->body);
        if (!wire) return std::unexpected(wire.error());
        return AcmeOrder{resp->location, std::move(wire->status), std::move(wire->finalize),
                         std::move(wire->certificate), std::move(wire->authorizations)};
    }

    auto prepare_challenge(AcmeOrder const& order, ChallengeType preferred, EcAccountKey const& key,
                           std::string_view kid, std::string& nonce, HttpExchangeFn http)
        -> std::expected<std::vector<AcmeChallenge>, std::string> {
        AcmeDirectory empty{};
        auto prepared = prepare_challenges_with_dir(empty, order, preferred, key, kid, nonce, http);
        if (!prepared) return std::unexpected(std::move(prepared.error()));
        std::vector<AcmeChallenge> out;
        out.reserve(prepared->size());
        for (auto& entry : *prepared) out.push_back(std::move(entry.second));
        return out;
    }

    auto ensure_certificate(AcmeConfig const& cfg, CertificateStore& store, EcAccountKey const& key,
                            HttpExchangeFn http, ChallengeHooks const& hooks, std::int64_t now_epoch)
        -> std::expected<bool, std::string> {
        if (cfg.domains.empty() || cfg.directory_url.empty()) return std::unexpected("invalid ACME config");
        if (!store.needs_renewal(now_epoch, cfg.renew_before_seconds)) return false;

        auto dir = fetch_directory(cfg.directory_url, http);
        if (!dir) return std::unexpected(dir.error());
        auto nonce_res = fetch_nonce(dir->new_nonce, http);
        if (!nonce_res) return std::unexpected(nonce_res.error());
        std::string nonce = std::move(*nonce_res);

        auto kid = register_account(*dir, key, cfg.email, nonce, http, cfg.eab ? &*cfg.eab : nullptr);
        if (!kid) return std::unexpected(kid.error());
        auto order = create_order(*dir, key, *kid, cfg.domains, nonce, http);
        if (!order) return std::unexpected(order.error());
        auto challenges = prepare_challenges_with_dir(*dir, *order, cfg.challenge, key, *kid, nonce, http);
        if (!challenges) return std::unexpected(challenges.error());

        struct Cleanup {
            ChallengeHooks const& h;
            ~Cleanup() { if (h.cleanup) (*h.cleanup)(); }
        } cleanup_guard{hooks};

        auto strip_wild = [](std::string_view s) { return s.starts_with("*.") ? s.substr(2) : s; };
        for (auto const& [authz_domain, ch] : *challenges) {
            auto matched = std::ranges::find_if(cfg.domains, [&](std::string const& d) {
                return iequal_ascii(d, authz_domain) || iequal_ascii(strip_wild(d), authz_domain);
            });
            if (matched == cfg.domains.end())
                return std::unexpected("ACME authorization domain mismatch: " + authz_domain);
            std::string_view domain = strip_wild(*matched);
            if (cfg.challenge == ChallengeType::http01 && hooks.publish_http01) {
                if (!(*hooks.publish_http01)(ch.token, ch.key_authorization)) return std::unexpected("HTTP-01 hook failed");
            } else if (cfg.challenge == ChallengeType::tls_alpn01 && hooks.publish_alpn01) {
                auto dig = key.tls_alpn01_digest(ch.token);
                if (!dig) return std::unexpected(dig.error());
                auto cert = generate_alpn01_cert(domain, *dig);
                if (!cert) return std::unexpected(cert.error());
                if (!(*hooks.publish_alpn01)(domain, cert->cert_pem, cert->key_pem))
                    return std::unexpected("TLS-ALPN-01 hook failed");
            } else if (cfg.challenge == ChallengeType::dns01 && hooks.publish_dns01) {
                auto txt = key.dns01_txt_value(ch.token);
                if (!txt) return std::unexpected(txt.error());
                if (!(*hooks.publish_dns01)(domain, *txt)) return std::unexpected("DNS-01 hook failed");
            }
            auto ack = post_jws(key, ch.url, "{}", *kid, *dir, nonce, http);
            if (!ack || ack->status >= 300) return std::unexpected("ACME challenge trigger failed");
        }

        OrderWire cur{};
        for (std::uint32_t attempt = 0; attempt < cfg.max_poll_attempts; ++attempt) {
            auto poll = post_jws(key, order->url, {}, *kid, *dir, nonce, http);
            if (!poll || poll->status >= 300) return std::unexpected("ACME order poll failed");
            auto parsed = parse_json<OrderWire>(poll->body);
            if (!parsed) return std::unexpected(parsed.error());
            cur = std::move(*parsed);
            if (cur.status == "ready" || cur.status == "valid") break;
            if (cur.status == "invalid") return std::unexpected("ACME order became invalid");
        }
        auto csr = generate_csr_p256(cfg.domains);
        if (!csr) return std::unexpected(csr.error());
        if (cur.status == "ready") {
            auto fin = post_jws(key, cur.finalize.empty() ? order->finalize_url : cur.finalize,
                                std::format("{{\"csr\":\"{}\"}}", csr->csr_der_base64url), *kid, *dir, nonce, http);
            if (!fin || fin->status >= 300) return std::unexpected("ACME finalize failed");
            auto parsed = parse_json<OrderWire>(fin->body);
            if (!parsed) return std::unexpected(parsed.error());
            cur = std::move(*parsed);
        }
        for (std::uint32_t attempt = 0; cur.status != "valid" && attempt < cfg.max_poll_attempts; ++attempt) {
            auto poll = post_jws(key, order->url, {}, *kid, *dir, nonce, http);
            if (!poll || poll->status >= 300) return std::unexpected("ACME final poll failed");
            auto parsed = parse_json<OrderWire>(poll->body);
            if (!parsed) return std::unexpected(parsed.error());
            cur = std::move(*parsed);
        }
        if (cur.status != "valid" || cur.certificate.empty()) return std::unexpected("ACME order did not issue cert");
        auto dl = post_jws(key, cur.certificate, {}, *kid, *dir, nonce, http);
        if (!dl || dl->status < 200 || dl->status >= 300) return std::unexpected("ACME certificate download failed");
        auto validity = parse_cert_validity(dl->body);
        if (!validity) return std::unexpected(validity.error());

        CertificateBundle bundle{std::move(dl->body), std::move(csr->key_pem), validity->not_before_epoch,
                                 validity->not_after_epoch, cfg.domains};
        if (!cfg.state_dir.empty()) {
            if (auto saved = CertificateStore::save_to_dir(cfg.state_dir, bundle); !saved)
                return std::unexpected(saved.error());
        }
        store.install(std::move(bundle));
        return true;
    }
}
