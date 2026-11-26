module acme.dns01_providers;
import std;
import crypto;
import encoding.base64;
import glaze;

namespace acme {
    namespace detail {
        struct CfZoneWire { std::string id, name; };
        struct CfZonesRespWire { bool success = false; std::vector<CfZoneWire> result; };
        struct CfRecordWire { std::string id; };
        struct CfCreateRespWire { bool success = false; CfRecordWire result; };
        struct CfDeleteRespWire { bool success = false; };
        struct AliDomainInfoWire { std::string DomainName, Code, Message; };
        struct AliAddRecordWire { std::string RecordId, Code, Message; };
        struct AliDelRecordWire { std::string RecordId, Code, Message; };
    }

    namespace {
        auto trim_trailing_slash(std::string s) -> std::string {
            while (!s.empty() && s.back() == '/') s.pop_back();
            return s;
        }

        auto valid_txt_value(std::string_view v) noexcept -> bool {
            return !v.empty() && v.size() <= 512 && std::ranges::none_of(v, [](unsigned char c) {
                return c < 0x20 || c >= 0x7f || c == '"' || c == '\\';
            });
        }

        auto valid_api_id(std::string_view v) noexcept -> bool {
            return !v.empty() && v.size() <= 128 && std::ranges::all_of(v, [](unsigned char c) {
                return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                       (c >= '0' && c <= '9') || c == '-' || c == '_';
            });
        }

        auto parent_zones(std::string_view norm) -> std::vector<std::string_view> {
            std::vector<std::string_view> zones;
            std::string_view cur = norm;
            while (cur.contains('.')) {
                zones.push_back(cur);
                auto dot = cur.find('.');
                if (dot == std::string_view::npos || dot + 1 >= cur.size()) break;
                cur.remove_prefix(dot + 1);
            }
            return zones;
        }

        template<class T>
        auto decode_json(std::string_view body) -> std::expected<T, std::string> {
            T out{};
            auto err = glaze::read<glaze::opts{.error_on_unknown_keys = false}>(out, body);
            if (err) return std::unexpected("DNS-01 JSON decode failed");
            return out;
        }

        auto utc_iso8601_now() -> std::string {
            auto sec = std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());
            return std::format("{:%FT%TZ}", sec);
        }

        auto random_nonce_hex() -> std::expected<std::string, std::string> {
            std::array<std::uint8_t, 16> raw{};
            if (!crypto::random_bytes(raw)) return std::unexpected("AliDNS nonce CSPRNG failed");
            static constexpr char kHex[] = "0123456789abcdef";
            std::string out;
            out.reserve(32);
            for (auto b : raw) { out.push_back(kHex[b >> 4]); out.push_back(kHex[b & 0x0f]); }
            return out;
        }
    }

    auto normalize_acme_domain(std::string_view domain) -> std::expected<std::string, std::string> {
        if (domain.starts_with("*.")) domain.remove_prefix(2);
        while (!domain.empty() && domain.back() == '.') domain.remove_suffix(1);
        if (domain.empty() || domain.size() > 253 || domain.front() == '.' || !domain.contains('.'))
            return std::unexpected("invalid DNS-01 domain");
        std::string out;
        out.reserve(domain.size());
        bool prev_dot = false;
        for (unsigned char c : domain) {
            if (c >= 'A' && c <= 'Z') c = static_cast<unsigned char>(c - 'A' + 'a');
            bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.';
            if (!ok || (c == '.' && prev_dot)) return std::unexpected("invalid DNS-01 domain character");
            prev_dot = (c == '.');
            out.push_back(static_cast<char>(c));
        }
        return out;
    }

    auto percent_encode_rfc3986(std::string_view input) -> std::string {
        static constexpr char kHex[] = "0123456789ABCDEF";
        std::string out;
        out.reserve(input.size() + 16);
        for (unsigned char c : input) {
            bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                              (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~';
            if (unreserved) out.push_back(static_cast<char>(c));
            else {
                out.push_back('%');
                out.push_back(kHex[c >> 4]);
                out.push_back(kHex[c & 0x0f]);
            }
        }
        return out;
    }

    auto alidns_build_signed_query(
        std::span<std::pair<std::string, std::string> const> params,
        std::string_view access_key_secret,
        std::string_view http_method) -> std::expected<std::string, std::string> {
        if (access_key_secret.empty() || http_method.empty())
            return std::unexpected("AliDNS signing requires secret and HTTP method");
        std::vector<std::pair<std::string, std::string>> sorted(params.begin(), params.end());
        std::ranges::sort(sorted, [](auto const& a, auto const& b) {
            return a.first < b.first || (a.first == b.first && a.second < b.second);
        });
        std::string canonical;
        for (std::size_t i = 0; i < sorted.size(); ++i) {
            if (i > 0) canonical.push_back('&');
            canonical += percent_encode_rfc3986(sorted[i].first);
            canonical.push_back('=');
            canonical += percent_encode_rfc3986(sorted[i].second);
        }
        std::string to_sign = std::format("{}&%2F&{}", http_method, percent_encode_rfc3986(canonical));
        std::string key = std::string(access_key_secret) + "&";
        struct Wipe {
            std::string& s;
            ~Wipe() { if (!s.empty()) crypto::cleanse({reinterpret_cast<std::uint8_t*>(s.data()), s.size()}); }
        } wipe{key};
        auto ctx = crypto::HmacSha1Context::create({reinterpret_cast<std::uint8_t const*>(key.data()), key.size()});
        if (!ctx) return std::unexpected("AliDNS HMAC-SHA1 init failed");
        if (!ctx->update({reinterpret_cast<std::uint8_t const*>(to_sign.data()), to_sign.size()}))
            return std::unexpected("AliDNS HMAC-SHA1 update failed");
        auto mac = ctx->snapshot();
        if (!mac) return std::unexpected("AliDNS HMAC-SHA1 finalize failed");
        auto sig_b64 = encoding::encode_base64(*mac, false, true);
        return canonical + "&Signature=" + percent_encode_rfc3986(sig_b64);
    }

    CloudflareDns01Provider::CloudflareDns01Provider(std::string api_token, std::string api_base)
        : api_token_(std::move(api_token)), api_base_(trim_trailing_slash(std::move(api_base))) {}

    auto CloudflareDns01Provider::publish(std::string_view domain, std::string_view txt_value, HttpExchangeFn http) const
        -> std::expected<Dns01RecordHandle, std::string> {
        if (api_token_.empty() || api_base_.empty()) return std::unexpected("Cloudflare DNS-01 missing API token");
        auto norm = normalize_acme_domain(domain);
        if (!norm) return std::unexpected(norm.error());
        if (!valid_txt_value(txt_value)) return std::unexpected("invalid DNS-01 TXT value");

        std::vector<std::pair<std::string, std::string>> auth{{"Authorization", "Bearer " + api_token_}};
        struct WipeAuth {
            std::string& s;
            ~WipeAuth() { if (!s.empty()) crypto::cleanse({reinterpret_cast<std::uint8_t*>(s.data()), s.size()}); }
        } wipe_auth{auth[0].second};
        std::string zone_id;
        for (auto cand : parent_zones(*norm)) {
            auto url = std::format("{}/zones?name={}&status=active", api_base_, percent_encode_rfc3986(cand));
            auto resp = http({"GET", url, {}, {}, auth});
            if (!resp) return std::unexpected("Cloudflare zone lookup failed: " + resp.error());
            if (resp->status < 200 || resp->status >= 300) continue;
            auto parsed = decode_json<detail::CfZonesRespWire>(resp->body);
            if (parsed && parsed->success && !parsed->result.empty() && valid_api_id(parsed->result.front().id)) {
                zone_id = parsed->result.front().id;
                break;
            }
        }
        if (zone_id.empty()) return std::unexpected("Cloudflare DNS-01 zone not found for " + *norm);

        auto create_url = std::format("{}/zones/{}/dns_records", api_base_, zone_id);
        auto body = std::format(R"({{"type":"TXT","name":"_acme-challenge.{}","content":"{}","ttl":60}})",
                                *norm, txt_value);
        auto resp = http({"POST", create_url, "application/json", body, auth});
        if (!resp) return std::unexpected("Cloudflare create TXT failed: " + resp.error());
        if (resp->status < 200 || resp->status >= 300)
            return std::unexpected(std::format("Cloudflare create TXT HTTP {}", resp->status));
        auto created = decode_json<detail::CfCreateRespWire>(resp->body);
        if (!created || !created->success || !valid_api_id(created->result.id))
            return std::unexpected("Cloudflare create TXT rejected or missing record id");
        return Dns01RecordHandle{std::move(zone_id), std::move(created->result.id)};
    }

    auto CloudflareDns01Provider::cleanup(Dns01RecordHandle const& handle, HttpExchangeFn http) const
        -> std::expected<void, std::string> {
        if (api_token_.empty() || !valid_api_id(handle.zone) || !valid_api_id(handle.record_id))
            return std::unexpected("Cloudflare DNS-01 invalid cleanup handle");
        std::vector<std::pair<std::string, std::string>> auth{{"Authorization", "Bearer " + api_token_}};
        struct WipeAuth {
            std::string& s;
            ~WipeAuth() { if (!s.empty()) crypto::cleanse({reinterpret_cast<std::uint8_t*>(s.data()), s.size()}); }
        } wipe_auth{auth[0].second};
        auto url = std::format("{}/zones/{}/dns_records/{}", api_base_, handle.zone, handle.record_id);
        auto resp = http({"DELETE", url, {}, {}, auth});
        if (!resp) return std::unexpected("Cloudflare delete TXT failed: " + resp.error());
        if (resp->status < 200 || resp->status >= 300)
            return std::unexpected(std::format("Cloudflare delete TXT HTTP {}", resp->status));
        if (!resp->body.empty()) {
            auto parsed = decode_json<detail::CfDeleteRespWire>(resp->body);
            if (!parsed || !parsed->success) return std::unexpected("Cloudflare delete TXT returned success=false");
        }
        return {};
    }

    AliDns01Provider::AliDns01Provider(std::string access_key_id, std::string access_key_secret, std::string api_base)
        : access_key_id_(std::move(access_key_id)), access_key_secret_(std::move(access_key_secret)),
          api_base_(trim_trailing_slash(std::move(api_base))) {}

    auto AliDns01Provider::publish(std::string_view domain, std::string_view txt_value, HttpExchangeFn http,
                                   std::string_view timestamp_utc, std::string_view nonce) const
        -> std::expected<Dns01RecordHandle, std::string> {
        if (access_key_id_.empty() || access_key_secret_.empty() || api_base_.empty())
            return std::unexpected("AliDNS DNS-01 missing credentials");
        auto norm = normalize_acme_domain(domain);
        if (!norm) return std::unexpected(norm.error());
        if (!valid_txt_value(txt_value)) return std::unexpected("invalid DNS-01 TXT value");

        auto call_rpc = [&](std::vector<std::pair<std::string, std::string>> params)
            -> std::expected<HttpResponse, std::string> {
            std::string ts = timestamp_utc.empty() ? utc_iso8601_now() : std::string(timestamp_utc);
            std::string sn;
            if (!nonce.empty()) sn = std::string(nonce);
            else {
                auto gen = random_nonce_hex();
                if (!gen) return std::unexpected(gen.error());
                sn = std::move(*gen);
            }
            params.emplace_back("AccessKeyId", access_key_id_);
            params.emplace_back("Format", "JSON");
            params.emplace_back("SignatureMethod", "HMAC-SHA1");
            params.emplace_back("SignatureNonce", std::move(sn));
            params.emplace_back("SignatureVersion", "1.0");
            params.emplace_back("Timestamp", std::move(ts));
            params.emplace_back("Version", "2015-01-09");
            auto query = alidns_build_signed_query(params, access_key_secret_, "GET");
            if (!query) return std::unexpected(query.error());
            auto url = std::format("{}/?{}", api_base_, *query);
            return http({"GET", url, {}, {}, {}});
        };

        std::string zone;
        for (auto cand : parent_zones(*norm)) {
            auto resp = call_rpc({{"Action", "DescribeDomainInfo"}, {"DomainName", std::string(cand)}});
            if (!resp) return std::unexpected("AliDNS zone lookup failed: " + resp.error());
            if (resp->status < 200 || resp->status >= 300) continue;
            auto info = decode_json<detail::AliDomainInfoWire>(resp->body);
            if (info && info->Code.empty() && !info->DomainName.empty()) {
                auto norm_zone = normalize_acme_domain(info->DomainName);
                if (!norm_zone) continue;
                if (*norm == *norm_zone ||
                    (norm->size() > norm_zone->size() + 1 &&
                     norm->ends_with(*norm_zone) &&
                     (*norm)[norm->size() - norm_zone->size() - 1] == '.')) {
                    zone = std::move(*norm_zone);
                    break;
                }
            }
        }
        if (zone.empty()) return std::unexpected("AliDNS DNS-01 zone not found for " + *norm);

        std::string rr = (*norm == zone)
            ? std::string("_acme-challenge")
            : std::format("_acme-challenge.{}", std::string_view(*norm).substr(0, norm->size() - zone.size() - 1));
        auto resp = call_rpc({
            {"Action", "AddDomainRecord"},
            {"DomainName", zone},
            {"RR", rr},
            {"TTL", "600"},
            {"Type", "TXT"},
            {"Value", std::string(txt_value)},
        });
        if (!resp) return std::unexpected("AliDNS AddDomainRecord failed: " + resp.error());
        if (resp->status < 200 || resp->status >= 300)
            return std::unexpected(std::format("AliDNS AddDomainRecord HTTP {}", resp->status));
        auto added = decode_json<detail::AliAddRecordWire>(resp->body);
        if (!added || !added->Code.empty() || !valid_api_id(added->RecordId))
            return std::unexpected("AliDNS AddDomainRecord rejected or missing RecordId");
        return Dns01RecordHandle{std::move(zone), std::move(added->RecordId)};
    }

    auto AliDns01Provider::cleanup(Dns01RecordHandle const& handle, HttpExchangeFn http,
                                   std::string_view timestamp_utc, std::string_view nonce) const
        -> std::expected<void, std::string> {
        if (access_key_id_.empty() || access_key_secret_.empty() || !valid_api_id(handle.record_id))
            return std::unexpected("AliDNS DNS-01 invalid cleanup handle");
        std::string ts = timestamp_utc.empty() ? utc_iso8601_now() : std::string(timestamp_utc);
        std::string sn;
        if (!nonce.empty()) sn = std::string(nonce);
        else {
            auto gen = random_nonce_hex();
            if (!gen) return std::unexpected(gen.error());
            sn = std::move(*gen);
        }
        std::vector<std::pair<std::string, std::string>> params{
            {"AccessKeyId", access_key_id_},
            {"Action", "DeleteDomainRecord"},
            {"Format", "JSON"},
            {"RecordId", handle.record_id},
            {"SignatureMethod", "HMAC-SHA1"},
            {"SignatureNonce", std::move(sn)},
            {"SignatureVersion", "1.0"},
            {"Timestamp", std::move(ts)},
            {"Version", "2015-01-09"},
        };
        auto query = alidns_build_signed_query(params, access_key_secret_, "GET");
        if (!query) return std::unexpected(query.error());
        auto url = std::format("{}/?{}", api_base_, *query);
        auto resp = http({"GET", url, {}, {}, {}});
        if (!resp) return std::unexpected("AliDNS DeleteDomainRecord failed: " + resp.error());
        if (resp->status < 200 || resp->status >= 300)
            return std::unexpected(std::format("AliDNS DeleteDomainRecord HTTP {}", resp->status));
        if (!resp->body.empty()) {
            auto del = decode_json<detail::AliDelRecordWire>(resp->body);
            if (!del || !del->Code.empty()) return std::unexpected("AliDNS DeleteDomainRecord returned error");
        }
        return {};
    }
}
