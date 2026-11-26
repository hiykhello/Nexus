module;

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

module desktop.workspace_store;

import std;
import desktop.mini_json;
import desktop.workspace_models;

#include "workspace_json_codec.hpp"

namespace desktop {
    namespace {
        auto trim_ws(std::string_view sv) noexcept -> std::string_view {
            while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.front()))) sv.remove_prefix(1);
            while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.back()))) sv.remove_suffix(1);
            return sv;
        }

        auto lower_ascii_str(std::string_view sv) -> std::string {
            std::string out(sv.size(), '\0');
            for (std::size_t i = 0; i < sv.size(); ++i) {
                out[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(sv[i])));
            }
            return out;
        }

        auto sanitize_title(std::string_view raw) -> std::string {
            std::string out;
            out.reserve(raw.size());
            for (unsigned char c : raw) {
                if (c >= 0x20u && c != 0x7Fu) out.push_back(static_cast<char>(c));
            }
            return std::string(trim_ws(out));
        }

        auto read_file_str(std::filesystem::path const& p) -> std::string {
            std::ifstream in(p, std::ios::binary);
            if (!in) return {};
            std::ostringstream ss;
            ss << in.rdbuf();
            return ss.str();
        }

        auto write_file_0600_atomic(std::filesystem::path const& path, std::string_view content) -> bool {
            std::error_code ec;
            if (!path.parent_path().empty()) std::filesystem::create_directories(path.parent_path(), ec);
            static std::atomic<std::uint64_t> seq{0};
#ifdef _WIN32
            auto tmp = path;
            tmp += std::format(".tmp.{}.{}", ::GetCurrentProcessId(), seq.fetch_add(1, std::memory_order_relaxed));
            {
                std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
                if (!out) return false;
                out.write(content.data(), static_cast<std::streamsize>(content.size()));
                if (!out.good()) { out.close(); std::filesystem::remove(tmp, ec); return false; }
            }
            if (!::MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                std::filesystem::remove(tmp, ec);
                return false;
            }
            return true;
#else
            auto tmp = path.parent_path() /
                std::format(".{}.tmp.{}.{}", path.filename().string(), ::getpid(), seq.fetch_add(1, std::memory_order_relaxed));
            int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
            if (fd < 0) return false;
            if (::fchmod(fd, 0600) != 0) { ::close(fd); ::unlink(tmp.c_str()); return false; }
            std::size_t off = 0;
            while (off < content.size()) {
                auto n = ::write(fd, content.data() + off, content.size() - off);
                if (n < 0 && errno == EINTR) continue;
                if (n <= 0) { ::close(fd); ::unlink(tmp.c_str()); return false; }
                off += static_cast<std::size_t>(n);
            }
            bool closed = (::close(fd) == 0);
            if (!closed || std::rename(tmp.c_str(), path.c_str()) != 0) { ::unlink(tmp.c_str()); return false; }
            return true;
#endif
        }

        // 5-tier identity keys for subscription replacement
        auto tier1_key(WorkspaceProfileItem const& p) -> std::string {
            auto const& n = p.node;
            return std::format("{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
                n.protocol, n.server, n.port, n.username, n.password, n.method, n.flow,
                n.tls.sni, n.tls.reality_public_key, n.transport.type, n.transport.path, p.remarks);
        }
        auto tier2_key(WorkspaceProfileItem const& p) -> std::string {
            auto const& n = p.node;
            return std::format("{}|{}|{}|{}|{}|{}|{}|{}|{}",
                n.protocol, n.server, n.port, n.username, n.password, n.method,
                n.tls.sni, n.transport.type, n.transport.path);
        }
        auto tier3_key(WorkspaceProfileItem const& p) -> std::string {
            return std::format("{}|{}|{}|{}", p.node.protocol, p.node.server, p.node.port, p.remarks);
        }
        auto tier4_key(WorkspaceProfileItem const& p) -> std::string {
            return std::format("{}|{}|{}", p.node.protocol, p.node.server, p.node.port);
        }
        auto tier5_key(WorkspaceProfileItem const& p) -> std::string {
            return p.remarks;
        }
    }

    auto sanitize_workspace_id(std::string_view raw) -> std::string {
        std::string out;
        for (unsigned char ch : raw) {
            if (std::isalnum(ch) || ch == '-' || ch == '_') out.push_back(static_cast<char>(std::tolower(ch)));
            else if ((ch == ' ' || ch == '.' || ch == '/') && !out.empty() && out.back() != '-') out.push_back('-');
            if (out.size() >= 64) break;
        }
        while (!out.empty() && out.back() == '-') out.pop_back();
        return out.empty() ? "item" : out;
    }

    auto make_default_workspace() -> WorkspaceDocument {
        WorkspaceDocument doc{};
        doc.schema_version = 1;
        doc.revision = 1;
        doc.subscriptions.push_back({.id = "manual", .remarks = "Manual", .url = "", .enabled = true});

        RoutingProfile bypass{.id = "bypass-lan-cn", .name = "Bypass LAN & Private", .is_active = true,
                              .domain_strategy = "as-is", .default_outbound = "proxy"};
        bypass.rules.push_back({.id = "r-private-ip", .enabled = true, .locked = true, .scope = "routing_only",
                                .target_type = "direct", .ips = {"10.0.0.0/8", "127.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}});
        bypass.rules.push_back({.id = "r-local-dom", .enabled = true, .locked = true, .scope = "both",
                                .target_type = "direct", .domains = {"localhost", "local"}});
        doc.routing_profiles.push_back(std::move(bypass));
        doc.routing_profiles.push_back({.id = "global", .name = "Global Proxy", .is_active = false, .default_outbound = "proxy"});
        doc.routing_profiles.push_back({.id = "direct", .name = "Direct All", .is_active = false, .default_outbound = "direct"});
        return doc;
    }

    auto workspace_to_json(WorkspaceDocument const& doc) -> std::string {
        JsonArray profiles, subs, routings, assets;
        profiles.reserve(doc.profiles.size());
        for (auto const& p : doc.profiles) profiles.push_back(ws_codec::profile_to_json(p));
        subs.reserve(doc.subscriptions.size());
        for (auto const& s : doc.subscriptions) subs.push_back(ws_codec::sub_to_json(s));
        routings.reserve(doc.routing_profiles.size());
        for (auto const& r : doc.routing_profiles) routings.push_back(ws_codec::routing_to_json(r));
        assets.reserve(doc.rule_set_assets.size());
        for (auto const& a : doc.rule_set_assets) {
            assets.emplace_back(JsonObject{
                {"tag", a.tag}, {"source_type", a.source_type}, {"format", a.format},
                {"path", a.path}, {"url", a.url}, {"sha256", a.sha256}, {"update_interval_ms", a.update_interval_ms},
            });
        }
        JsonObject root{
            {"schema_version", doc.schema_version},
            {"revision", doc.revision},
            {"updated_at_ms", doc.updated_at_ms},
            {"profiles", JsonValue(std::move(profiles))},
            {"subscriptions", JsonValue(std::move(subs))},
            {"routing_profiles", JsonValue(std::move(routings))},
            {"dns", ws_codec::dns_to_json(doc.dns)},
            {"rule_set_assets", JsonValue(std::move(assets))},
            {"full_template", JsonObject{
                {"enabled", doc.full_template.enabled},
                {"template_kdl", doc.full_template.template_kdl},
                {"append_proxies_only", doc.full_template.append_proxies_only},
                {"proxy_detour", doc.full_template.proxy_detour},
            }},
        };
        return json_stringify(JsonValue(std::move(root)), true);
    }

    auto workspace_from_json(std::string_view text) -> std::expected<WorkspaceDocument, std::string> {
        auto parsed = json_parse(text);
        if (!parsed) return std::unexpected(parsed.error());
        if (!parsed->is_object()) return std::unexpected("workspace.json root must be a JSON object");
        auto const& root = std::get<JsonObject>(parsed->data);
        WorkspaceDocument doc{};
        doc.schema_version = json_get_i64(root, "schema_version", 1);
        if (doc.schema_version != 1) return std::unexpected("unsupported workspace.json schema_version");
        doc.revision = json_get_i64(root, "revision", 1);
        doc.updated_at_ms = json_get_i64(root, "updated_at_ms", 0);

        if (auto const* arr = json_find(root, "profiles"); arr && arr->is_array()) {
            for (auto const& e : std::get<JsonArray>(arr->data)) {
                if (e.is_object()) doc.profiles.push_back(ws_codec::profile_from_json(std::get<JsonObject>(e.data)));
            }
        }
        if (auto const* arr = json_find(root, "subscriptions"); arr && arr->is_array()) {
            for (auto const& e : std::get<JsonArray>(arr->data)) {
                if (!e.is_object()) continue;
                auto sub = ws_codec::sub_from_json(std::get<JsonObject>(e.data));
                if (!sub.url.empty() && !is_safe_subscription_link(sub.url)) sub.url.clear();
                std::erase_if(sub.more_urls, [](std::string const& u) { return !is_safe_subscription_link(u); });
                if (!sub.usage.web_page_url.empty() && !is_safe_subscription_link(sub.usage.web_page_url)) sub.usage.web_page_url.clear();
                if (!sub.usage.support_url.empty() && !is_safe_subscription_link(sub.usage.support_url)) sub.usage.support_url.clear();
                doc.subscriptions.push_back(std::move(sub));
            }
        }
        if (auto const* arr = json_find(root, "routing_profiles"); arr && arr->is_array()) {
            for (auto const& e : std::get<JsonArray>(arr->data)) {
                if (e.is_object()) doc.routing_profiles.push_back(ws_codec::routing_from_json(std::get<JsonObject>(e.data)));
            }
        }
        if (auto const* v = json_find(root, "dns"); v && v->is_object()) {
            doc.dns = ws_codec::dns_from_json(std::get<JsonObject>(v->data));
        }
        if (auto const* arr = json_find(root, "rule_set_assets"); arr && arr->is_array()) {
            for (auto const& e : std::get<JsonArray>(arr->data)) {
                if (!e.is_object()) continue;
                auto const& a = std::get<JsonObject>(e.data);
                doc.rule_set_assets.push_back({
                    json_get_string(a, "tag"), json_get_string(a, "source_type", "local"),
                    json_get_string(a, "format", "srs"), json_get_string(a, "path"),
                    json_get_string(a, "url"), json_get_string(a, "sha256"), json_get_i64(a, "update_interval_ms"),
                });
            }
        }
        if (auto const* v = json_find(root, "full_template"); v && v->is_object()) {
            auto const& f = std::get<JsonObject>(v->data);
            doc.full_template = {json_get_bool(f, "enabled"), json_get_string(f, "template_kdl"),
                                 json_get_bool(f, "append_proxies_only"), json_get_string(f, "proxy_detour")};
        }
        return doc;
    }

    auto load_workspace(std::filesystem::path const& path) -> std::expected<WorkspaceDocument, std::string> {
        std::error_code ec;
        if (!std::filesystem::is_regular_file(path, ec)) return make_default_workspace();
        auto text = read_file_str(path);
        if (text.empty()) return make_default_workspace();
        return workspace_from_json(text);
    }

    auto save_workspace_atomic(std::filesystem::path const& path, WorkspaceDocument const& doc) -> bool {
        return write_file_0600_atomic(path, workspace_to_json(doc));
    }

    auto is_safe_subscription_link(std::string_view url) noexcept -> bool {
        auto sv = trim_ws(url);
        if (sv.empty() || sv.size() > 2048) return false;
        for (unsigned char c : sv) if (c < 0x20u || c == 0x7Fu) return false;
        auto starts_ci = [](std::string_view s, std::string_view pfx) noexcept -> bool {
            if (s.size() < pfx.size()) return false;
            for (std::size_t i = 0; i < pfx.size(); ++i) {
                unsigned char a = static_cast<unsigned char>(s[i]);
                if (a >= 'A' && a <= 'Z') a = static_cast<unsigned char>(a + ('a' - 'A'));
                if (a != static_cast<unsigned char>(pfx[i])) return false;
            }
            return true;
        };
        return starts_ci(sv, "https://") || starts_ci(sv, "http://") || starts_ci(sv, "tg://");
    }

    auto parse_subscription_headers(std::span<std::pair<std::string, std::string> const> headers) -> SubscriptionUsage {
        SubscriptionUsage u{};
        for (auto const& [raw_k, raw_v] : headers) {
            auto k = lower_ascii_str(trim_ws(raw_k));
            auto v = trim_ws(raw_v);
            if (k == "subscription-userinfo") {
                std::string_view rem = v;
                while (!rem.empty()) {
                    auto semi = rem.find(';');
                    auto tok = trim_ws(semi == std::string_view::npos ? rem : rem.substr(0, semi));
                    rem = semi == std::string_view::npos ? std::string_view{} : rem.substr(semi + 1);
                    auto eq = tok.find('=');
                    if (eq == std::string_view::npos) continue;
                    auto fk = lower_ascii_str(trim_ws(tok.substr(0, eq)));
                    auto fv = trim_ws(tok.substr(eq + 1));
                    std::int64_t num = 0;
                    auto [ptr, ec] = std::from_chars(fv.data(), fv.data() + fv.size(), num, 10);
                    if (ec != std::errc{} || ptr != fv.data() + fv.size() || num < 0) continue;
                    if (fk == "upload") u.upload_bytes = num;
                    else if (fk == "download") u.download_bytes = num;
                    else if (fk == "total") u.total_bytes = num;
                    else if (fk == "expire") u.expire_unix_sec = num;
                }
            } else if (k == "profile-title") {
                auto low_v = lower_ascii_str(v.substr(0, std::min<std::size_t>(v.size(), 7)));
                if (low_v == "base64:") {
                    if (auto dec = ws_codec::decode_base64_str(v.substr(7))) u.profile_title = sanitize_title(*dec);
                } else {
                    u.profile_title = sanitize_title(ws_codec::percent_decode_str(v));
                }
            } else if (k == "profile-web-page-url" && is_safe_subscription_link(v)) {
                u.web_page_url = std::string(v);
            } else if (k == "support-url" && is_safe_subscription_link(v)) {
                u.support_url = std::string(v);
            }
        }
        return u;
    }

    auto replace_subscription_profiles(
        WorkspaceDocument& doc,
        std::string_view subscription_id,
        std::vector<WorkspaceProfileItem> incoming,
        std::string& active_profile_id,
        std::filesystem::path const& secrets_dir,
        std::unordered_set<std::string> const& referenced_secret_paths,
        bool allow_secret_gc) -> SubscriptionReplaceResult {
        SubscriptionReplaceResult res{};
        if (subscription_id.empty()) { res.message = "subscription_id required"; return res; }
        if (incoming.empty()) {
            res.message = "fail-closed: incoming subscription node list is empty; existing nodes kept";
            return res;
        }
        std::vector<WorkspaceProfileItem> kept, old_sub;
        kept.reserve(doc.profiles.size());
        for (auto& p : doc.profiles) {
            if (p.is_from_sub && p.subscription_id == subscription_id && p.kind == "node") old_sub.push_back(std::move(p));
            else kept.push_back(std::move(p));
        }
        std::vector<bool> old_used(old_sub.size(), false), in_matched(incoming.size(), false);
        std::unordered_set<std::string> used_ids;
        for (auto const& k : kept) used_ids.insert(k.id);

        auto run_tier = [&](auto key_fn, bool unique_only) {
            std::unordered_map<std::string, std::vector<std::size_t>> old_buckets;
            std::unordered_map<std::string, std::size_t> in_counts;
            for (std::size_t oi = 0; oi < old_sub.size(); ++oi) {
                if (!old_used[oi]) if (auto k = key_fn(old_sub[oi]); !k.empty()) old_buckets[std::move(k)].push_back(oi);
            }
            if (unique_only) {
                for (std::size_t ii = 0; ii < incoming.size(); ++ii) {
                    if (!in_matched[ii]) if (auto k = key_fn(incoming[ii]); !k.empty()) ++in_counts[std::move(k)];
                }
            }
            for (std::size_t ii = 0; ii < incoming.size(); ++ii) {
                if (in_matched[ii]) continue;
                auto k = key_fn(incoming[ii]);
                if (unique_only && in_counts[k] != 1) continue;
                auto it = old_buckets.find(k);
                if (it == old_buckets.end()) continue;
                std::size_t avail_count = 0, first_oi = 0;
                for (std::size_t oi : it->second) if (!old_used[oi]) { if (avail_count == 0) first_oi = oi; ++avail_count; }
                if (avail_count == 0 || (unique_only && avail_count != 1)) continue;
                old_used[first_oi] = true; in_matched[ii] = true;
                incoming[ii].id = old_sub[first_oi].id;
                incoming[ii].subscription_id = std::string(subscription_id);
                incoming[ii].is_from_sub = true;
                used_ids.insert(incoming[ii].id);
                ++res.matched_count;
            }
        };
        run_tier(tier1_key, false); run_tier(tier2_key, false); run_tier(tier3_key, false);
        run_tier(tier4_key, true);  run_tier(tier5_key, true);

        std::size_t seq = 1;
        for (std::size_t ii = 0; ii < incoming.size(); ++ii) {
            incoming[ii].subscription_id = std::string(subscription_id);
            incoming[ii].is_from_sub = true;
            if (!in_matched[ii]) {
                std::string base = incoming[ii].id.empty()
                    ? (sanitize_workspace_id(subscription_id) + "-" + sanitize_workspace_id(incoming[ii].remarks))
                    : sanitize_workspace_id(incoming[ii].id);
                std::string cand = base;
                while (used_ids.contains(cand)) cand = base + "-" + std::to_string(seq++);
                incoming[ii].id = std::move(cand);
                used_ids.insert(incoming[ii].id);
                ++res.added_count;
            }
            kept.push_back(std::move(incoming[ii]));
        }
        for (bool u : old_used) if (!u) ++res.removed_count;
        doc.profiles = std::move(kept);
        ++doc.revision;
        if (!active_profile_id.empty() && !used_ids.contains(active_profile_id)) {
            active_profile_id = doc.profiles.empty() ? std::string{} : doc.profiles.front().id;
        }

        // Fail-closed orphan secret GC (.secret / .pem / .ech; never deletes control-http.token or live refs)
        bool has_node_secrets = false;
        for (auto const& p : doc.profiles) {
            if (p.kind == "node" && (!p.node.password.empty() || !p.node.username.empty() ||
                                     !p.node.tls.ca_pem.empty() || !p.node.tls.ech_config.empty())) {
                has_node_secrets = true; break;
            }
        }
        std::error_code ec;
        if (allow_secret_gc && (!has_node_secrets || !referenced_secret_paths.empty()) &&
            !secrets_dir.empty() && std::filesystem::is_directory(secrets_dir, ec)) {
            for (auto const& ent : std::filesystem::directory_iterator(secrets_dir, ec)) {
                if (ec || !ent.is_regular_file(ec)) continue;
                auto const fname = ent.path().filename().string();
                if (!fname.ends_with(".secret") && !fname.ends_with(".pem") && !fname.ends_with(".ech")) continue;
                auto const u8 = ent.path().u8string();
                std::string full(reinterpret_cast<char const*>(u8.data()), u8.size());
                bool referenced = referenced_secret_paths.contains(full) || referenced_secret_paths.contains(fname);
                if (!referenced) {
                    for (auto const& p : doc.profiles) {
                        if (p.custom_outbound_kdl.contains(fname) || p.full_custom_kdl.contains(fname)) { referenced = true; break; }
                    }
                }
                if (!referenced && std::filesystem::remove(ent.path(), ec)) ++res.secrets_pruned;
            }
        }
        res.ok = true;
        return res;
    }
}
