module;

#include "sqlite3.h"

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

module desktop.client_db;

import std;
import desktop.mini_json;
import desktop.workspace_models;
import desktop.workspace_store;

#include "workspace_json_codec.hpp"
#include "client_db_schema.hpp"

namespace desktop {
    using namespace db_detail;

    ClientDatabase::Impl::~Impl() {
        if (db) {
            ::sqlite3_close_v2(db);
            db = nullptr;
        }
    }

    ClientDatabase::ClientDatabase(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
    ClientDatabase::~ClientDatabase() = default;
    ClientDatabase::ClientDatabase(ClientDatabase&&) noexcept = default;
    auto ClientDatabase::operator=(ClientDatabase&&) noexcept -> ClientDatabase& = default;

    auto ClientDatabase::path(this ClientDatabase const& self) noexcept -> std::filesystem::path const& {
        static std::filesystem::path const kEmpty{};
        return self.impl_ ? self.impl_->db_path : kEmpty;
    }

    auto ClientDatabase::open(std::filesystem::path const& db_path) -> std::expected<ClientDatabase, std::string> {
        if (db_path.empty()) return std::unexpected("empty sqlite database path");
        std::error_code ec;
        if (!db_path.parent_path().empty()) std::filesystem::create_directories(db_path.parent_path(), ec);
        precreate_private_file(db_path);

        auto impl = std::make_unique<Impl>();
        impl->db_path = db_path;
        auto const utf8 = path_to_utf8(db_path);
        int rc = ::sqlite3_open_v2(
            utf8.c_str(), &impl->db,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr);
        if (rc != SQLITE_OK || !impl->db) {
            auto msg = sqlite_err_msg(impl->db, "sqlite3_open_v2");
            return std::unexpected(std::move(msg));
        }

        if (auto pr = exec_sql(impl->db, kPragmasSql); !pr) return std::unexpected(pr.error());

        int cur_ver = 0;
        if (auto st = prepare_stmt(impl->db, "PRAGMA user_version;"); st) {
            if (::sqlite3_step(st->get()) == SQLITE_ROW) cur_ver = ::sqlite3_column_int(st->get(), 0);
        } else {
            return std::unexpected(st.error());
        }
        if (cur_ver > kClientDbSchemaVersion) {
            return std::unexpected(std::format("unsupported client db user_version {}", cur_ver));
        }
        if (cur_ver < kClientDbSchemaVersion) {
            TxGuard tx(impl->db);
            if (auto b = tx.begin(); !b) return std::unexpected(b.error());
            if (auto s = exec_sql(impl->db, kSchemaV1Sql); !s) return std::unexpected(s.error());
            if (auto c = tx.commit(); !c) return std::unexpected(c.error());
        }
        ensure_private_db_perms(db_path);
        return ClientDatabase(std::move(impl));
    }

    auto ClientDatabase::user_version(this ClientDatabase& self) -> std::expected<int, std::string> {
        if (!self.impl_ || !self.impl_->db) return std::unexpected("sqlite database is closed");
        std::scoped_lock lk(self.impl_->mu);
        auto st = prepare_stmt(self.impl_->db, "PRAGMA user_version;");
        if (!st) return std::unexpected(st.error());
        if (::sqlite3_step(st->get()) != SQLITE_ROW) return std::unexpected("failed to read user_version");
        return ::sqlite3_column_int(st->get(), 0);
    }

    auto ClientDatabase::has_workspace_data(this ClientDatabase& self) -> std::expected<bool, std::string> {
        if (!self.impl_ || !self.impl_->db) return std::unexpected("sqlite database is closed");
        std::scoped_lock lk(self.impl_->mu);
        auto st = prepare_stmt(
            self.impl_->db,
            "SELECT (SELECT COUNT(*) FROM profiles) + (SELECT COUNT(*) FROM subscriptions) "
            "+ (SELECT COUNT(*) FROM routing_profiles) + (SELECT COUNT(*) FROM workspace_meta);");
        if (!st) return std::unexpected(st.error());
        if (::sqlite3_step(st->get()) != SQLITE_ROW) return false;
        return ::sqlite3_column_int64(st->get(), 0) > 0;
    }

    auto ClientDatabase::save_workspace(this ClientDatabase& self, WorkspaceDocument const& doc)
        -> std::expected<void, std::string> {
        if (!self.impl_ || !self.impl_->db) return std::unexpected("sqlite database is closed");
        std::scoped_lock lk(self.impl_->mu);
        TxGuard tx(self.impl_->db);
        if (auto b = tx.begin(); !b) return std::unexpected(b.error());

        std::unordered_set<std::string> pinned_ids;
        if (auto ps = prepare_stmt(self.impl_->db, "SELECT id FROM profiles WHERE pinned != 0;"); ps) {
            while (::sqlite3_step(ps->get()) == SQLITE_ROW) pinned_ids.insert(col_text(ps->get(), 0));
        }

        if (auto clr = exec_sql(self.impl_->db,
            "DELETE FROM subscriptions; DELETE FROM profiles; DELETE FROM routing_profiles;"); !clr) {
            return std::unexpected(clr.error());
        }

        auto sub_st = prepare_stmt(
            self.impl_->db,
            "INSERT INTO subscriptions(id, name, url, enabled, sort_order, payload_json, updated_at) "
            "VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7);");
        if (!sub_st) return std::unexpected(sub_st.error());
        for (std::size_t i = 0; i < doc.subscriptions.size(); ++i) {
            auto const& s = doc.subscriptions[i];
            auto payload = json_stringify(ws_codec::sub_to_json(s), false);
            ::sqlite3_reset(sub_st->get());
            bind_text(sub_st->get(), 1, s.id);
            bind_text(sub_st->get(), 2, s.remarks.empty() ? s.id : s.remarks);
            bind_text(sub_st->get(), 3, s.url);
            ::sqlite3_bind_int(sub_st->get(), 4, s.enabled ? 1 : 0);
            ::sqlite3_bind_int64(sub_st->get(), 5, static_cast<sqlite3_int64>(i));
            bind_text(sub_st->get(), 6, payload);
            ::sqlite3_bind_int64(sub_st->get(), 7, s.updated_at_ms);
            if (::sqlite3_step(sub_st->get()) != SQLITE_DONE) {
                return std::unexpected(sqlite_err_msg(self.impl_->db, "insert subscription"));
            }
        }

        auto prof_st = prepare_stmt(
            self.impl_->db,
            "INSERT INTO profiles(id, kind, subscription_id, name, protocol, server, port, sort_order, pinned, updated_at) "
            "VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10);");
        if (!prof_st) return std::unexpected(prof_st.error());
        auto pay_st = prepare_stmt(
            self.impl_->db,
            "INSERT INTO profile_payloads(profile_id, payload_json) VALUES(?1, ?2);");
        if (!pay_st) return std::unexpected(pay_st.error());

        for (std::size_t i = 0; i < doc.profiles.size(); ++i) {
            auto const& p = doc.profiles[i];
            auto payload = json_stringify(ws_codec::profile_to_json(p), false);
            ::sqlite3_reset(prof_st->get());
            bind_text(prof_st->get(), 1, p.id);
            bind_text(prof_st->get(), 2, p.kind);
            bind_text(prof_st->get(), 3, p.subscription_id);
            bind_text(prof_st->get(), 4, p.remarks.empty() ? p.id : p.remarks);
            bind_text(prof_st->get(), 5, p.kind == "node" ? std::string_view(p.node.protocol) : std::string_view{});
            bind_text(prof_st->get(), 6, p.kind == "node" ? std::string_view(p.node.server) : std::string_view{});
            ::sqlite3_bind_int64(prof_st->get(), 7, p.kind == "node" ? p.node.port : 0);
            ::sqlite3_bind_int64(prof_st->get(), 8, static_cast<sqlite3_int64>(i));
            ::sqlite3_bind_int(prof_st->get(), 9, pinned_ids.contains(p.id) ? 1 : 0);
            ::sqlite3_bind_int64(prof_st->get(), 10, doc.updated_at_ms);
            if (::sqlite3_step(prof_st->get()) != SQLITE_DONE) {
                return std::unexpected(sqlite_err_msg(self.impl_->db, "insert profile"));
            }
            ::sqlite3_reset(pay_st->get());
            bind_text(pay_st->get(), 1, p.id);
            bind_text(pay_st->get(), 2, payload);
            if (::sqlite3_step(pay_st->get()) != SQLITE_DONE) {
                return std::unexpected(sqlite_err_msg(self.impl_->db, "insert profile_payload"));
            }
        }

        auto rt_st = prepare_stmt(
            self.impl_->db,
            "INSERT INTO routing_profiles(id, name, sort_order, payload_json, updated_at) "
            "VALUES(?1, ?2, ?3, ?4, ?5);");
        if (!rt_st) return std::unexpected(rt_st.error());
        std::string active_routing_id;
        for (std::size_t i = 0; i < doc.routing_profiles.size(); ++i) {
            auto const& r = doc.routing_profiles[i];
            if (r.is_active && active_routing_id.empty()) active_routing_id = r.id;
            auto payload = json_stringify(ws_codec::routing_to_json(r), false);
            ::sqlite3_reset(rt_st->get());
            bind_text(rt_st->get(), 1, r.id);
            bind_text(rt_st->get(), 2, r.name.empty() ? r.id : r.name);
            ::sqlite3_bind_int64(rt_st->get(), 3, static_cast<sqlite3_int64>(i));
            bind_text(rt_st->get(), 4, payload);
            ::sqlite3_bind_int64(rt_st->get(), 5, doc.updated_at_ms);
            if (::sqlite3_step(rt_st->get()) != SQLITE_DONE) {
                return std::unexpected(sqlite_err_msg(self.impl_->db, "insert routing_profile"));
            }
        }

        auto meta_st = prepare_stmt(
            self.impl_->db,
            "INSERT INTO workspace_meta(key, value_json) VALUES(?1, ?2) "
            "ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json;");
        if (!meta_st) return std::unexpected(meta_st.error());
        auto put_meta = [&](std::string_view k, std::string_view v) -> std::expected<void, std::string> {
            ::sqlite3_reset(meta_st->get());
            bind_text(meta_st->get(), 1, k);
            bind_text(meta_st->get(), 2, v);
            if (::sqlite3_step(meta_st->get()) != SQLITE_DONE) {
                return std::unexpected(sqlite_err_msg(self.impl_->db, "upsert workspace_meta"));
            }
            return {};
        };

        JsonArray assets;
        assets.reserve(doc.rule_set_assets.size());
        for (auto const& a : doc.rule_set_assets) {
            assets.emplace_back(JsonObject{
                {"tag", a.tag}, {"source_type", a.source_type}, {"format", a.format},
                {"path", a.path}, {"url", a.url}, {"sha256", a.sha256}, {"update_interval_ms", a.update_interval_ms},
            });
        }
        JsonValue full_tpl(JsonObject{
            {"enabled", doc.full_template.enabled},
            {"template_kdl", doc.full_template.template_kdl},
            {"append_proxies_only", doc.full_template.append_proxies_only},
            {"proxy_detour", doc.full_template.proxy_detour},
        });

        if (auto r = put_meta("schema_version", std::to_string(doc.schema_version)); !r) return r;
        if (auto r = put_meta("sync_revision", std::to_string(doc.revision)); !r) return r;
        if (auto r = put_meta("updated_at_ms", std::to_string(doc.updated_at_ms)); !r) return r;
        if (auto r = put_meta("active_routing_id", json_stringify(JsonValue(active_routing_id), false)); !r) return r;
        if (auto r = put_meta("dns", json_stringify(ws_codec::dns_to_json(doc.dns), false)); !r) return r;
        if (auto r = put_meta("rule_set_assets", json_stringify(JsonValue(std::move(assets)), false)); !r) return r;
        if (auto r = put_meta("full_template", json_stringify(full_tpl, false)); !r) return r;

        auto cr = tx.commit();
        if (cr) ensure_private_db_perms(self.impl_->db_path);
        return cr;
    }

    auto ClientDatabase::load_workspace(this ClientDatabase& self) -> std::expected<WorkspaceDocument, std::string> {
        if (!self.impl_ || !self.impl_->db) return std::unexpected("sqlite database is closed");
        std::scoped_lock lk(self.impl_->mu);
        TxGuard tx(self.impl_->db);
        if (auto b = tx.begin_deferred(); !b) return std::unexpected(b.error());

        WorkspaceDocument doc{};
        std::string active_routing_id;
        bool has_any = false;
        bool has_sync_rev = false;

        if (auto st = prepare_stmt(self.impl_->db, "SELECT key, value_json FROM workspace_meta;"); st) {
            int rc = SQLITE_OK;
            while ((rc = ::sqlite3_step(st->get())) == SQLITE_ROW) {
                has_any = true;
                auto k = col_text(st->get(), 0);
                auto parsed = json_parse(col_text(st->get(), 1));
                if (!parsed) continue;
                if (k == "schema_version" && std::holds_alternative<std::int64_t>(parsed->data)) {
                    doc.schema_version = std::get<std::int64_t>(parsed->data);
                } else if (k == "sync_revision" && std::holds_alternative<std::int64_t>(parsed->data)) {
                    doc.revision = std::get<std::int64_t>(parsed->data);
                    has_sync_rev = true;
                } else if (k == "revision" && !has_sync_rev && std::holds_alternative<std::int64_t>(parsed->data)) {
                    doc.revision = std::get<std::int64_t>(parsed->data);
                } else if (k == "updated_at_ms" && std::holds_alternative<std::int64_t>(parsed->data)) {
                    doc.updated_at_ms = std::get<std::int64_t>(parsed->data);
                } else if (k == "active_routing_id" && std::holds_alternative<std::string>(parsed->data)) {
                    active_routing_id = std::get<std::string>(parsed->data);
                } else if (k == "dns" && parsed->is_object()) {
                    doc.dns = ws_codec::dns_from_json(std::get<JsonObject>(parsed->data));
                } else if (k == "rule_set_assets" && parsed->is_array()) {
                    for (auto const& e : std::get<JsonArray>(parsed->data)) {
                        if (!e.is_object()) continue;
                        auto const& a = std::get<JsonObject>(e.data);
                        doc.rule_set_assets.push_back({
                            json_get_string(a, "tag"), json_get_string(a, "source_type", "local"),
                            json_get_string(a, "format", "srs"), json_get_string(a, "path"),
                            json_get_string(a, "url"), json_get_string(a, "sha256"), json_get_i64(a, "update_interval_ms"),
                        });
                    }
                } else if (k == "full_template" && parsed->is_object()) {
                    auto const& f = std::get<JsonObject>(parsed->data);
                    doc.full_template = {json_get_bool(f, "enabled"), json_get_string(f, "template_kdl"),
                                         json_get_bool(f, "append_proxies_only"), json_get_string(f, "proxy_detour")};
                }
            }
            if (rc != SQLITE_DONE) return std::unexpected(sqlite_err_msg(self.impl_->db, "load workspace_meta"));
        } else {
            return std::unexpected(st.error());
        }

        if (auto st = prepare_stmt(self.impl_->db, "SELECT payload_json FROM subscriptions ORDER BY sort_order ASC, id ASC;"); st) {
            int rc = SQLITE_OK;
            while ((rc = ::sqlite3_step(st->get())) == SQLITE_ROW) {
                has_any = true;
                auto parsed = json_parse(col_text(st->get(), 0));
                if (!parsed || !parsed->is_object()) continue;
                auto sub = ws_codec::sub_from_json(std::get<JsonObject>(parsed->data));
                if (!sub.url.empty() && !is_safe_subscription_link(sub.url)) sub.url.clear();
                std::erase_if(sub.more_urls, [](std::string const& u) { return !is_safe_subscription_link(u); });
                if (!sub.usage.web_page_url.empty() && !is_safe_subscription_link(sub.usage.web_page_url)) sub.usage.web_page_url.clear();
                if (!sub.usage.support_url.empty() && !is_safe_subscription_link(sub.usage.support_url)) sub.usage.support_url.clear();
                doc.subscriptions.push_back(std::move(sub));
            }
            if (rc != SQLITE_DONE) return std::unexpected(sqlite_err_msg(self.impl_->db, "load subscriptions"));
        } else {
            return std::unexpected(st.error());
        }

        if (auto st = prepare_stmt(
            self.impl_->db,
            "SELECT pp.payload_json FROM profiles p "
            "JOIN profile_payloads pp ON pp.profile_id = p.id "
            "ORDER BY p.sort_order ASC, p.id ASC;"); st) {
            int rc = SQLITE_OK;
            while ((rc = ::sqlite3_step(st->get())) == SQLITE_ROW) {
                has_any = true;
                auto parsed = json_parse(col_text(st->get(), 0));
                if (parsed && parsed->is_object()) {
                    doc.profiles.push_back(ws_codec::profile_from_json(std::get<JsonObject>(parsed->data)));
                }
            }
            if (rc != SQLITE_DONE) return std::unexpected(sqlite_err_msg(self.impl_->db, "load profiles"));
        } else {
            return std::unexpected(st.error());
        }

        if (auto st = prepare_stmt(self.impl_->db, "SELECT payload_json FROM routing_profiles ORDER BY sort_order ASC, id ASC;"); st) {
            int rc = SQLITE_OK;
            while ((rc = ::sqlite3_step(st->get())) == SQLITE_ROW) {
                has_any = true;
                auto parsed = json_parse(col_text(st->get(), 0));
                if (parsed && parsed->is_object()) {
                    doc.routing_profiles.push_back(ws_codec::routing_from_json(std::get<JsonObject>(parsed->data)));
                }
            }
            if (rc != SQLITE_DONE) return std::unexpected(sqlite_err_msg(self.impl_->db, "load routing_profiles"));
        } else {
            return std::unexpected(st.error());
        }

        if (auto c = tx.commit(); !c) return std::unexpected(c.error());
        if (!active_routing_id.empty()) {
            bool matched = std::ranges::any_of(doc.routing_profiles, [&](auto const& r) { return r.id == active_routing_id; });
            if (matched) {
                for (auto& rp : doc.routing_profiles) rp.is_active = (rp.id == active_routing_id);
            }
        }
        if (!has_any) return make_default_workspace();
        return doc;
    }

    auto ClientDatabase::list_profile_summaries(
        this ClientDatabase& self,
        std::string_view subscription_id,
        std::string_view kind) -> std::expected<std::vector<ProfileSummary>, std::string> {
        if (!self.impl_ || !self.impl_->db) return std::unexpected("sqlite database is closed");
        std::scoped_lock lk(self.impl_->mu);
        std::string sql =
            "SELECT id, kind, subscription_id, name, protocol, server, port, sort_order, pinned, updated_at "
            "FROM profiles WHERE 1=1";
        if (!subscription_id.empty()) sql += " AND subscription_id = ?1";
        if (!kind.empty()) sql += subscription_id.empty() ? " AND kind = ?1" : " AND kind = ?2";
        sql += " ORDER BY pinned DESC, sort_order ASC, id ASC;";

        auto st = prepare_stmt(self.impl_->db, sql.c_str());
        if (!st) return std::unexpected(st.error());
        int bidx = 1;
        if (!subscription_id.empty()) bind_text(st->get(), bidx++, subscription_id);
        if (!kind.empty()) bind_text(st->get(), bidx++, kind);

        std::vector<ProfileSummary> out;
        int rc = SQLITE_OK;
        while ((rc = ::sqlite3_step(st->get())) == SQLITE_ROW) {
            out.push_back({
                col_text(st->get(), 0), col_text(st->get(), 1), col_text(st->get(), 2), col_text(st->get(), 3),
                col_text(st->get(), 4), col_text(st->get(), 5),
                ::sqlite3_column_int64(st->get(), 6), ::sqlite3_column_int64(st->get(), 7),
                ::sqlite3_column_int(st->get(), 8) != 0, ::sqlite3_column_int64(st->get(), 9),
            });
        }
        if (rc != SQLITE_DONE) return std::unexpected(sqlite_err_msg(self.impl_->db, "list_profile_summaries"));
        return out;
    }

    auto ClientDatabase::load_profile_payload(this ClientDatabase& self, std::string_view profile_id)
        -> std::expected<std::optional<WorkspaceProfileItem>, std::string> {
        if (!self.impl_ || !self.impl_->db) return std::unexpected("sqlite database is closed");
        std::scoped_lock lk(self.impl_->mu);
        auto st = prepare_stmt(self.impl_->db, "SELECT payload_json FROM profile_payloads WHERE profile_id = ?1;");
        if (!st) return std::unexpected(st.error());
        bind_text(st->get(), 1, profile_id);
        int rc = ::sqlite3_step(st->get());
        if (rc == SQLITE_DONE) return std::nullopt;
        if (rc != SQLITE_ROW) return std::unexpected(sqlite_err_msg(self.impl_->db, "load_profile_payload"));
        auto parsed = json_parse(col_text(st->get(), 0));
        if (!parsed || !parsed->is_object()) return std::unexpected("corrupt profile_payloads JSON");
        return ws_codec::profile_from_json(std::get<JsonObject>(parsed->data));
    }

    auto ClientDatabase::delete_profile(this ClientDatabase& self, std::string_view profile_id)
        -> std::expected<bool, std::string> {
        if (!self.impl_ || !self.impl_->db) return std::unexpected("sqlite database is closed");
        std::scoped_lock lk(self.impl_->mu);
        auto st = prepare_stmt(self.impl_->db, "DELETE FROM profiles WHERE id = ?1;");
        if (!st) return std::unexpected(st.error());
        bind_text(st->get(), 1, profile_id);
        if (::sqlite3_step(st->get()) != SQLITE_DONE) return std::unexpected(sqlite_err_msg(self.impl_->db, "delete_profile"));
        return ::sqlite3_changes(self.impl_->db) > 0;
    }

    auto ClientDatabase::set_profile_pinned(this ClientDatabase& self, std::string_view profile_id, bool pinned)
        -> std::expected<void, std::string> {
        if (!self.impl_ || !self.impl_->db) return std::unexpected("sqlite database is closed");
        std::scoped_lock lk(self.impl_->mu);
        auto st = prepare_stmt(self.impl_->db, "UPDATE profiles SET pinned = ?1 WHERE id = ?2;");
        if (!st) return std::unexpected(st.error());
        ::sqlite3_bind_int(st->get(), 1, pinned ? 1 : 0);
        bind_text(st->get(), 2, profile_id);
        if (::sqlite3_step(st->get()) != SQLITE_DONE) return std::unexpected(sqlite_err_msg(self.impl_->db, "set_profile_pinned"));
        return {};
    }

    auto ClientDatabase::count_profile_payloads(this ClientDatabase& self) -> std::expected<std::int64_t, std::string> {
        if (!self.impl_ || !self.impl_->db) return std::unexpected("sqlite database is closed");
        std::scoped_lock lk(self.impl_->mu);
        auto st = prepare_stmt(self.impl_->db, "SELECT COUNT(*) FROM profile_payloads;");
        if (!st) return std::unexpected(st.error());
        if (::sqlite3_step(st->get()) != SQLITE_ROW) return 0;
        return ::sqlite3_column_int64(st->get(), 0);
    }
}
