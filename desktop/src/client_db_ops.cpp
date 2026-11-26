module;

#include "sqlite3.h"

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <malloc.h>
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(__linux__) && defined(__GLIBC__)
#include <malloc.h>
#elif defined(__APPLE__)
#include <malloc/malloc.h>
#endif
#endif

module desktop.client_db;

import std;
import desktop.mini_json;
import desktop.telemetry_store;

#include "client_db_schema.hpp"

namespace desktop {
    using namespace db_detail;

    namespace {
        auto is_forbidden_secret_key(std::string_view key) noexcept -> bool {
            auto eq_icase = [](std::string_view a, std::string_view b) {
                if (a.size() != b.size()) return false;
                for (std::size_t i = 0; i < a.size(); ++i) {
                    auto ca = static_cast<unsigned char>(a[i]);
                    auto cb = static_cast<unsigned char>(b[i]);
                    if (ca >= 'A' && ca <= 'Z') ca = static_cast<unsigned char>(ca - 'A' + 'a');
                    if (cb >= 'A' && cb <= 'Z') cb = static_cast<unsigned char>(cb - 'A' + 'a');
                    if (ca != cb) return false;
                }
                return true;
            };
            return eq_icase(key, "webdav_password") || eq_icase(key, "sync_passphrase") || eq_icase(key, "lan_password");
        }

        auto json_value_has_secret(JsonValue const& v) -> bool {
            if (v.is_object()) {
                for (auto const& [k, child] : std::get<JsonObject>(v.data)) {
                    if (is_forbidden_secret_key(k)) {
                        if (std::holds_alternative<std::string>(child.data)) {
                            if (!std::get<std::string>(child.data).empty()) return true;
                        } else if (!std::holds_alternative<std::monostate>(child.data)) {
                            return true;
                        }
                    }
                    if (json_value_has_secret(child)) return true;
                }
            } else if (v.is_array()) {
                for (auto const& elem : std::get<JsonArray>(v.data)) {
                    if (json_value_has_secret(elem)) return true;
                }
            }
            return false;
        }
    }

    auto ClientDatabase::has_telemetry_data(this ClientDatabase& self) -> std::expected<bool, std::string> {
        if (!self.impl_ || !self.impl_->db) return std::unexpected("sqlite database is closed");
        std::scoped_lock lk(self.impl_->mu);
        auto st = prepare_stmt(
            self.impl_->db,
            "SELECT (SELECT COUNT(*) FROM node_telemetry) + (SELECT COUNT(*) FROM traffic_ledger) "
            "+ (SELECT COUNT(*) FROM host_kv WHERE key = 'active_profile_id');");
        if (!st) return std::unexpected(st.error());
        if (::sqlite3_step(st->get()) != SQLITE_ROW) return std::unexpected(sqlite_err_msg(self.impl_->db, "has_telemetry_data"));
        return ::sqlite3_column_int64(st->get(), 0) > 0;
    }

    auto ClientDatabase::upsert_node_telemetry(this ClientDatabase& self, NodeTelemetryRow const& row)
        -> std::expected<void, std::string> {
        if (!self.impl_ || !self.impl_->db) return std::unexpected("sqlite database is closed");
        std::scoped_lock lk(self.impl_->mu);
        auto st = prepare_stmt(
            self.impl_->db,
            "INSERT INTO node_telemetry(profile_id, latency_ms, ewma_ms, status_code, state, tested_at) "
            "VALUES(?1, ?2, ?3, ?4, ?5, ?6) "
            "ON CONFLICT(profile_id) DO UPDATE SET latency_ms = excluded.latency_ms, ewma_ms = excluded.ewma_ms, "
            "status_code = excluded.status_code, state = excluded.state, tested_at = excluded.tested_at;");
        if (!st) return std::unexpected(st.error());
        bind_text(st->get(), 1, row.profile_id);
        ::sqlite3_bind_int64(st->get(), 2, row.latency_ms);
        ::sqlite3_bind_int64(st->get(), 3, row.ewma_ms);
        ::sqlite3_bind_int64(st->get(), 4, row.status_code);
        bind_text(st->get(), 5, row.state);
        ::sqlite3_bind_int64(st->get(), 6, row.tested_at);
        if (::sqlite3_step(st->get()) != SQLITE_DONE) return std::unexpected(sqlite_err_msg(self.impl_->db, "upsert_node_telemetry"));
        return {};
    }

    auto ClientDatabase::load_node_telemetry(this ClientDatabase& self) -> std::expected<std::vector<NodeTelemetryRow>, std::string> {
        if (!self.impl_ || !self.impl_->db) return std::unexpected("sqlite database is closed");
        std::scoped_lock lk(self.impl_->mu);
        auto st = prepare_stmt(
            self.impl_->db,
            "SELECT profile_id, latency_ms, ewma_ms, status_code, state, tested_at FROM node_telemetry ORDER BY profile_id ASC;");
        if (!st) return std::unexpected(st.error());
        std::vector<NodeTelemetryRow> out;
        int rc = SQLITE_OK;
        while ((rc = ::sqlite3_step(st->get())) == SQLITE_ROW) {
            out.push_back({
                col_text(st->get(), 0), ::sqlite3_column_int64(st->get(), 1), ::sqlite3_column_int64(st->get(), 2),
                ::sqlite3_column_int64(st->get(), 3), col_text(st->get(), 4), ::sqlite3_column_int64(st->get(), 5),
            });
        }
        if (rc != SQLITE_DONE) return std::unexpected(sqlite_err_msg(self.impl_->db, "load_node_telemetry"));
        return out;
    }

    auto ClientDatabase::load_telemetry(this ClientDatabase& self) -> std::expected<TelemetryStoreData, std::string> {
        if (!self.impl_ || !self.impl_->db) return std::unexpected("sqlite database is closed");
        std::scoped_lock lk(self.impl_->mu);
        TxGuard tx(self.impl_->db);
        if (auto b = tx.begin_deferred(); !b) return std::unexpected(b.error());

        TelemetryStoreData out{};
        if (auto kv = prepare_stmt(self.impl_->db, "SELECT value_json FROM host_kv WHERE key = 'active_profile_id';"); kv) {
            int rc = ::sqlite3_step(kv->get());
            if (rc == SQLITE_ROW) {
                if (auto p = json_parse(col_text(kv->get(), 0)); p && std::holds_alternative<std::string>(p->data)) {
                    out.active_profile_id = std::get<std::string>(p->data);
                }
            } else if (rc != SQLITE_DONE) {
                return std::unexpected(sqlite_err_msg(self.impl_->db, "load active_profile_id"));
            }
        } else {
            return std::unexpected(kv.error());
        }

        auto st = prepare_stmt(
            self.impl_->db,
            "SELECT profile_id, latency_ms, tested_at FROM node_telemetry ORDER BY profile_id ASC;");
        if (!st) return std::unexpected(st.error());
        int rc = SQLITE_OK;
        while ((rc = ::sqlite3_step(st->get())) == SQLITE_ROW) {
            out.entries.push_back({
                .profile_id = col_text(st->get(), 0),
                .delay_ms = ::sqlite3_column_int64(st->get(), 1),
                .last_tested_ms = ::sqlite3_column_int64(st->get(), 2),
            });
        }
        if (rc != SQLITE_DONE) return std::unexpected(sqlite_err_msg(self.impl_->db, "load_telemetry"));
        if (auto c = tx.commit(); !c) return std::unexpected(c.error());
        return out;
    }

    auto ClientDatabase::save_telemetry(this ClientDatabase& self, TelemetryStoreData const& data)
        -> std::expected<void, std::string> {
        if (!self.impl_ || !self.impl_->db) return std::unexpected("sqlite database is closed");
        std::scoped_lock lk(self.impl_->mu);
        TxGuard tx(self.impl_->db);
        if (auto b = tx.begin(); !b) return std::unexpected(b.error());

        // Preserve rich probe telemetry columns (ewma_ms, status_code, state) for retained profile IDs.
        struct RichMeta { std::int64_t ewma_ms = -1; std::int64_t status_code = 0; std::string state; };
        std::unordered_map<std::string, RichMeta> prev_meta;
        if (auto rd = prepare_stmt(self.impl_->db, "SELECT profile_id, ewma_ms, status_code, state FROM node_telemetry;"); rd) {
            int rc = SQLITE_OK;
            while ((rc = ::sqlite3_step(rd->get())) == SQLITE_ROW) {
                prev_meta.emplace(col_text(rd->get(), 0), RichMeta{
                    ::sqlite3_column_int64(rd->get(), 1), ::sqlite3_column_int64(rd->get(), 2), col_text(rd->get(), 3)});
            }
            if (rc != SQLITE_DONE) return std::unexpected(sqlite_err_msg(self.impl_->db, "read prev node_telemetry"));
        } else {
            return std::unexpected(rd.error());
        }

        if (auto clr = exec_sql(self.impl_->db, "DELETE FROM node_telemetry;"); !clr) return std::unexpected(clr.error());

        auto st = prepare_stmt(
            self.impl_->db,
            "INSERT INTO node_telemetry(profile_id, latency_ms, ewma_ms, status_code, state, tested_at) "
            "VALUES(?1, ?2, ?3, ?4, ?5, ?6);");
        if (!st) return std::unexpected(st.error());
        for (auto const& e : data.entries) {
            if (e.profile_id.empty()) continue;
            auto it = prev_meta.find(e.profile_id);
            std::int64_t const ewma = (it != prev_meta.end() && it->second.ewma_ms >= 0) ? it->second.ewma_ms : e.delay_ms;
            std::int64_t const code = (it != prev_meta.end()) ? it->second.status_code : 0;
            std::string const state = (it != prev_meta.end() && !it->second.state.empty())
                ? it->second.state : std::string(e.delay_ms > 0 ? "healthy" : (e.delay_ms == 0 ? "timeout" : ""));
            ::sqlite3_reset(st->get());
            bind_text(st->get(), 1, e.profile_id);
            ::sqlite3_bind_int64(st->get(), 2, e.delay_ms);
            ::sqlite3_bind_int64(st->get(), 3, ewma);
            ::sqlite3_bind_int64(st->get(), 4, code);
            bind_text(st->get(), 5, state);
            ::sqlite3_bind_int64(st->get(), 6, e.last_tested_ms);
            if (::sqlite3_step(st->get()) != SQLITE_DONE) return std::unexpected(sqlite_err_msg(self.impl_->db, "save_telemetry"));
        }

        auto kv = prepare_stmt(
            self.impl_->db,
            "INSERT INTO host_kv(key, value_json) VALUES('active_profile_id', ?1) "
            "ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json;");
        if (!kv) return std::unexpected(kv.error());
        auto active_json = json_stringify(JsonValue(data.active_profile_id), false);
        bind_text(kv->get(), 1, active_json);
        if (::sqlite3_step(kv->get()) != SQLITE_DONE) return std::unexpected(sqlite_err_msg(self.impl_->db, "save_active_profile"));
        return tx.commit();
    }

    auto ClientDatabase::record_traffic_delta(
        this ClientDatabase& self,
        std::int64_t bucket_hour,
        std::string_view profile_id,
        std::int64_t upload_delta,
        std::int64_t download_delta) -> std::expected<void, std::string> {
        if (!self.impl_ || !self.impl_->db) return std::unexpected("sqlite database is closed");
        if (upload_delta <= 0 && download_delta <= 0) return {};
        std::scoped_lock lk(self.impl_->mu);
        auto st = prepare_stmt(
            self.impl_->db,
            "INSERT INTO traffic_ledger(bucket_hour, profile_id, upload_bytes, download_bytes) VALUES(?1, ?2, ?3, ?4) "
            "ON CONFLICT(bucket_hour, profile_id) DO UPDATE SET "
            "upload_bytes = upload_bytes + excluded.upload_bytes, download_bytes = download_bytes + excluded.download_bytes;");
        if (!st) return std::unexpected(st.error());
        ::sqlite3_bind_int64(st->get(), 1, bucket_hour);
        bind_text(st->get(), 2, profile_id);
        ::sqlite3_bind_int64(st->get(), 3, std::max<std::int64_t>(0, upload_delta));
        ::sqlite3_bind_int64(st->get(), 4, std::max<std::int64_t>(0, download_delta));
        if (::sqlite3_step(st->get()) != SQLITE_DONE) return std::unexpected(sqlite_err_msg(self.impl_->db, "record_traffic_delta"));
        return {};
    }

    auto ClientDatabase::query_traffic_ledger(
        this ClientDatabase& self,
        std::int64_t from_hour,
        std::int64_t to_hour,
        std::string_view profile_id) -> std::expected<std::vector<TrafficLedgerRow>, std::string> {
        if (!self.impl_ || !self.impl_->db) return std::unexpected("sqlite database is closed");
        std::scoped_lock lk(self.impl_->mu);
        char const* sql = profile_id.empty()
            ? "SELECT bucket_hour, profile_id, upload_bytes, download_bytes FROM traffic_ledger "
              "WHERE bucket_hour >= ?1 AND bucket_hour <= ?2 ORDER BY bucket_hour ASC, profile_id ASC;"
            : "SELECT bucket_hour, profile_id, upload_bytes, download_bytes FROM traffic_ledger "
              "WHERE bucket_hour >= ?1 AND bucket_hour <= ?2 AND profile_id = ?3 ORDER BY bucket_hour ASC;";
        auto st = prepare_stmt(self.impl_->db, sql);
        if (!st) return std::unexpected(st.error());
        ::sqlite3_bind_int64(st->get(), 1, from_hour);
        ::sqlite3_bind_int64(st->get(), 2, to_hour);
        if (!profile_id.empty()) bind_text(st->get(), 3, profile_id);
        std::vector<TrafficLedgerRow> out;
        int rc = SQLITE_OK;
        while ((rc = ::sqlite3_step(st->get())) == SQLITE_ROW) {
            out.push_back({
                ::sqlite3_column_int64(st->get(), 0), col_text(st->get(), 1),
                ::sqlite3_column_int64(st->get(), 2), ::sqlite3_column_int64(st->get(), 3),
            });
        }
        if (rc != SQLITE_DONE) return std::unexpected(sqlite_err_msg(self.impl_->db, "query_traffic_ledger"));
        return out;
    }

    auto ClientDatabase::get_host_kv(this ClientDatabase& self, std::string_view key)
        -> std::expected<std::optional<std::string>, std::string> {
        if (!self.impl_ || !self.impl_->db) return std::unexpected("sqlite database is closed");
        std::scoped_lock lk(self.impl_->mu);
        auto st = prepare_stmt(self.impl_->db, "SELECT value_json FROM host_kv WHERE key = ?1;");
        if (!st) return std::unexpected(st.error());
        bind_text(st->get(), 1, key);
        int rc = ::sqlite3_step(st->get());
        if (rc == SQLITE_DONE) return std::nullopt;
        if (rc != SQLITE_ROW) return std::unexpected(sqlite_err_msg(self.impl_->db, "get_host_kv"));
        return col_text(st->get(), 0);
    }

    auto ClientDatabase::set_host_kv(this ClientDatabase& self, std::string_view key, std::string_view value_json)
        -> std::expected<void, std::string> {
        if (!self.impl_ || !self.impl_->db) return std::unexpected("sqlite database is closed");
        if (is_forbidden_secret_key(key)) {
            return std::unexpected("refusing to store secret credential key in SQLite host_kv");
        }
        if (auto parsed = json_parse(value_json); parsed && json_value_has_secret(*parsed)) {
            return std::unexpected("refusing to store secret credentials in SQLite host_kv");
        }
        std::scoped_lock lk(self.impl_->mu);
        auto st = prepare_stmt(
            self.impl_->db,
            "INSERT INTO host_kv(key, value_json) VALUES(?1, ?2) "
            "ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json;");
        if (!st) return std::unexpected(st.error());
        bind_text(st->get(), 1, key);
        bind_text(st->get(), 2, value_json);
        if (::sqlite3_step(st->get()) != SQLITE_DONE) return std::unexpected(sqlite_err_msg(self.impl_->db, "set_host_kv"));
        return {};
    }

    auto ClientDatabase::delete_host_kv(this ClientDatabase& self, std::string_view key)
        -> std::expected<void, std::string> {
        if (!self.impl_ || !self.impl_->db) return std::unexpected("sqlite database is closed");
        std::scoped_lock lk(self.impl_->mu);
        auto st = prepare_stmt(self.impl_->db, "DELETE FROM host_kv WHERE key = ?1;");
        if (!st) return std::unexpected(st.error());
        bind_text(st->get(), 1, key);
        if (::sqlite3_step(st->get()) != SQLITE_DONE) return std::unexpected(sqlite_err_msg(self.impl_->db, "delete_host_kv"));
        return {};
    }

    auto ClientDatabase::shrink_memory(this ClientDatabase& self) -> std::expected<void, std::string> {
        if (!self.impl_ || !self.impl_->db) return std::unexpected("sqlite database is closed");
        std::scoped_lock lk(self.impl_->mu);
        if (auto r = exec_sql(self.impl_->db, "PRAGMA shrink_memory; PRAGMA wal_checkpoint(PASSIVE);"); !r) {
            return r;
        }
        (void)::sqlite3_db_release_memory(self.impl_->db);
        ensure_private_db_perms(self.impl_->db_path);
        return {};
    }

    auto reclaim_process_memory(ClientDatabase* db) noexcept -> void {
        if (db) {
            try {
                (void)db->shrink_memory();
            } catch (...) {
            }
        }
        (void)::sqlite3_release_memory(1024 * 1024);
#if defined(_WIN32)
        (void)::_heapmin();
        (void)::SetProcessWorkingSetSize(::GetCurrentProcess(), static_cast<SIZE_T>(-1), static_cast<SIZE_T>(-1));
#elif defined(__linux__) && defined(__GLIBC__)
        (void)::malloc_trim(0);
#elif defined(__APPLE__)
        ::malloc_zone_pressure_relief(nullptr, 0);
#endif
    }
}
