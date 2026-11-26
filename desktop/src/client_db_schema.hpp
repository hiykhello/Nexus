// SQLite 3 WAL Schema v1 DDL, RAII wrappers, and POSIX 0600 helpers for desktop/src/client_db.cpp.
#pragma once

namespace desktop::db_detail {
    inline constexpr int kClientDbSchemaVersion = 1;

    inline constexpr char const* kPragmasSql =
        "PRAGMA journal_mode = WAL;"
        "PRAGMA synchronous = NORMAL;"
        "PRAGMA foreign_keys = ON;"
        "PRAGMA busy_timeout = 5000;"
        "PRAGMA temp_store = MEMORY;"
        "PRAGMA mmap_size = 0;"
        "PRAGMA cache_size = -2000;";

    inline constexpr char const* kSchemaV1Sql = R"SQL(
CREATE TABLE IF NOT EXISTS subscriptions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    sort_order INTEGER NOT NULL DEFAULT 0,
    payload_json TEXT NOT NULL,
    updated_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS profiles (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    subscription_id TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL,
    protocol TEXT NOT NULL DEFAULT '',
    server TEXT NOT NULL DEFAULT '',
    port INTEGER NOT NULL DEFAULT 0,
    sort_order INTEGER NOT NULL DEFAULT 0,
    pinned INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_profiles_sub_order ON profiles(subscription_id, sort_order);
CREATE INDEX IF NOT EXISTS idx_profiles_kind ON profiles(kind);
CREATE INDEX IF NOT EXISTS idx_profiles_protocol ON profiles(protocol);
CREATE INDEX IF NOT EXISTS idx_profiles_pinned ON profiles(pinned);

CREATE TABLE IF NOT EXISTS profile_payloads (
    profile_id TEXT PRIMARY KEY REFERENCES profiles(id) ON DELETE CASCADE,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS routing_profiles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    sort_order INTEGER NOT NULL DEFAULT 0,
    payload_json TEXT NOT NULL,
    updated_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS workspace_meta (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS node_telemetry (
    profile_id TEXT PRIMARY KEY,
    latency_ms INTEGER NOT NULL DEFAULT -1,
    ewma_ms INTEGER NOT NULL DEFAULT -1,
    status_code INTEGER NOT NULL DEFAULT 0,
    state TEXT NOT NULL DEFAULT '',
    tested_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS traffic_ledger (
    bucket_hour INTEGER NOT NULL,
    profile_id TEXT NOT NULL,
    upload_bytes INTEGER NOT NULL DEFAULT 0,
    download_bytes INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_hour, profile_id)
);

CREATE TABLE IF NOT EXISTS host_kv (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL
);

PRAGMA user_version = 1;
)SQL";

    namespace {
    struct StmtGuard {
        sqlite3_stmt* stmt = nullptr;
        StmtGuard() = default;
        explicit StmtGuard(sqlite3_stmt* s) noexcept : stmt(s) {}
        ~StmtGuard() { if (stmt) ::sqlite3_finalize(stmt); }
        StmtGuard(StmtGuard const&) = delete;
        auto operator=(StmtGuard const&) -> StmtGuard& = delete;
        StmtGuard(StmtGuard&& o) noexcept : stmt(o.stmt) { o.stmt = nullptr; }
        auto operator=(StmtGuard&& o) noexcept -> StmtGuard& {
            if (this != &o) {
                if (stmt) ::sqlite3_finalize(stmt);
                stmt = o.stmt;
                o.stmt = nullptr;
            }
            return *this;
        }
        [[nodiscard]] auto get() const noexcept -> sqlite3_stmt* { return stmt; }
    };

    inline auto path_to_utf8(std::filesystem::path const& p) -> std::string {
        auto u8 = p.u8string();
        return std::string(reinterpret_cast<char const*>(u8.data()), u8.size());
    }

    inline auto ensure_private_db_perms(std::filesystem::path const& db_path) noexcept -> void {
#ifndef _WIN32
        (void)::chmod(db_path.c_str(), 0600);
        auto wal = db_path;
        wal += "-wal";
        (void)::chmod(wal.c_str(), 0600);
        auto shm = db_path;
        shm += "-shm";
        (void)::chmod(shm.c_str(), 0600);
#else
        (void)db_path;
#endif
    }

    inline auto precreate_private_file(std::filesystem::path const& db_path) noexcept -> void {
#ifndef _WIN32
        int fd = ::open(db_path.c_str(), O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd >= 0) {
            (void)::fchmod(fd, 0600);
            ::close(fd);
        } else if (errno == EEXIST) {
            (void)::chmod(db_path.c_str(), 0600);
        }
#else
        (void)db_path;
#endif
    }

    inline auto sqlite_err_msg(sqlite3* db, std::string_view ctx) -> std::string {
        char const* msg = db ? ::sqlite3_errmsg(db) : "null sqlite3 handle";
        return std::format("{}: {}", ctx, msg ? msg : "unknown error");
    }

    inline auto exec_sql(sqlite3* db, char const* sql) -> std::expected<void, std::string> {
        char* err = nullptr;
        int rc = ::sqlite3_exec(db, sql, nullptr, nullptr, &err);
        if (rc != SQLITE_OK) {
            std::string msg = err ? std::string(err) : sqlite_err_msg(db, "sqlite3_exec");
            if (err) ::sqlite3_free(err);
            return std::unexpected(std::move(msg));
        }
        return {};
    }

    inline auto prepare_stmt(sqlite3* db, char const* sql) -> std::expected<StmtGuard, std::string> {
        sqlite3_stmt* raw = nullptr;
        int rc = ::sqlite3_prepare_v2(db, sql, -1, &raw, nullptr);
        if (rc != SQLITE_OK || !raw) {
            if (raw) ::sqlite3_finalize(raw);
            return std::unexpected(sqlite_err_msg(db, "sqlite3_prepare_v2"));
        }
        return StmtGuard{raw};
    }

    inline auto bind_text(sqlite3_stmt* s, int idx, std::string_view sv) noexcept -> int {
        return ::sqlite3_bind_text(s, idx, sv.data() ? sv.data() : "", static_cast<int>(sv.size()), SQLITE_TRANSIENT);
    }

    inline auto col_text(sqlite3_stmt* s, int col) -> std::string {
        auto const* ptr = reinterpret_cast<char const*>(::sqlite3_column_text(s, col));
        int const len = ::sqlite3_column_bytes(s, col);
        if (!ptr || len <= 0) return {};
        return std::string(ptr, static_cast<std::size_t>(len));
    }

    struct TxGuard {
        sqlite3* db = nullptr;
        bool active = false;
        explicit TxGuard(sqlite3* d) : db(d) {}
        auto begin() -> std::expected<void, std::string> {
            auto r = exec_sql(db, "BEGIN IMMEDIATE;");
            if (r) active = true;
            return r;
        }
        auto begin_deferred() -> std::expected<void, std::string> {
            auto r = exec_sql(db, "BEGIN DEFERRED;");
            if (r) active = true;
            return r;
        }
        auto commit() -> std::expected<void, std::string> {
            if (!active) return {};
            auto r = exec_sql(db, "COMMIT;");
            if (r) active = false;
            return r;
        }
        ~TxGuard() {
            if (active && db) (void)exec_sql(db, "ROLLBACK;");
        }
    };
    }
}

namespace desktop {
    struct ClientDatabase::Impl {
        std::filesystem::path db_path;
        sqlite3* db = nullptr;
        std::mutex mu;
        ~Impl();
    };
}
