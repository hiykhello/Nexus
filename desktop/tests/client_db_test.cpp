#ifndef _WIN32
#include <sys/stat.h>
#endif

import std;
import desktop.client_db;
import desktop.desktop_host_config;
import desktop.telemetry_store;
import desktop.ui_prefs;
import desktop.workspace_models;
import desktop.workspace_store;

namespace {
    auto expect(bool cond, std::string_view msg) -> void {
        if (!cond) throw std::runtime_error(std::string(msg));
    }

    auto make_temp_dir(std::string_view suffix) -> std::filesystem::path {
        auto dir = std::filesystem::temp_directory_path() / ("nexus-client-db-test-" + std::string(suffix));
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
        std::filesystem::create_directories(dir, ec);
        return dir;
    }

    auto test_schema_v1_workspace_vertical_split_and_cascade() -> void {
        auto dir = make_temp_dir("schema");
        auto db_path = dir / "nexus-client.db";
        auto db = desktop::ClientDatabase::open(db_path);
        expect(db.has_value(), "open nexus-client.db");

#ifndef _WIN32
        struct stat st{};
        expect(::stat(db_path.c_str(), &st) == 0 && (st.st_mode & 0777) == 0600,
            "nexus-client.db created with 0600 permissions on POSIX");
#endif
        auto ver = db->user_version();
        expect(ver.has_value() && *ver == 1, "PRAGMA user_version == 1");
        auto has_data0 = db->has_workspace_data();
        expect(has_data0.has_value() && !*has_data0, "fresh DB reports empty workspace");

        auto doc = desktop::make_default_workspace();
        doc.revision = 5;
        doc.updated_at_ms = 1764001234567LL;

        desktop::WorkspaceProfileItem n1{
            .id = "n-hk-1", .remarks = "HK Edge 1", .subscription_id = "sub-a", .is_from_sub = true, .kind = "node",
        };
        n1.node.protocol = "vless";
        n1.node.server = "hk1.example.net";
        n1.node.port = 443;
        n1.node.password = "uuid-hk-1";
        n1.node.tls.enabled = true;
        n1.node.tls.sni = "cdn.example.net";
        doc.profiles.push_back(n1);

        desktop::WorkspaceProfileItem n2{
            .id = "n-jp-2", .remarks = "JP Edge 2", .subscription_id = "sub-a", .is_from_sub = true, .kind = "node",
        };
        n2.node.protocol = "trojan";
        n2.node.server = "jp2.example.net";
        n2.node.port = 8443;
        n2.node.password = "pw-jp-2";
        doc.profiles.push_back(n2);

        doc.profiles.push_back({
            .id = "grp-1", .remarks = "Auto Fastest", .subscription_id = "manual", .is_from_sub = false,
            .kind = "policy_group", .policy_group = {.strategy = "url-test", .member_ids = {"n-hk-1", "n-jp-2"}},
        });
        doc.subscriptions.push_back({
            .id = "sub-a", .remarks = "Sub A", .url = "https://sub.example.net/feed", .enabled = true,
            .prev_profile_id = "grp-1", .usage = {.upload_bytes = 512, .download_bytes = 1024, .total_bytes = 4096},
        });
        doc.dns.simple.fake_ip_enabled = true;
        doc.rule_set_assets.push_back({.tag = "geo-cn", .source_type = "local", .format = "srs", .path = "cn.srs"});
        doc.full_template = {.enabled = false, .template_kdl = "// tpl", .append_proxies_only = true, .proxy_detour = "direct"};

        expect(db->save_workspace(doc).has_value(), "save_workspace succeeds");
        expect(db->set_profile_pinned("n-jp-2", true).has_value(), "pin n-jp-2");

        // Index-only profile listing puts pinned first, filters by subscription_id and kind cleanly.
        auto all_sum = db->list_profile_summaries();
        expect(all_sum.has_value() && all_sum->size() == 3 &&
               (*all_sum)[0].id == "n-jp-2" && (*all_sum)[0].pinned &&
               (*all_sum)[0].protocol == "trojan" && (*all_sum)[0].port == 8443,
            "list_profile_summaries reads index columns with pinned-first ordering");

        auto sub_sum = db->list_profile_summaries("sub-a", "node");
        expect(sub_sum.has_value() && sub_sum->size() == 2, "list_profile_summaries filters by subscription_id + kind");

        auto payload = db->load_profile_payload("n-hk-1");
        expect(payload.has_value() && payload->has_value() && (**payload).node.tls.sni == "cdn.example.net",
            "load_profile_payload reads full vertical-split JSON");

        // Verify ON DELETE CASCADE removes matching profile_payloads row.
        auto cnt_before = db->count_profile_payloads();
        expect(cnt_before.has_value() && *cnt_before == 3, "3 rows in profile_payloads before delete");
        auto del = db->delete_profile("n-hk-1");
        expect(del.has_value() && *del, "delete_profile removes profile");
        auto cnt_after = db->count_profile_payloads();
        expect(cnt_after.has_value() && *cnt_after == 2, "ON DELETE CASCADE pruned profile_payloads row");
        auto gone = db->load_profile_payload("n-hk-1");
        expect(gone.has_value() && !gone->has_value(), "deleted payload no longer exists");

        // Full workspace save & reload round-trip preserves all tables + workspace_meta + pinned state.
        expect(db->save_workspace(doc).has_value(), "re-save workspace preserves pinned state");
        auto re_sum = db->list_profile_summaries();
        expect(re_sum.has_value() && (*re_sum)[0].id == "n-jp-2" && (*re_sum)[0].pinned,
            "pinned flag survives full workspace save");

        auto loaded = db->load_workspace();
        expect(loaded.has_value(), "load_workspace succeeds");
        expect(loaded->revision == 5 && loaded->updated_at_ms == 1764001234567LL, "revision & updated_at_ms roundtrip");
        expect(loaded->profiles.size() == 3 && loaded->subscriptions.size() == 2 && loaded->routing_profiles.size() == 3,
            "all profiles, subscriptions, routing_profiles roundtrip");
        expect(loaded->dns.simple.fake_ip_enabled && loaded->rule_set_assets.size() == 1 &&
               loaded->full_template.append_proxies_only,
            "workspace_meta dns / rule_set_assets / full_template roundtrip");

        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }

    auto test_telemetry_traffic_ledger_and_memory_reclaim() -> void {
        auto dir = make_temp_dir("telemetry");
        auto db = desktop::ClientDatabase::open(dir / "nexus-client.db");
        expect(db.has_value(), "open db");

        expect(db->upsert_node_telemetry({"p1", 38, 41, 204, "healthy", 1764000000}).has_value(), "upsert telemetry p1");
        expect(db->upsert_node_telemetry({"p2", 0, 120, 0, "timeout", 1764000010}).has_value(), "upsert telemetry p2");
        expect(db->upsert_node_telemetry({"p1", 32, 37, 204, "healthy", 1764000020}).has_value(), "update telemetry p1");
        auto rows = db->load_node_telemetry();
        expect(rows.has_value() && rows->size() == 2 &&
               (*rows)[0].profile_id == "p1" && (*rows)[0].latency_ms == 32 && (*rows)[0].ewma_ms == 37 &&
               (*rows)[0].status_code == 204 && (*rows)[1].state == "timeout",
            "node_telemetry upsert & load roundtrip");

        desktop::TelemetryStoreData tel{.schema_version = 1, .active_profile_id = "p1"};
        tel.entries.push_back({.profile_id = "p1", .delay_ms = 29, .last_tested_ms = 1764000099});
        expect(db->save_telemetry(tel).has_value(), "save_telemetry succeeds");
        auto loaded_tel = db->load_telemetry();
        expect(loaded_tel.has_value() && loaded_tel->active_profile_id == "p1" &&
               loaded_tel->entries.size() == 1 && loaded_tel->entries[0].delay_ms == 29,
            "load_telemetry roundtrip");
        auto rich_after = db->load_node_telemetry();
        expect(rich_after.has_value() && rich_after->size() == 1 &&
               (*rich_after)[0].ewma_ms == 37 && (*rich_after)[0].status_code == 204 &&
               (*rich_after)[0].state == "healthy",
            "save_telemetry preserves rich probe metadata (ewma_ms, status_code, state)");

        // Hourly traffic_ledger accumulation across buckets and profiles.
        expect(db->record_traffic_delta(490000, "p1", 1024, 4096).has_value(), "record delta 1");
        expect(db->record_traffic_delta(490000, "p1", 512, 2048).has_value(), "accumulate same bucket+profile");
        expect(db->record_traffic_delta(490001, "p1", 100, 200).has_value(), "record next hour");
        expect(db->record_traffic_delta(490000, "p2", 50, 75).has_value(), "record sibling profile");

        auto p1_rows = db->query_traffic_ledger(490000, 490001, "p1");
        expect(p1_rows.has_value() && p1_rows->size() == 2 &&
               (*p1_rows)[0].upload_bytes == 1536 && (*p1_rows)[0].download_bytes == 6144 &&
               (*p1_rows)[1].upload_bytes == 100 && (*p1_rows)[1].download_bytes == 200,
            "traffic_ledger accumulates deltas accurately per (bucket_hour, profile_id)");

        auto all_rows = db->query_traffic_ledger(490000, 490000);
        expect(all_rows.has_value() && all_rows->size() == 2, "traffic_ledger range query returns all profiles in bucket");

        expect(db->shrink_memory().has_value(), "shrink_memory succeeds");
        desktop::reclaim_process_memory(&*db);

        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }

    auto test_host_kv_secret_isolation_and_guards() -> void {
        auto dir = make_temp_dir("host-kv");
        auto sec_dir = dir / "secrets";

        auto db = desktop::ClientDatabase::open(dir / "nexus-client.db");
        expect(db.has_value(), "open db for host_kv & secret isolation test");

        auto host = desktop::make_default_desktop_host_config(dir, "/run/nexus.sock");
        expect(host.workers == 1, "default host workers == 1");
        host.workers = 24;
        host.workers_spec = "max-2";
        host.workers_max = 12;
        host.enable_mixed = true;
        host.mixed_listen = "127.0.0.1:7895";
        host.webdav_url = "https://dav.example.net/nexus/";
        host.webdav_username = "alice";
        host.webdav_password = "dav-super-secret-password";
        host.sync_passphrase = "e2ee-ultra-secret-passphrase";
        host.lan_password = "lan-secret-password";
        expect(desktop::save_host_config_to_db(*db, sec_dir, host), "save_host_config_to_db succeeds");

        desktop::UiPrefs prefs{};
        prefs.sidebar_collapsed = true;
        prefs.dash_show_connectivity = false;
        prefs.theme_preference = "dark";
        expect(desktop::save_ui_prefs_to_db(*db, prefs), "save_ui_prefs_to_db succeeds");

        auto prefs_out = desktop::load_ui_prefs_from_db(*db);
        expect(prefs_out.has_value() && prefs_out->sidebar_collapsed && !prefs_out->dash_show_connectivity &&
               prefs_out->theme_preference == "obsidian",
            "ui_prefs and sidebar_collapsed round-trip through SQLite host_kv (legacy dark migrates to obsidian)");
        auto sc_kv = db->get_host_kv("sidebar_collapsed");
        expect(sc_kv.has_value() && sc_kv->has_value() && **sc_kv == "true", "sidebar_collapsed persisted directly in host_kv");

        // CRITICAL SECURITY CHECK: WebDAV password, E2EE sync passphrase, and LAN password MUST NOT exist in SQLite!
        auto host_kv_raw = db->get_host_kv("desktop_host");
        expect(host_kv_raw.has_value() && host_kv_raw->has_value(), "desktop_host stored in host_kv");
        expect(!host_kv_raw->value().contains("dav-super-secret-password") &&
               !host_kv_raw->value().contains("e2ee-ultra-secret-passphrase") &&
               !host_kv_raw->value().contains("lan-secret-password"),
            "WebDAV/E2EE/LAN secrets MUST NEVER be stored in SQLite host_kv");

        // Also inspect raw SQLite file bytes on disk to guarantee zero plaintext secret leakage into SQLite pages/WAL.
        auto read_raw = [](std::filesystem::path const& p) {
            std::ifstream in(p, std::ios::binary);
            std::ostringstream ss;
            if (in) ss << in.rdbuf();
            return ss.str();
        };
        auto db_bytes = read_raw(dir / "nexus-client.db") + read_raw(dir / "nexus-client.db-wal");
        expect(!db_bytes.contains("dav-super-secret-password") &&
               !db_bytes.contains("e2ee-ultra-secret-passphrase") &&
               !db_bytes.contains("lan-secret-password"),
            "raw SQLite database and WAL files contain zero WebDAV/E2EE/LAN secrets");

        // Verify secrets are stored in 0600 secrets/sync-creds.json and re-hydrated cleanly by load_host_config_from_db.
        auto creds_path = sec_dir / "sync-creds.json";
        expect(std::filesystem::is_regular_file(creds_path), "0600 sync-creds.json created");
#ifndef _WIN32
        struct stat st{};
        expect(::stat(creds_path.c_str(), &st) == 0 && (st.st_mode & 0777) == 0600, "sync-creds.json has 0600 mode");
#endif
        auto host_reloaded = desktop::load_host_config_from_db(*db, dir, sec_dir, "/run/nexus.sock");
        expect(host_reloaded.workers == 24 &&
               host_reloaded.workers_spec == "max-2" &&
               host_reloaded.workers_max == 12 &&
               host_reloaded.mixed_listen == "127.0.0.1:7895" &&
               host_reloaded.webdav_url == "https://dav.example.net/nexus/" &&
               host_reloaded.webdav_password == "dav-super-secret-password" &&
               host_reloaded.sync_passphrase == "e2ee-ultra-secret-passphrase" &&
               host_reloaded.lan_password == "lan-secret-password",
            "load_host_config_from_db re-hydrates non-secrets (incl. workers/workers_spec/workers_max) from SQLite + secrets from 0600 file");

        // And verify desktop_host_to_core_json strips WebDAV/E2EE secrets while keeping mixed/lan settings.
        auto core_host_json = desktop::desktop_host_to_core_json(host_reloaded);
        expect(!core_host_json.contains("dav-super-secret-password") &&
               !core_host_json.contains("e2ee-ultra-secret-passphrase") &&
               core_host_json.contains("127.0.0.1:7895"),
            "desktop_host_to_core_json excludes WebDAV/E2EE secrets");

        // Defense-in-depth: set_host_kv refuses direct secret keys AND deeply nested objects/arrays.
        auto rej1 = db->set_host_kv("bad_top", R"({"webdav_password":"leak"})");
        auto rej2 = db->set_host_kv("bad_nested", R"({"desktop":{"sync_passphrase":"leak"}})");
        auto rej3 = db->set_host_kv("webdav_password", R"("raw-secret")");
        auto rej4 = db->set_host_kv("SYNC_PASSPHRASE", R"("raw-secret")");
        auto rej5 = db->set_host_kv("bad_deep", R"({"a":[{"b":{"lan_password":"deep-leak"}}]})");
        expect(!rej1.has_value() && !rej2.has_value() && !rej3.has_value() && !rej4.has_value() && !rej5.has_value(),
            "set_host_kv refuses direct secret keys and arbitrarily nested secrets");

        // save_host_config_to_db fails closed when secret-file write fails (does NOT clobber SQLite desktop_host).
        {
            auto pdir = make_temp_dir("partial-save");
            auto pdb = desktop::ClientDatabase::open(pdir / "nexus-client.db");
            expect(pdb.has_value(), "open db for partial-save test");
            auto h = desktop::make_default_desktop_host_config(pdir, "/run/nexus.sock");
            h.webdav_password = "must-not-lose";
            expect(!desktop::save_host_config_to_db(*pdb, {}, h), "save_host_config_to_db fails when secrets_dir is empty");
            auto kv_missing = pdb->get_host_kv("desktop_host");
            expect(kv_missing.has_value() && !kv_missing->has_value(),
                "desktop_host is NOT written to SQLite when save_sync_secrets fails");
            // Moved-from ClientDatabase returns clean unexpected instead of crashing.
            desktop::ClientDatabase moved_to = std::move(*pdb);
            expect(!pdb->user_version().has_value() && !pdb->get_host_kv("k").has_value() &&
                   !pdb->shrink_memory().has_value(),
                "moved-from ClientDatabase fails safely without UB");
            desktop::reclaim_process_memory(&*pdb);
            std::error_code pec;
            std::filesystem::remove_all(pdir, pec);
        }

        // Forward schema guard: PRAGMA user_version > 1 fails closed on open().
        {
            auto fdir = make_temp_dir("fwd-schema");
            auto fdb_path = fdir / "nexus-client.db";
            {
                auto fdb = desktop::ClientDatabase::open(fdb_path);
                expect(fdb.has_value(), "create v1 db");
            }
            {
                std::fstream io(fdb_path, std::ios::in | std::ios::out | std::ios::binary);
                expect(static_cast<bool>(io), "open db file to patch SQLite user_version header");
                io.seekp(60);
                unsigned char v99[4] = {0, 0, 0, 99};
                io.write(reinterpret_cast<char const*>(v99), 4);
                io.flush();
            }
            auto reopened = desktop::ClientDatabase::open(fdb_path);
            expect(!reopened.has_value(), "open() rejects future SQLite schema user_version > 1");
            std::error_code fec;
            std::filesystem::remove_all(fdir, fec);
        }

        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
}

auto main() -> int {
    try {
        test_schema_v1_workspace_vertical_split_and_cascade();
        test_telemetry_traffic_ledger_and_memory_reclaim();
        test_host_kv_secret_isolation_and_guards();
        std::println("nexus-desktop-client-db-tests: ALL PASSED");
        return 0;
    } catch (std::exception const& e) {
        std::println(std::cerr, "FAIL: {}", e.what());
        return 1;
    }
}
