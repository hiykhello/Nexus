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

module desktop.telemetry_store;

import std;
import desktop.mini_json;

namespace desktop {
    auto telemetry_to_json(TelemetryStoreData const& data) -> std::string {
        JsonArray arr;
        arr.reserve(data.entries.size());
        for (auto const& e : data.entries) {
            arr.emplace_back(JsonObject{
                {"profile_id", e.profile_id},
                {"delay_ms", e.delay_ms},
                {"speed_bps", e.speed_bps},
                {"up_bytes", e.up_bytes},
                {"down_bytes", e.down_bytes},
                {"last_tested_ms", e.last_tested_ms},
                {"sort_order", e.sort_order},
            });
        }
        JsonObject root{
            {"schema_version", data.schema_version},
            {"active_profile_id", data.active_profile_id},
            {"entries", JsonValue(std::move(arr))},
        };
        return json_stringify(JsonValue(std::move(root)), true);
    }

    auto telemetry_from_json(std::string_view text) -> std::expected<TelemetryStoreData, std::string> {
        auto parsed = json_parse(text);
        if (!parsed) return std::unexpected(parsed.error());
        if (!parsed->is_object()) return std::unexpected("telemetry.json root must be object");
        auto const& root = std::get<JsonObject>(parsed->data);
        TelemetryStoreData out{};
        out.schema_version = json_get_i64(root, "schema_version", 1);
        out.active_profile_id = json_get_string(root, "active_profile_id", "");
        if (auto const* arr = json_find(root, "entries"); arr && arr->is_array()) {
            for (auto const& elem : std::get<JsonArray>(arr->data)) {
                if (!elem.is_object()) continue;
                auto const& obj = std::get<JsonObject>(elem.data);
                auto id = json_get_string(obj, "profile_id");
                if (id.empty()) continue;
                out.entries.push_back({
                    std::move(id),
                    json_get_i64(obj, "delay_ms", -1),
                    json_get_i64(obj, "speed_bps", 0),
                    json_get_i64(obj, "up_bytes", 0),
                    json_get_i64(obj, "down_bytes", 0),
                    json_get_i64(obj, "last_tested_ms", 0),
                    json_get_i64(obj, "sort_order", 0),
                });
            }
        }
        return out;
    }

    auto load_telemetry_store(std::filesystem::path const& path) -> TelemetryStoreData {
        std::ifstream in(path, std::ios::binary);
        if (!in) return {};
        std::ostringstream ss;
        ss << in.rdbuf();
        auto parsed = telemetry_from_json(ss.str());
        return parsed ? *parsed : TelemetryStoreData{};
    }

    auto save_telemetry_store(std::filesystem::path const& path, TelemetryStoreData const& data) -> bool {
        auto const payload = telemetry_to_json(data);
        std::error_code ec;
        if (!path.parent_path().empty()) std::filesystem::create_directories(path.parent_path(), ec);
#ifdef _WIN32
        static std::atomic<std::uint64_t> seq{0};
        auto tmp = path;
        tmp += std::format(".tmp.{}.{}", ::GetCurrentProcessId(), seq.fetch_add(1, std::memory_order_relaxed));
        {
            std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
            if (!out) return false;
            out.write(payload.data(), static_cast<std::streamsize>(payload.size()));
            if (!out.good()) { out.close(); std::filesystem::remove(tmp, ec); return false; }
        }
        if (!::MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            std::filesystem::remove(tmp, ec);
            return false;
        }
        return true;
#else
        static std::atomic<std::uint64_t> seq{0};
        auto tmp = path.parent_path() /
            std::format(".{}.tmp.{}.{}", path.filename().string(), ::getpid(),
                        seq.fetch_add(1, std::memory_order_relaxed));
        int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0) return false;
        if (::fchmod(fd, 0600) != 0) { ::close(fd); ::unlink(tmp.c_str()); return false; }
        std::size_t off = 0;
        while (off < payload.size()) {
            auto n = ::write(fd, payload.data() + off, payload.size() - off);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) { ::close(fd); ::unlink(tmp.c_str()); return false; }
            off += static_cast<std::size_t>(n);
        }
        bool closed = (::close(fd) == 0);
        if (!closed || std::rename(tmp.c_str(), path.c_str()) != 0) { ::unlink(tmp.c_str()); return false; }
        return true;
#endif
    }

    auto prune_telemetry_entries(TelemetryStoreData& data, std::unordered_set<std::string> const& live_profile_ids) -> std::size_t {
        std::size_t before = data.entries.size();
        std::erase_if(data.entries, [&](ProfileTelemetryEntry const& e) {
            return !live_profile_ids.contains(e.profile_id);
        });
        if (!data.active_profile_id.empty() && !live_profile_ids.contains(data.active_profile_id)) {
            data.active_profile_id.clear();
        }
        return before - data.entries.size();
    }
}
