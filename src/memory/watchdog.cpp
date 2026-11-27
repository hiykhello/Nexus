module;
#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <psapi.h>
#elif defined(__APPLE__)
#include <mach/mach.h>
#elif defined(__linux__)
#include <unistd.h>
#endif

module memory.watchdog;
import std;
import functional;

namespace memory {
    namespace {
        auto trim_crlf(std::string_view sv) noexcept -> std::string_view {
            while (!sv.empty() && (sv.back() == '\r' || sv.back() == '\n')) sv.remove_suffix(1);
            return sv;
        }

        auto safe_cgroup_rel_path(std::string_view rel) noexcept -> bool {
            if (rel.empty() || rel.front() != '/') return false;
            std::size_t pos = 1;
            while (pos <= rel.size()) {
                auto slash = rel.find('/', pos);
                auto seg = slash == std::string_view::npos ? rel.substr(pos) : rel.substr(pos, slash - pos);
                if (seg == "..") return false;
                if (slash == std::string_view::npos) break;
                pos = slash + 1;
            }
            return true;
        }

#if defined(__linux__)
        auto read_text_small(char const* path, std::size_t max_bytes = 4096) noexcept -> std::optional<std::string> {
            std::FILE* fp = std::fopen(path, "r");
            if (!fp) return std::nullopt;
            std::string out;
            try {
                char buf[512];
                while (out.size() < max_bytes) {
                    auto want = std::min(sizeof(buf), max_bytes - out.size());
                    auto got = std::fread(buf, 1, want, fp);
                    if (got == 0) break;
                    out.append(buf, got);
                }
            } catch (...) {
                std::fclose(fp);
                return std::nullopt;
            }
            std::fclose(fp);
            return out;
        }

        auto read_u64_file(std::string const& path) noexcept -> std::optional<std::uint64_t> {
            std::FILE* fp = std::fopen(path.c_str(), "r");
            if (!fp) return std::nullopt;
            char buf[64]{};
            auto got = std::fread(buf, 1, sizeof(buf) - 1, fp);
            std::fclose(fp);
            if (got == 0) return std::nullopt;
            auto sv = trim_crlf(std::string_view(buf, got));
            if (sv.empty() || sv == "max") return std::nullopt;
            std::uint64_t value = 0;
            auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), value);
            if (ec != std::errc{} || ptr != sv.data() + sv.size()) return std::nullopt;
            return value;
        }
#endif

        auto pct_reached(std::uint64_t used, std::uint64_t limit, std::uint64_t pct) noexcept -> bool {
            if (limit == 0) return false;
            if (used >= limit) return true;
            auto const q = limit / 100u;
            auto const r = limit % 100u;
            auto const threshold = q * pct + (r * pct + 99u) / 100u;
            return used >= threshold;
        }
    }

    auto parse_cgroup_v2_path(std::string_view proc_cgroup_content) -> std::optional<std::string> {
        std::size_t pos = 0;
        while (pos < proc_cgroup_content.size()) {
            auto nl = proc_cgroup_content.find('\n', pos);
            auto line = trim_crlf(nl == std::string_view::npos
                ? proc_cgroup_content.substr(pos)
                : proc_cgroup_content.substr(pos, nl - pos));
            if (line.starts_with("0::")) {
                auto rel = line.substr(3);
                if (!safe_cgroup_rel_path(rel)) return std::nullopt;
                return std::string(rel);
            }
            if (nl == std::string_view::npos) break;
            pos = nl + 1;
        }
        return std::nullopt;
    }

    auto sample_process_rss_bytes() noexcept -> std::uint64_t {
#if defined(_WIN32)
        PROCESS_MEMORY_COUNTERS pmc{};
        if (::GetProcessMemoryInfo(::GetCurrentProcess(), &pmc, sizeof(pmc)))
            return static_cast<std::uint64_t>(pmc.WorkingSetSize);
        return 0;
#elif defined(__APPLE__)
        task_vm_info_data_t info{};
        mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
        if (::task_info(mach_task_self(), TASK_VM_INFO, reinterpret_cast<task_info_t>(&info), &count) == KERN_SUCCESS)
            return static_cast<std::uint64_t>(info.phys_footprint ? info.phys_footprint : info.resident_size);
        return 0;
#elif defined(__linux__)
        std::uint64_t rss_bytes = 0;
        if (std::FILE* fp = std::fopen("/proc/self/statm", "r")) {
            unsigned long total = 0, resident = 0;
            if (std::fscanf(fp, "%lu %lu", &total, &resident) == 2) {
                long ps = ::sysconf(_SC_PAGESIZE);
                if (ps > 0) rss_bytes = static_cast<std::uint64_t>(resident) * static_cast<std::uint64_t>(ps);
            }
            std::fclose(fp);
        }
        return rss_bytes;
#else
        return 0;
#endif
    }

    auto sample_memory_usage() noexcept -> MemorySample {
        MemorySample sample{};
        sample.process_rss_bytes = sample_process_rss_bytes();
#if defined(__linux__)
        if (auto content = read_text_small("/proc/self/cgroup")) {
            try {
                if (auto rel = parse_cgroup_v2_path(*content); rel && *rel != "/") {
                    sample.cgroup_is_root = false;
                    std::string base = "/sys/fs/cgroup" + *rel;
                    if (auto cur = read_u64_file(base + "/memory.current"))
                        sample.cgroup_bytes = *cur;
                    if (auto lim = read_u64_file(base + "/memory.max"); lim && *lim > 0)
                        sample.cgroup_limit_bytes = *lim;
                }
            } catch (...) {}
        }
#endif
        return sample;
    }

    auto classify_pressure(MemorySample const& sample, WatchdogPolicy const& policy) noexcept -> PressureLevel {
        PressureLevel rss_level = PressureLevel::normal;
        if (sample.process_rss_bytes >= policy.emergency_bytes) rss_level = PressureLevel::emergency;
        else if (sample.process_rss_bytes >= policy.hard_bytes) rss_level = PressureLevel::hard;
        else if (sample.process_rss_bytes >= policy.soft_bytes) rss_level = PressureLevel::soft;

        PressureLevel cg_level = PressureLevel::normal;
        if (!sample.cgroup_is_root && sample.cgroup_limit_bytes > 0 && sample.cgroup_bytes > 0) {
            if (pct_reached(sample.cgroup_bytes, sample.cgroup_limit_bytes, 95)) cg_level = PressureLevel::emergency;
            else if (pct_reached(sample.cgroup_bytes, sample.cgroup_limit_bytes, 88)) cg_level = PressureLevel::hard;
            else if (pct_reached(sample.cgroup_bytes, sample.cgroup_limit_bytes, 75)) cg_level = PressureLevel::soft;
        }
        return static_cast<std::uint8_t>(cg_level) > static_cast<std::uint8_t>(rss_level) ? cg_level : rss_level;
    }

    auto MemoryWatchdog::evaluate(MemorySample const& sample, std::uint64_t now_ms,
                                  functional::function_ref<void(PressureLevel)> on_pressure) -> PressureLevel {
        ++stats_.evaluations;
        stats_.last_rss_bytes = sample.process_rss_bytes;
        stats_.peak_rss_bytes = std::max(stats_.peak_rss_bytes, sample.process_rss_bytes);
        stats_.last_cgroup_bytes = sample.cgroup_bytes;
        stats_.last_cgroup_limit_bytes = sample.cgroup_limit_bytes;

        auto const prev = stats_.level;
        auto const next = classify_pressure(sample, policy_);

        if (next == PressureLevel::normal) {
            stats_.level = PressureLevel::normal;
            has_acted_ = false;
            if (prev != PressureLevel::normal) on_pressure(PressureLevel::normal);
            return next;
        }

        bool escalating = static_cast<std::uint8_t>(next) > static_cast<std::uint8_t>(prev);
        bool cooldown_elapsed = !has_acted_ || now_ms >= last_action_ms_ + policy_.cooldown_ms;
        stats_.level = next;

        if (escalating || cooldown_elapsed) {
            has_acted_ = true;
            last_action_ms_ = now_ms;
            if (next == PressureLevel::soft) ++stats_.soft_reclaims;
            else if (next == PressureLevel::hard) ++stats_.hard_reclaims;
            else ++stats_.emergency_sheds;
            on_pressure(next);
        }
        return next;
    }

    auto MemoryWatchdog::evaluate(std::uint64_t rss_bytes, std::uint64_t now_ms,
                                  functional::function_ref<void(PressureLevel)> on_pressure) -> PressureLevel {
        return evaluate(MemorySample{.process_rss_bytes = rss_bytes}, now_ms, on_pressure);
    }

    auto MemoryWatchdog::sample_and_evaluate(std::uint64_t now_ms,
                                             functional::function_ref<void(PressureLevel)> on_pressure) -> PressureLevel {
        return evaluate(sample_memory_usage(), now_ms, on_pressure);
    }
}
