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
        if (std::FILE* cg = std::fopen("/sys/fs/cgroup/memory.current", "r")) {
            unsigned long long cg_bytes = 0;
            if (std::fscanf(cg, "%llu", &cg_bytes) == 1 && cg_bytes > 0)
                rss_bytes = rss_bytes ? std::max(rss_bytes, static_cast<std::uint64_t>(cg_bytes)) : cg_bytes;
            std::fclose(cg);
        }
        return rss_bytes;
#else
        return 0;
#endif
    }

    auto MemoryWatchdog::evaluate(std::uint64_t rss_bytes, std::uint64_t now_ms,
                                  functional::function_ref<void(PressureLevel)> on_pressure) -> PressureLevel {
        ++stats_.evaluations;
        stats_.last_rss_bytes = rss_bytes;
        stats_.peak_rss_bytes = std::max(stats_.peak_rss_bytes, rss_bytes);

        auto const prev = stats_.level;
        PressureLevel next = PressureLevel::normal;
        if (rss_bytes >= policy_.emergency_bytes) next = PressureLevel::emergency;
        else if (rss_bytes >= policy_.hard_bytes) next = PressureLevel::hard;
        else if (rss_bytes >= policy_.soft_bytes) next = PressureLevel::soft;

        if (next == PressureLevel::normal) {
            stats_.level = PressureLevel::normal;
            has_acted_ = false;
            if (prev != PressureLevel::normal) on_pressure(PressureLevel::normal);
            return next;
        }

        bool escalating = static_cast<std::uint8_t>(next) > static_cast<std::uint8_t>(prev);
        bool cooldown_elapsed = !has_acted_ || now_ms >= last_action_ms_ + policy_.cooldown_ms;
        stats_.level = next;

        if (next != PressureLevel::normal && (escalating || cooldown_elapsed)) {
            has_acted_ = true;
            last_action_ms_ = now_ms;
            if (next == PressureLevel::soft) ++stats_.soft_reclaims;
            else if (next == PressureLevel::hard) ++stats_.hard_reclaims;
            else ++stats_.emergency_sheds;
            on_pressure(next);
        }
        return next;
    }

    auto MemoryWatchdog::sample_and_evaluate(std::uint64_t now_ms,
                                             functional::function_ref<void(PressureLevel)> on_pressure) -> PressureLevel {
        return evaluate(sample_process_rss_bytes(), now_ms, on_pressure);
    }
}
