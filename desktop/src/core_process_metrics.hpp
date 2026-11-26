// Cross-platform OS-aligned private memory and CPU time sampling helpers for desktop/src/core_supervisor.cpp.
// Included inside module desktop.core_supervisor after OS headers and `import std;`.
#pragma once

namespace desktop::detail {
#ifdef _WIN32
    inline auto query_win_private_bytes(HANDLE proc) noexcept -> std::uint64_t {
        if (!proc) return 0;
        PROCESS_MEMORY_COUNTERS_EX pmc{};
        pmc.cb = sizeof(pmc);
        return ::K32GetProcessMemoryInfo(proc, reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))
            ? static_cast<std::uint64_t>(pmc.PrivateUsage) : 0;
    }

    inline auto query_win_cpu_time_ns(HANDLE proc) noexcept -> std::uint64_t {
        if (!proc) return 0;
        FILETIME created{}, exited{}, kernel{}, user{};
        if (!::GetProcessTimes(proc, &created, &exited, &kernel, &user)) return 0;
        ULARGE_INTEGER k{}, u{};
        k.LowPart = kernel.dwLowDateTime;
        k.HighPart = kernel.dwHighDateTime;
        u.LowPart = user.dwLowDateTime;
        u.HighPart = user.dwHighDateTime;
        std::uint64_t const ticks_100ns = k.QuadPart + u.QuadPart;
        return ticks_100ns <= (std::numeric_limits<std::uint64_t>::max() / 100ULL) ? (ticks_100ns * 100ULL) : 0;
    }
#elif defined(__linux__)
    inline auto parse_smaps_rollup_kb_line(std::string_view line, std::string_view key, std::uint64_t& out_kb) noexcept -> bool {
        if (!line.starts_with(key)) return false;
        auto rest = line.substr(key.size());
        while (!rest.empty() && (rest.front() == ' ' || rest.front() == '\t')) rest.remove_prefix(1);
        std::uint64_t kb = 0;
        auto [ptr, ec] = std::from_chars(rest.data(), rest.data() + rest.size(), kb);
        if (ec == std::errc{} && (ptr == rest.data() + rest.size() || *ptr == ' ' || *ptr == '\t' || *ptr == '\r')) {
            out_kb = kb;
            return true;
        }
        return false;
    }

    inline auto parse_smaps_rollup_private_bytes(std::string_view sv) noexcept -> std::uint64_t {
        std::uint64_t private_dirty_kb = 0;
        std::uint64_t swap_pss_kb = 0;
        bool has_private_dirty = false;
        std::size_t pos = 0;
        while (pos < sv.size()) {
            auto nl = sv.find('\n', pos);
            auto line = sv.substr(pos, nl == std::string_view::npos ? sv.size() - pos : nl - pos);
            if (!has_private_dirty && parse_smaps_rollup_kb_line(line, "Private_Dirty:", private_dirty_kb)) {
                has_private_dirty = true;
            } else {
                std::uint64_t sp = 0;
                if (parse_smaps_rollup_kb_line(line, "SwapPss:", sp)) swap_pss_kb = sp;
            }
            if (nl == std::string_view::npos) break;
            pos = nl + 1;
        }
        if (!has_private_dirty) return 0;
        constexpr std::uint64_t kKiB = 1024;
        std::uint64_t const total_kb = (private_dirty_kb <= std::numeric_limits<std::uint64_t>::max() - swap_pss_kb)
            ? (private_dirty_kb + swap_pss_kb) : private_dirty_kb;
        return total_kb <= (std::numeric_limits<std::uint64_t>::max() / kKiB) ? (total_kb * kKiB) : 0;
    }

    inline auto read_proc_smaps_rollup_private_bytes(char const* smaps_path) noexcept -> std::uint64_t {
        if (!smaps_path || !*smaps_path) return 0;
        int fd = ::open(smaps_path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) return 0;
        char buf[2048]{};
        std::size_t total = 0;
        while (total < sizeof(buf) - 1) {
            ssize_t n = ::read(fd, buf + total, sizeof(buf) - 1 - total);
            if (n < 0) { if (errno == EINTR) continue; total = 0; break; }
            if (n == 0) break;
            total += static_cast<std::size_t>(n);
        }
        ::close(fd);
        if (total == 0) return 0;
        return parse_smaps_rollup_private_bytes(std::string_view(buf, total));
    }

    inline auto read_proc_statm_rss_bytes(char const* statm_path) noexcept -> std::uint64_t {
        if (!statm_path || !*statm_path) return 0;
        int fd = ::open(statm_path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) return 0;
        char buf[128]{};
        ssize_t n = 0;
        do { n = ::read(fd, buf, sizeof(buf) - 1); } while (n < 0 && errno == EINTR);
        ::close(fd);
        if (n <= 0) return 0;
        std::string_view sv(buf, static_cast<std::size_t>(n));
        auto sp1 = sv.find(' ');
        if (sp1 == std::string_view::npos) return 0;
        while (sp1 < sv.size() && sv[sp1] == ' ') ++sp1;
        auto sp2 = sv.find_first_of(" \t\r\n", sp1);
        auto rss_sv = sv.substr(sp1, sp2 == std::string_view::npos ? sv.size() - sp1 : sp2 - sp1);
        std::uint64_t rss_pages = 0;
        auto [ptr, ec] = std::from_chars(rss_sv.data(), rss_sv.data() + rss_sv.size(), rss_pages);
        if (ec != std::errc{} || ptr != rss_sv.data() + rss_sv.size()) return 0;
        long const page_size = ::sysconf(_SC_PAGESIZE);
        if (page_size <= 0) return 0;
        auto const page_u64 = static_cast<std::uint64_t>(page_size);
        if (rss_pages > std::numeric_limits<std::uint64_t>::max() / page_u64) return 0;
        return rss_pages * page_u64;
    }

    inline auto read_proc_memory_bytes(char const* smaps_path, char const* statm_path) noexcept -> std::uint64_t {
        if (auto const priv = read_proc_smaps_rollup_private_bytes(smaps_path); priv > 0) return priv;
        return read_proc_statm_rss_bytes(statm_path);
    }

    inline auto read_proc_stat_cpu_time_ns(char const* stat_path) noexcept -> std::uint64_t {
        if (!stat_path || !*stat_path) return 0;
        int fd = ::open(stat_path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) return 0;
        char buf[1024]{};
        ssize_t n = 0;
        do { n = ::read(fd, buf, sizeof(buf) - 1); } while (n < 0 && errno == EINTR);
        ::close(fd);
        if (n <= 0) return 0;
        std::string_view sv(buf, static_cast<std::size_t>(n));
        auto rparen = sv.rfind(')');
        if (rparen == std::string_view::npos || rparen + 2 >= sv.size()) return 0;
        sv.remove_prefix(rparen + 2);
        // After ") ", fields start at index 3 (state); utime is field 14 (idx 11), stime is field 15 (idx 12).
        std::uint64_t utime = 0, stime = 0;
        int field = 0;
        while (!sv.empty() && field <= 12) {
            while (!sv.empty() && sv.front() == ' ') sv.remove_prefix(1);
            if (sv.empty()) break;
            auto sp = sv.find_first_of(" \t\r\n");
            auto tok = sv.substr(0, sp == std::string_view::npos ? sv.size() : sp);
            if (field == 11) {
                auto [ptr, ec] = std::from_chars(tok.data(), tok.data() + tok.size(), utime);
                if (ec != std::errc{} || ptr != tok.data() + tok.size()) return 0;
            } else if (field == 12) {
                auto [ptr, ec] = std::from_chars(tok.data(), tok.data() + tok.size(), stime);
                if (ec != std::errc{} || ptr != tok.data() + tok.size()) return 0;
            }
            if (sp == std::string_view::npos) break;
            sv.remove_prefix(sp + 1);
            ++field;
        }
        if (field < 12) return 0;
        long const clk = ::sysconf(_SC_CLK_TCK);
        if (clk <= 0) return 0;
        std::uint64_t const ticks = utime + stime;
        constexpr std::uint64_t kNsPerSec = 1'000'000'000ULL;
        auto const clk_u64 = static_cast<std::uint64_t>(clk);
        return (ticks / clk_u64) * kNsPerSec + ((ticks % clk_u64) * kNsPerSec) / clk_u64;
    }
#elif defined(__APPLE__)
    inline auto query_macos_phys_footprint_bytes(pid_t pid) noexcept -> std::uint64_t {
        if (pid <= 0) return 0;
        rusage_info_v2 rusage{};
        if (::proc_pid_rusage(pid, RUSAGE_INFO_V2, reinterpret_cast<rusage_info_t*>(&rusage)) == 0) {
            return static_cast<std::uint64_t>(rusage.ri_phys_footprint);
        }
        return 0;
    }

    inline auto query_macos_cpu_time_ns(pid_t pid) noexcept -> std::uint64_t {
        if (pid <= 0) return 0;
        rusage_info_v2 rusage{};
        if (::proc_pid_rusage(pid, RUSAGE_INFO_V2, reinterpret_cast<rusage_info_t*>(&rusage)) != 0) return 0;
        mach_timebase_info_data_t tb{};
        if (::mach_timebase_info(&tb) != KERN_SUCCESS || tb.denom == 0) return 0;
        std::uint64_t const raw = static_cast<std::uint64_t>(rusage.ri_user_time) +
                                  static_cast<std::uint64_t>(rusage.ri_system_time);
        return (raw / tb.denom) * tb.numer + ((raw % tb.denom) * tb.numer) / tb.denom;
    }
#endif

    inline auto query_self_pid() noexcept -> std::uint64_t {
#ifdef _WIN32
        return static_cast<std::uint64_t>(::GetCurrentProcessId());
#else
        return static_cast<std::uint64_t>(::getpid());
#endif
    }

    inline auto query_self_memory_bytes() noexcept -> std::uint64_t {
#ifdef _WIN32
        return query_win_private_bytes(::GetCurrentProcess());
#elif defined(__linux__)
        return read_proc_memory_bytes("/proc/self/smaps_rollup", "/proc/self/statm");
#elif defined(__APPLE__)
        return query_macos_phys_footprint_bytes(::getpid());
#else
        return 0;
#endif
    }

    inline auto query_self_cpu_time_ns() noexcept -> std::uint64_t {
#ifdef _WIN32
        return query_win_cpu_time_ns(::GetCurrentProcess());
#elif defined(__linux__)
        return read_proc_stat_cpu_time_ns("/proc/self/stat");
#elif defined(__APPLE__)
        return query_macos_cpu_time_ns(::getpid());
#else
        return 0;
#endif
    }

#ifndef _WIN32
    inline auto query_posix_pid_memory_bytes(std::uint64_t pid) noexcept -> std::uint64_t {
        if (pid == 0) return 0;
#ifdef __linux__
        char smaps[64]{}, statm[64]{};
        *std::format_to_n(smaps, sizeof(smaps) - 1, "/proc/{}/smaps_rollup", pid).out = '\0';
        *std::format_to_n(statm, sizeof(statm) - 1, "/proc/{}/statm", pid).out = '\0';
        return read_proc_memory_bytes(smaps, statm);
#elif defined(__APPLE__)
        return query_macos_phys_footprint_bytes(static_cast<pid_t>(pid));
#else
        return 0;
#endif
    }

    inline auto query_posix_pid_cpu_time_ns(std::uint64_t pid) noexcept -> std::uint64_t {
        if (pid == 0) return 0;
#ifdef __linux__
        char stat_path[64]{};
        *std::format_to_n(stat_path, sizeof(stat_path) - 1, "/proc/{}/stat", pid).out = '\0';
        return read_proc_stat_cpu_time_ns(stat_path);
#elif defined(__APPLE__)
        return query_macos_cpu_time_ns(static_cast<pid_t>(pid));
#else
        return 0;
#endif
    }
#endif
}
