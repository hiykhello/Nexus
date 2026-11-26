// Host parallelism detection and KDL workers specification parser.
module;
#if defined(__linux__)
#include <cerrno>
#include <sched.h>
#endif

module config;
import std;
import config.kdl_common;

namespace config {
    using namespace config::kdl;

    namespace {
        auto parse_unsigned_digits(std::string_view text) noexcept -> std::optional<unsigned> {
            if (text.empty()) return {};
            for (unsigned char c : text)
                if (c < '0' || c > '9') return {};
            unsigned value = 0;
            auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
            if (ec != std::errc{} || end != text.data() + text.size()) return {};
            return value;
        }

        auto parse_spec_offset(std::string_view spec) noexcept -> std::optional<unsigned> {
            if (spec == "auto" || spec == "max") return 0u;
            if (spec.starts_with("max-")) return parse_unsigned_digits(spec.substr(4));
            if (spec.starts_with("auto-")) return parse_unsigned_digits(spec.substr(5));
            return {};
        }

#if defined(__linux__)
        auto parse_u64_token(std::string_view text) noexcept -> std::optional<std::uint64_t> {
            if (text.empty()) return {};
            for (unsigned char c : text)
                if (c < '0' || c > '9') return {};
            std::uint64_t value = 0;
            auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
            if (ec != std::errc{} || end != text.data() + text.size()) return {};
            return value;
        }

        auto parse_i64_token(std::string_view text) noexcept -> std::optional<std::int64_t> {
            if (text.empty()) return {};
            std::int64_t value = 0;
            auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
            if (ec != std::errc{} || end != text.data() + text.size()) return {};
            return value;
        }

        auto ceil_quota_cpus(std::uint64_t quota, std::uint64_t period) noexcept -> unsigned {
            if (quota == 0 || period == 0) return 0u;
            std::uint64_t q = quota / period + ((quota % period) != 0 ? 1u : 0u);
            if (q == 0) q = 1;
            auto cap = static_cast<std::uint64_t>(std::numeric_limits<unsigned>::max());
            return static_cast<unsigned>(std::min(q, cap));
        }

        auto safe_cgroup_relpath(std::string_view rel) -> std::optional<std::filesystem::path> {
            while (!rel.empty() && (rel.back() == '\r' || rel.back() == '\n')) rel.remove_suffix(1);
            if (rel.empty() || rel == "/") return std::filesystem::path{};
            if (rel.front() != '/') return {};
            std::filesystem::path out;
            std::size_t pos = 1;
            while (pos < rel.size()) {
                auto slash = rel.find('/', pos);
                auto seg = slash == std::string_view::npos ? rel.substr(pos) : rel.substr(pos, slash - pos);
                if (seg == "..") return {};
                if (!seg.empty() && seg != ".") out /= seg;
                if (slash == std::string_view::npos) break;
                pos = slash + 1;
            }
            return out;
        }

        auto has_cpu_controller(std::string_view list) noexcept -> bool {
            std::size_t pos = 0;
            while (pos <= list.size()) {
                auto comma = list.find(',', pos);
                auto token = comma == std::string_view::npos ? list.substr(pos) : list.substr(pos, comma - pos);
                if (token == "cpu") return true;
                if (comma == std::string_view::npos) break;
                pos = comma + 1;
            }
            return false;
        }

        auto detect_cgroup_quota_cpus() -> unsigned {
            unsigned best = 0;
            auto combine = [&](unsigned v) noexcept {
                if (v > 0 && (best == 0 || v < best)) best = v;
            };

            std::optional<std::string> v2_rel;
            std::optional<std::string> v1_cpu_rel;
            {
                std::ifstream cg("/proc/self/cgroup");
                std::string line;
                while (std::getline(cg, line)) {
                    if (!line.empty() && line.back() == '\r') line.pop_back();
                    auto c1 = line.find(':');
                    if (c1 == std::string::npos) continue;
                    auto c2 = line.find(':', c1 + 1);
                    if (c2 == std::string::npos) continue;
                    auto id = std::string_view(line).substr(0, c1);
                    auto ctrls = std::string_view(line).substr(c1 + 1, c2 - c1 - 1);
                    auto path = std::string_view(line).substr(c2 + 1);
                    if (id == "0" && ctrls.empty()) {
                        v2_rel = std::string(path);
                    } else if (!v1_cpu_rel && has_cpu_controller(ctrls)) {
                        v1_cpu_rel = std::string(path);
                    }
                }
            }

            std::filesystem::path const v2_root("/sys/fs/cgroup");
            bool v2_present = false;
            auto scan_v2 = [&](std::filesystem::path cur) {
                for (unsigned depth = 0; depth < 64; ++depth) {
                    std::ifstream f(cur / "cpu.max");
                    if (f.is_open()) {
                        v2_present = true;
                        std::string q_tok, p_tok;
                        if (f >> q_tok >> p_tok && q_tok != "max") {
                            auto q = parse_u64_token(q_tok);
                            auto p = parse_u64_token(p_tok);
                            if (q && p && *q > 0 && *p > 0) combine(ceil_quota_cpus(*q, *p));
                        }
                    }
                    if (cur == v2_root) break;
                    auto parent = cur.parent_path();
                    if (parent.empty() || parent == cur) break;
                    cur = std::move(parent);
                }
            };

            if (v2_rel) {
                if (auto rel = safe_cgroup_relpath(*v2_rel))
                    scan_v2(rel->empty() ? v2_root : (v2_root / *rel));
            } else {
                std::error_code ec;
                if (std::filesystem::exists(v2_root / "cgroup.controllers", ec))
                    scan_v2(v2_root);
            }

            if (best == 0 && !v2_present && v1_cpu_rel) {
                if (auto rel = safe_cgroup_relpath(*v1_cpu_rel)) {
                    for (char const* mount : {"/sys/fs/cgroup/cpu,cpuacct", "/sys/fs/cgroup/cpu"}) {
                        std::filesystem::path base(mount);
                        std::error_code ec;
                        if (!std::filesystem::is_directory(base, ec)) continue;
                        auto cur = rel->empty() ? base : (base / *rel);
                        for (unsigned depth = 0; depth < 64; ++depth) {
                            std::ifstream fq(cur / "cpu.cfs_quota_us");
                            std::ifstream fp(cur / "cpu.cfs_period_us");
                            std::string qs, ps;
                            if ((fq >> qs) && (fp >> ps)) {
                                auto q = parse_i64_token(qs);
                                auto p = parse_i64_token(ps);
                                if (q && p && *q > 0 && *p > 0)
                                    combine(ceil_quota_cpus(static_cast<std::uint64_t>(*q),
                                                            static_cast<std::uint64_t>(*p)));
                            }
                            if (cur == base) break;
                            auto parent = cur.parent_path();
                            if (parent.empty() || parent == cur) break;
                            cur = std::move(parent);
                        }
                        if (best > 0) break;
                    }
                }
            }
            return best;
        }
#endif
    }

    auto detect_host_parallelism() noexcept -> unsigned {
        unsigned result = 0;
        auto combine = [&](unsigned v) noexcept {
            if (v > 0 && (result == 0 || v < result)) result = v;
        };
        combine(std::thread::hardware_concurrency());
#if defined(__linux__)
        try {
            cpu_set_t set{};
            CPU_ZERO(&set);
            if (::sched_getaffinity(0, sizeof(set), &set) == 0) {
                int count = CPU_COUNT(&set);
                if (count > 0) combine(static_cast<unsigned>(count));
            }
#if defined(CPU_ALLOC) && defined(CPU_ALLOC_SIZE) && defined(CPU_COUNT_S) && defined(CPU_FREE)
            else if (errno == EINVAL) {
                for (std::size_t ncpus = 2048; ncpus <= 65536; ncpus *= 2) {
                    cpu_set_t* dyn = CPU_ALLOC(ncpus);
                    if (!dyn) break;
                    std::size_t bytes = CPU_ALLOC_SIZE(ncpus);
                    CPU_ZERO_S(bytes, dyn);
                    int rc = ::sched_getaffinity(0, bytes, dyn);
                    int err = errno;
                    if (rc == 0) {
                        int count = CPU_COUNT_S(bytes, dyn);
                        CPU_FREE(dyn);
                        if (count > 0) combine(static_cast<unsigned>(count));
                        break;
                    }
                    CPU_FREE(dyn);
                    if (err != EINVAL) break;
                }
            }
#endif
            combine(detect_cgroup_quota_cpus());
        } catch (...) {
        }
#endif
        return result > 0 ? result : 1u;
    }

    auto validate_workers_spec(std::string_view spec) noexcept -> bool {
        return parse_spec_offset(spec).has_value();
    }

    auto resolve_workers_spec(std::string_view spec, std::optional<unsigned> max_cap, unsigned host_parallelism)
        -> std::expected<unsigned, std::string> {
        auto offset = parse_spec_offset(spec);
        if (!offset)
            return error("workers must be a positive integer or \"auto\", \"max\", \"auto-<N>\", or \"max-<N>\"");
        if (max_cap && *max_cap == 0)
            return error("workers max must be an integer >= 1");
        unsigned h = std::max(1u, host_parallelism);
        unsigned resolved = h > *offset ? (h - *offset) : 1u;
        if (max_cap) resolved = std::min(resolved, *max_cap);
        return std::max(1u, resolved);
    }

    auto parse_workers_node(Node const& node, Config& result, bool& workers_seen)
        -> std::expected<void, std::string> {
        if (workers_seen) return error("duplicate workers configuration");
        if (node.tag || !node.children.empty() || node.arguments.size() != 1)
            return error("workers must be a positive integer or \"auto\", \"max\", \"auto-<N>\", or \"max-<N>\"");
        auto const& arg = node.arguments.front();
        if (arg.tag)
            return error("workers argument must not have a type annotation");
        if (auto value = kdl::integer(arg)) {
            if (!node.properties.empty())
                return error("workers max property is only allowed with string specifications");
            if (*value == 0 || *value > std::numeric_limits<unsigned>::max())
                return error("workers must be a positive integer");
            unsigned requested = static_cast<unsigned>(*value);
            unsigned h = std::max(1u, result.host_parallelism);
            if (requested > h) {
                result.workers = h;
                result.workers_clamped_from = requested;
            } else {
                result.workers = requested;
                result.workers_clamped_from.reset();
            }
            workers_seen = true;
            return {};
        }
        if (auto text = kdl::string(arg)) {
            std::optional<unsigned> max_cap;
            if (!node.properties.empty()) {
                auto max_prop = kdl::property(node, "max");
                if (!max_prop || node.properties.size() != 1)
                    return error("workers only supports the optional max=<N> property");
                auto max_val = kdl::integer(*max_prop);
                if (!max_val || *max_val == 0 || *max_val > std::numeric_limits<unsigned>::max())
                    return error("workers max must be an integer >= 1");
                max_cap = static_cast<unsigned>(*max_val);
            }
            auto resolved = resolve_workers_spec(*text, max_cap, result.host_parallelism);
            if (!resolved) return std::unexpected(std::move(resolved.error()));
            result.workers = *resolved;
            result.workers_clamped_from.reset();
            workers_seen = true;
            return {};
        }
        return error("workers must be a positive integer or \"auto\", \"max\", \"auto-<N>\", or \"max-<N>\"");
    }
}
