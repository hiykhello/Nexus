module cli.proxy_services;
import std;
import config;
import logging;
import logging.cli;
import memory.watchdog;

namespace cli {
    namespace {
        struct WatchdogState {
            memory::MemoryWatchdog dog;
            WatchdogHooks hooks;
            std::uint64_t next_sample_ms = 0;
            memory::PressureLevel last_level = memory::PressureLevel::normal;
            WatchdogState(memory::WatchdogPolicy p, WatchdogHooks h) noexcept
                : dog(p), hooks(std::move(h)) {}
            ~WatchdogState() {
                if (hooks.shed_new_sessions)
                    hooks.shed_new_sessions->store(false, std::memory_order_release);
            }
        };
    }

    auto init_watchdog_service(config::MemoryWatchdogConfig const& cfg, logging::Runtime& logs, WatchdogHooks hooks)
        -> std::expected<ServiceHandle, std::string> {
        constexpr std::uint64_t mib = 1024ull * 1024ull;
        memory::WatchdogPolicy policy{cfg.soft_mb * mib, cfg.hard_mb * mib, cfg.emergency_mb * mib, cfg.cooldown_ms};
        auto state = std::make_unique<WatchdogState>(policy, std::move(hooks));
        logs.emit(logging::Level::info, logging::Domain::core, 109, {},
            "memory-watchdog enabled soft_mb={} hard_mb={} emergency_mb={}",
            cfg.soft_mb, cfg.hard_mb, cfg.emergency_mb);
        auto tick = [](void* ptr, std::uint64_t now_ms, logging::Runtime& rt) noexcept {
            auto* s = static_cast<WatchdogState*>(ptr);
            if (now_ms < s->next_sample_ms) return;
            s->next_sample_ms = now_ms + 1000;
            auto lvl = s->dog.sample_and_evaluate(now_ms, [&](memory::PressureLevel p) {
                if (p != memory::PressureLevel::normal && s->hooks.on_reclaim)
                    s->hooks.on_reclaim(static_cast<std::uint8_t>(p));
            });
            if (s->hooks.shed_new_sessions)
                s->hooks.shed_new_sessions->store(lvl == memory::PressureLevel::emergency, std::memory_order_release);
            if (lvl != s->last_level) {
                s->last_level = lvl;
                rt.emit(lvl == memory::PressureLevel::emergency ? logging::Level::warn : logging::Level::info,
                    logging::Domain::core, 109, {}, "memory-watchdog pressure_level={}", static_cast<int>(lvl));
            }
        };
        return ServiceHandle::create(std::move(state), tick);
    }
}
