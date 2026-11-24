module desktop.tray_controller;

import std;

namespace desktop {
    namespace {
        auto format_legacy_tooltip(TrayState st, std::string_view detail) -> std::string {
            std::string_view base = "Nexus - 已停止";
            if (st == TrayState::running) base = "Nexus - 运行中";
            else if (st == TrayState::tun_active) base = "Nexus - TUN 已接管";
            else if (st == TrayState::degraded) base = "Nexus - 连接波动";
            return detail.empty() ? std::string(base) : std::format("{} ({})", base, detail);
        }

        auto format_primary_header(TraySnapshot const& snap) -> std::string {
            std::string_view status = snap.is_en ? "Disconnected" : "未连接";
            if (snap.state == TrayState::running) status = snap.is_en ? "Connected" : "已连接";
            else if (snap.state == TrayState::tun_active) status = snap.is_en ? "TUN Active" : "TUN 运行中";
            else if (snap.state == TrayState::degraded) status = snap.is_en ? "Degraded" : "连接波动";

            auto line = std::format("Nexus · {}", status);
            if (snap.core_running && !snap.active_node.empty()) {
                line += snap.active_latency.empty()
                    ? std::format(" · {}", snap.active_node)
                    : std::format(" · {} ({})", snap.active_node, snap.active_latency);
            }
            return line;
        }

        auto format_speed_line(TraySnapshot const& snap) -> std::string {
            if (!snap.show_speed || !snap.core_running) return {};
            if (snap.download_rate.empty() && snap.upload_rate.empty()) return {};
            std::string_view dl = snap.download_rate.empty() ? std::string_view("0 B/s") : std::string_view(snap.download_rate);
            std::string_view ul = snap.upload_rate.empty() ? std::string_view("0 B/s") : std::string_view(snap.upload_rate);
            return std::format("↓ {} · ↑ {}", dl, ul);
        }
    }

    namespace detail {
        auto native_tray_disabled_by_env() noexcept -> bool {
            char const* raw = std::getenv("NEXUS_DISABLE_NATIVE_TRAY");
            if (!raw || !*raw) return false;
            std::string_view sv(raw);
            return sv == "1" || sv == "true" || sv == "TRUE" || sv == "yes" || sv == "YES";
        }

        // Renders an anti-aliased 32x32 Optical Precision prism badge in ARGB32 network byte order.
        auto render_prism_icon_argb32(TrayState state) -> std::array<std::uint8_t, 32 * 32 * 4> {
            struct Rgb { float r, g, b; };
            Rgb hi{148.f, 163.f, 184.f}, lo{71.f, 85.f, 105.f}; // Slate (offline)
            if (state == TrayState::running) { hi = {52.f, 211.f, 153.f}; lo = {5.f, 150.f, 105.f}; }
            else if (state == TrayState::tun_active) { hi = {56.f, 189.f, 248.f}; lo = {2.f, 132.f, 199.f}; }
            else if (state == TrayState::degraded) { hi = {251.f, 191.f, 36.f}; lo = {217.f, 119.f, 6.f}; }

            std::array<std::uint8_t, 32 * 32 * 4> buf{};
            auto u8 = [](float v) { return static_cast<std::uint8_t>(std::clamp(std::lround(v), 0l, 255l)); };
            for (int y = 0; y < 32; ++y) {
                for (int x = 0; x < 32; ++x) {
                    float const u = (static_cast<float>(x) + 0.5f) / 16.0f - 1.0f;
                    float const v = (static_cast<float>(y) + 0.5f) / 16.0f - 1.0f;
                    float const d = std::abs(u) + std::abs(v);
                    float const alpha = std::clamp((0.90f - d) * 14.0f, 0.0f, 1.0f);
                    if (alpha <= 0.004f) continue;
                    float const f = std::clamp(0.5f + (u + v) * 0.42f, 0.0f, 1.0f);
                    float const ring = std::clamp(1.0f - std::abs(d - 0.44f) * 16.0f, 0.0f, 1.0f);
                    float const core = (state != TrayState::offline) ? std::clamp((0.20f - d) * 16.0f, 0.0f, 1.0f) : 0.0f;
                    float const rim = std::clamp((d - 0.78f) * 12.0f, 0.0f, 1.0f) * 0.25f;
                    float const glow = std::clamp(ring * 0.85f + core * 0.95f + rim, 0.0f, 1.0f);
                    std::size_t const off = static_cast<std::size_t>((y * 32 + x) * 4);
                    buf[off + 0] = u8(alpha * 255.0f);
                    buf[off + 1] = u8((hi.r * (1.f - f) + lo.r * f) * (1.f - glow) + 255.f * glow);
                    buf[off + 2] = u8((hi.g * (1.f - f) + lo.g * f) * (1.f - glow) + 255.f * glow);
                    buf[off + 3] = u8((hi.b * (1.f - f) + lo.b * f) * (1.f - glow) + 255.f * glow);
                }
            }
            return buf;
        }

        auto escape_dbusmenu_label(std::string_view raw) -> std::string {
            std::string out;
            out.reserve(raw.size() + 4);
            for (char c : raw) {
                if (c == '_') out.append("__");
                else out.push_back(c);
            }
            return out;
        }

        auto find_menu_item(std::vector<TrayMenuItem> const& items, std::int32_t id) -> TrayMenuItem const* {
            for (auto const& it : items) {
                if (it.id == id) return &it;
                if (auto const* found = find_menu_item(it.children, id)) return found;
            }
            return nullptr;
        }

        auto flatten_menu_items(std::vector<TrayMenuItem> const& items, std::vector<TrayMenuItem const*>& out) -> void {
            for (auto const& it : items) {
                out.push_back(&it);
                flatten_menu_items(it.children, out);
            }
        }
    }

    auto format_tray_tooltip(TraySnapshot const& snap) -> std::string {
        auto tip = format_primary_header(snap);
        if (auto speed = format_speed_line(snap); !speed.empty()) {
            tip.push_back('\n');
            tip.append(speed);
        }
        return tip;
    }

    auto build_tray_menu(TraySnapshot const& snap) -> std::vector<TrayMenuItem> {
        using namespace detail;
        bool const en = snap.is_en;
        std::vector<TrayMenuItem> items;
        items.reserve(16);

        items.push_back({kMenuHeaderStatus, TrayMenuKind::header, format_primary_header(snap), false, false, {}});
        if (auto speed = format_speed_line(snap); !speed.empty()) {
            items.push_back({kMenuHeaderSpeed, TrayMenuKind::header, std::move(speed), false, false, {}});
        }

        items.push_back({kMenuToggleWindow, TrayMenuKind::action,
            snap.window_visible ? (en ? "Hide Window" : "隐藏主窗口") : (en ? "Show Window" : "显示主窗口"),
            true, false, {}});
        items.push_back({kMenuToggleCore, TrayMenuKind::action,
            snap.core_running ? (en ? "Disconnect" : "停止连接") : (en ? "Connect" : "一键连接"),
            true, false, {}});
        items.push_back({kMenuSep1, TrayMenuKind::separator, {}, false, false, {}});

        items.push_back({kMenuSystemProxy, TrayMenuKind::checkbox,
            en ? "System Proxy" : "系统代理", true, snap.system_proxy_enabled, {}});
        items.push_back({kMenuTun, TrayMenuKind::checkbox,
            en ? "TUN Mode" : "TUN 模式", true, snap.tun_enabled, {}});

        bool const is_global = snap.outbound_mode == "global";
        bool const is_direct = snap.outbound_mode == "direct";
        bool const is_rule = !is_global && !is_direct;
        items.push_back({kMenuModeSubmenu, TrayMenuKind::submenu, en ? "Routing Mode" : "分流模式", true, false, {
            {kMenuModeRule, TrayMenuKind::radio, en ? "Rule" : "规则", true, is_rule, {}},
            {kMenuModeGlobal, TrayMenuKind::radio, en ? "Global" : "全局", true, is_global, {}},
            {kMenuModeDirect, TrayMenuKind::radio, en ? "Direct" : "直连", true, is_direct, {}},
        }});

        if (snap.show_nodes && !snap.quick_nodes.empty()) {
            TrayMenuItem sub{kMenuNodesSubmenu, TrayMenuKind::submenu, en ? "Quick Nodes" : "快捷切换节点", true, false, {}};
            std::size_t const limit = std::min(snap.quick_nodes.size(), kMaxQuickNodes);
            sub.children.reserve(limit);
            for (std::size_t i = 0; i < limit; ++i) {
                auto const& node = snap.quick_nodes[i];
                std::string label = node.latency_label.empty()
                    ? node.name : std::format("{}  {}", node.name, node.latency_label);
                sub.children.push_back({kMenuNodeBase + static_cast<std::int32_t>(i),
                    TrayMenuKind::radio, std::move(label), true, node.active, {}});
            }
            items.push_back(std::move(sub));
        }

        if (snap.profiles.size() > 1) {
            TrayMenuItem sub{kMenuProfilesSubmenu, TrayMenuKind::submenu, en ? "Profiles" : "配置档案", true, false, {}};
            std::size_t const limit = std::min(snap.profiles.size(), kMaxProfiles);
            sub.children.reserve(limit);
            for (std::size_t i = 0; i < limit; ++i) {
                auto const& prof = snap.profiles[i];
                sub.children.push_back({kMenuProfileBase + static_cast<std::int32_t>(i),
                    TrayMenuKind::radio, prof.name.empty() ? prof.id : prof.name, true, prof.active, {}});
            }
            items.push_back(std::move(sub));
        }

        items.push_back({kMenuSep2, TrayMenuKind::separator, {}, false, false, {}});
        items.push_back({kMenuProbe, TrayMenuKind::action, en ? "Test Latency" : "立即测速", true, false, {}});
        items.push_back({kMenuCopyProxy, TrayMenuKind::action,
            en ? "Copy Proxy Env" : "复制终端代理", !snap.proxy_export_cmd.empty(), false, {}});
        items.push_back({kMenuReload, TrayMenuKind::action, en ? "Reload Config" : "重载配置", true, false, {}});
        items.push_back({kMenuSep3, TrayMenuKind::separator, {}, false, false, {}});
        items.push_back({kMenuQuit, TrayMenuKind::action, en ? "Quit Nexus" : "退出 Nexus", true, false, {}});
        return items;
    }

    struct TrayController::Impl {
        TrayCallbacks callbacks;
        mutable std::mutex mutex;
        std::atomic<TrayState> state{TrayState::offline};
        std::atomic<bool> quit{false};
        std::atomic<bool> stopped{false};
        TraySnapshot snap{};
        std::string tooltip_text{"Nexus - 已停止"};
        std::unique_ptr<detail::NativeTrayBackend> backend;

        auto dispatch_id_impl(std::int32_t id) -> bool {
            using namespace detail;
            if (stopped.load(std::memory_order_acquire)) return false;

            TraySnapshot cur;
            {
                std::lock_guard lock(mutex);
                cur = snap;
            }

            switch (id) {
            case kMenuToggleWindow:
                if (callbacks.on_toggle_window) callbacks.on_toggle_window();
                else if (callbacks.on_show) callbacks.on_show();
                return true;
            case kMenuToggleCore:
                if (callbacks.on_toggle_core) callbacks.on_toggle_core();
                return true;
            case kMenuSystemProxy:
                if (callbacks.on_toggle_system_proxy) callbacks.on_toggle_system_proxy(!cur.system_proxy_enabled);
                return true;
            case kMenuTun:
                if (callbacks.on_toggle_tun) callbacks.on_toggle_tun(!cur.tun_enabled);
                return true;
            case kMenuModeRule:
                if (callbacks.on_switch_mode) callbacks.on_switch_mode("rule");
                return true;
            case kMenuModeGlobal:
                if (callbacks.on_switch_mode) callbacks.on_switch_mode("global");
                return true;
            case kMenuModeDirect:
                if (callbacks.on_switch_mode) callbacks.on_switch_mode("direct");
                return true;
            case kMenuProbe:
                if (callbacks.on_probe_active_group) callbacks.on_probe_active_group();
                return true;
            case kMenuCopyProxy:
                if (cur.proxy_export_cmd.empty()) return false;
                if (callbacks.on_copy_proxy_env) callbacks.on_copy_proxy_env();
                return true;
            case kMenuReload:
                if (callbacks.on_reload) callbacks.on_reload();
                return true;
            case kMenuQuit:
                if (!quit.exchange(true, std::memory_order_acq_rel) && callbacks.on_quit) callbacks.on_quit();
                return true;
            default:
                break;
            }

            if (id >= kMenuNodeBase && id < kMenuNodeBase + static_cast<std::int32_t>(kMaxQuickNodes)) {
                auto const idx = static_cast<std::size_t>(id - kMenuNodeBase);
                if (!cur.show_nodes || idx >= cur.quick_nodes.size()) return false;
                auto const& node = cur.quick_nodes[idx];
                std::string grp = node.group.empty() ? cur.active_group : node.group;
                if (callbacks.on_select_node) callbacks.on_select_node(std::move(grp), node.name);
                return true;
            }

            if (id >= kMenuProfileBase && id < kMenuProfileBase + static_cast<std::int32_t>(kMaxProfiles)) {
                auto const idx = static_cast<std::size_t>(id - kMenuProfileBase);
                if (cur.profiles.size() <= 1 || idx >= cur.profiles.size()) return false;
                if (callbacks.on_activate_profile) callbacks.on_activate_profile(cur.profiles[idx].id);
                return true;
            }
            return false;
        }

        auto primary_click_impl() -> void {
            if (stopped.load(std::memory_order_acquire)) return;
            std::string action;
            bool proxy_enabled = false;
            {
                std::lock_guard lock(mutex);
                action = snap.click_action;
                proxy_enabled = snap.system_proxy_enabled;
            }
            if (action == "show") {
                if (callbacks.on_show) callbacks.on_show();
                else if (callbacks.on_toggle_window) callbacks.on_toggle_window();
            } else if (action == "toggle_proxy") {
                if (callbacks.on_toggle_system_proxy) callbacks.on_toggle_system_proxy(!proxy_enabled);
            } else {
                if (callbacks.on_toggle_window) callbacks.on_toggle_window();
                else if (callbacks.on_show) callbacks.on_show();
            }
        }

        auto secondary_click_impl() -> void {
            if (stopped.load(std::memory_order_acquire)) return;
            bool proxy_enabled = false;
            {
                std::lock_guard lock(mutex);
                proxy_enabled = snap.system_proxy_enabled;
            }
            if (callbacks.on_toggle_system_proxy) callbacks.on_toggle_system_proxy(!proxy_enabled);
        }

        auto make_host() -> detail::NativeTrayHost {
            return {
                .get_snapshot = [this] { std::lock_guard lock(mutex); return snap; },
                .get_menu = [this] {
                    TraySnapshot copy;
                    { std::lock_guard lock(mutex); copy = snap; }
                    return build_tray_menu(copy);
                },
                .get_tooltip = [this] { std::lock_guard lock(mutex); return tooltip_text; },
                .dispatch_menu_id = [this](std::int32_t id) { return dispatch_id_impl(id); },
                .primary_click = [this] { primary_click_impl(); },
                .secondary_click = [this] { secondary_click_impl(); },
                .is_stopped = [this] { return stopped.load(std::memory_order_acquire); },
            };
        }

        auto start_native_backend() -> void {
            if (detail::native_tray_disabled_by_env()) return;
#ifdef _WIN32
            backend = detail::create_win32_tray(make_host());
#elif defined(__linux__)
            backend = detail::create_linux_sni_tray(make_host());
#endif
        }

        auto stop_impl() noexcept -> void {
            if (stopped.exchange(true, std::memory_order_seq_cst)) return;
            if (backend) backend->stop();
        }

        ~Impl() { stop_impl(); }
    };

    TrayController::TrayController(TrayCallbacks callbacks) : impl_(std::make_unique<Impl>()) {
        impl_->callbacks = std::move(callbacks);
        impl_->start_native_backend();
    }

    TrayController::~TrayController() = default;
    TrayController::TrayController(TrayController&&) noexcept = default;
    auto TrayController::operator=(TrayController&&) noexcept -> TrayController& = default;

    auto TrayController::set_status(this TrayController& self, TrayState state, std::string_view summary) -> void {
        if (!self.impl_ || self.impl_->stopped.load(std::memory_order_acquire)) return;
        self.impl_->state.store(state, std::memory_order_release);
        auto tip = format_legacy_tooltip(state, summary);
        {
            std::lock_guard lock(self.impl_->mutex);
            self.impl_->snap.state = state;
            self.impl_->snap.core_running = (state != TrayState::offline);
            self.impl_->snap.tun_enabled = (state == TrayState::tun_active);
            self.impl_->tooltip_text = std::move(tip);
        }
        if (self.impl_->backend) self.impl_->backend->notify_snapshot_changed();
    }

    auto TrayController::state(this TrayController const& self) noexcept -> TrayState {
        return self.impl_ ? self.impl_->state.load(std::memory_order_acquire) : TrayState::offline;
    }

    auto TrayController::tooltip(this TrayController const& self) -> std::string {
        if (!self.impl_) return {};
        std::lock_guard lock(self.impl_->mutex);
        return self.impl_->tooltip_text;
    }

    auto TrayController::quit_requested(this TrayController const& self) noexcept -> bool {
        return self.impl_ && self.impl_->quit.load(std::memory_order_acquire);
    }

    auto TrayController::update_snapshot(this TrayController& self, TraySnapshot snapshot) -> void {
        if (!self.impl_ || self.impl_->stopped.load(std::memory_order_acquire)) return;
        auto tip = format_tray_tooltip(snapshot);
        auto const st = snapshot.state;
        self.impl_->state.store(st, std::memory_order_release);
        {
            std::lock_guard lock(self.impl_->mutex);
            self.impl_->snap = std::move(snapshot);
            self.impl_->tooltip_text = std::move(tip);
        }
        if (self.impl_->backend) self.impl_->backend->notify_snapshot_changed();
    }

    auto TrayController::snapshot(this TrayController const& self) -> TraySnapshot {
        if (!self.impl_) return {};
        std::lock_guard lock(self.impl_->mutex);
        return self.impl_->snap;
    }

    auto TrayController::menu_items(this TrayController const& self) -> std::vector<TrayMenuItem> {
        if (!self.impl_) return {};
        TraySnapshot cur;
        { std::lock_guard lock(self.impl_->mutex); cur = self.impl_->snap; }
        return build_tray_menu(cur);
    }

    auto TrayController::dispatch_menu_id(this TrayController& self, std::int32_t id) -> bool {
        return self.impl_ && self.impl_->dispatch_id_impl(id);
    }

    auto TrayController::trigger_primary_click(this TrayController& self) -> void {
        if (self.impl_) self.impl_->primary_click_impl();
    }

    auto TrayController::trigger_secondary_click(this TrayController& self) -> void {
        if (self.impl_) self.impl_->secondary_click_impl();
    }

    auto TrayController::native_backend_active(this TrayController const& self) noexcept -> bool {
        return self.impl_ && self.impl_->backend && self.impl_->backend->active();
    }

    auto TrayController::trigger_show(this TrayController& self) -> void {
        if (self.impl_ && !self.impl_->stopped.load(std::memory_order_acquire) && self.impl_->callbacks.on_show)
            self.impl_->callbacks.on_show();
    }

    auto TrayController::trigger_reload(this TrayController& self) -> void {
        if (self.impl_ && !self.impl_->stopped.load(std::memory_order_acquire) && self.impl_->callbacks.on_reload)
            self.impl_->callbacks.on_reload();
    }

    auto TrayController::trigger_quit(this TrayController& self) -> void {
        if (!self.impl_ || self.impl_->stopped.load(std::memory_order_acquire)) return;
        if (!self.impl_->quit.exchange(true, std::memory_order_acq_rel) && self.impl_->callbacks.on_quit)
            self.impl_->callbacks.on_quit();
    }

    auto TrayController::stop(this TrayController& self) noexcept -> void {
        if (self.impl_) self.impl_->stop_impl();
    }
}
