export module desktop.tray_controller;

import std;

export namespace desktop {
    enum class TrayState : std::uint8_t {
        offline,
        running,
        tun_active,
        degraded,
    };

    enum class TrayMenuKind : std::uint8_t {
        action,
        checkbox,
        radio,
        submenu,
        separator,
        header,
    };

    struct TrayNodeEntry {
        std::string group;
        std::string name;
        std::string latency_label;
        bool active = false;
    };

    struct TrayProfileEntry {
        std::string id;
        std::string name;
        bool active = false;
    };

    struct TraySnapshot {
        TrayState state = TrayState::offline;
        bool core_running = false;
        bool window_visible = true;
        bool system_proxy_enabled = false;
        bool tun_enabled = false;
        bool is_en = false;
        bool show_nodes = true;
        bool show_speed = true;
        std::string click_action = "toggle"; // "toggle" | "show" | "toggle_proxy"
        std::string outbound_mode = "rule";  // "rule" | "global" | "direct"
        std::string active_group;
        std::string active_node;
        std::string active_latency;
        std::string download_rate;
        std::string upload_rate;
        std::string proxy_export_cmd;
        std::vector<TrayNodeEntry> quick_nodes;
        std::vector<TrayProfileEntry> profiles;
    };

    struct TrayMenuItem {
        std::int32_t id = 0;
        TrayMenuKind kind = TrayMenuKind::action;
        std::string label;
        bool enabled = true;
        bool checked = false;
        std::vector<TrayMenuItem> children;
    };

    enum class TrayNotificationUrgency : std::uint8_t {
        info,
        warning,
        error,
    };

    struct TrayNotification {
        std::string title;
        std::string body;
        TrayNotificationUrgency urgency = TrayNotificationUrgency::info;
    };

    struct TrayCallbacks {
        std::function<void()> on_show;
        std::function<void()> on_toggle_window;
        std::function<void()> on_toggle_core;
        std::function<void(std::string)> on_switch_mode;
        std::function<void(bool)> on_toggle_system_proxy;
        std::function<void(bool)> on_toggle_tun;
        std::function<void(std::string, std::string)> on_select_node;
        std::function<void(std::string)> on_activate_profile;
        std::function<void()> on_probe_active_group;
        std::function<void()> on_copy_proxy_env;
        std::function<void()> on_reload;
        std::function<void()> on_quit;
        std::function<void()> on_flush_fakeip;
        std::function<void()> on_clear_dns_cache;
    };

    [[nodiscard]] auto build_tray_menu(TraySnapshot const& snap) -> std::vector<TrayMenuItem>;
    [[nodiscard]] auto format_tray_tooltip(TraySnapshot const& snap) -> std::string;

    // Cross-platform system tray, dynamic menu, and shutdown coordinator for Nexus Desktop.
    class TrayController {
        struct Impl;
        std::unique_ptr<Impl> impl_;
    public:
        explicit TrayController(TrayCallbacks callbacks = {});
        ~TrayController();
        TrayController(TrayController const&) = delete;
        auto operator=(TrayController const&) -> TrayController& = delete;
        TrayController(TrayController&&) noexcept;
        auto operator=(TrayController&&) noexcept -> TrayController&;

        [[nodiscard]] auto state(this TrayController const& self) noexcept -> TrayState;
        [[nodiscard]] auto tooltip(this TrayController const& self) -> std::string;
        [[nodiscard]] auto quit_requested(this TrayController const& self) noexcept -> bool;

        auto update_snapshot(this TrayController& self, TraySnapshot snapshot) -> void;
        [[nodiscard]] auto snapshot(this TrayController const& self) -> TraySnapshot;
        [[nodiscard]] auto menu_items(this TrayController const& self) -> std::vector<TrayMenuItem>;
        auto dispatch_menu_id(this TrayController& self, std::int32_t id) -> bool;
        auto trigger_primary_click(this TrayController& self) -> void;
        auto trigger_secondary_click(this TrayController& self) -> void;
        [[nodiscard]] auto native_backend_active(this TrayController const& self) noexcept -> bool;
        auto notify(this TrayController& self, std::string title, std::string body,
            TrayNotificationUrgency urgency = TrayNotificationUrgency::info) -> bool;
        auto notify_if_hidden(this TrayController& self, std::string title, std::string body,
            TrayNotificationUrgency urgency = TrayNotificationUrgency::info) -> bool;
        [[nodiscard]] auto last_notification(this TrayController const& self) -> std::optional<TrayNotification>;

        auto trigger_show(this TrayController& self) -> void;
        auto trigger_reload(this TrayController& self) -> void;
        auto trigger_quit(this TrayController& self) -> void;
        auto stop(this TrayController& self) noexcept -> void;
    };
}

namespace desktop::detail {
    inline constexpr std::int32_t kMenuHeaderStatus = 100;
    inline constexpr std::int32_t kMenuHeaderSpeed = 101;
    inline constexpr std::int32_t kMenuToggleWindow = 1001;
    inline constexpr std::int32_t kMenuToggleCore = 1002;
    inline constexpr std::int32_t kMenuSystemProxy = 1003;
    inline constexpr std::int32_t kMenuTun = 1004;
    inline constexpr std::int32_t kMenuProbe = 1005;
    inline constexpr std::int32_t kMenuCopyProxy = 1006;
    inline constexpr std::int32_t kMenuReload = 1007;
    inline constexpr std::int32_t kMenuQuit = 1008;
    inline constexpr std::int32_t kMenuFlushFakeIp = 1009;
    inline constexpr std::int32_t kMenuClearDnsCache = 1010;
    inline constexpr std::int32_t kMenuModeSubmenu = 1100;
    inline constexpr std::int32_t kMenuModeRule = 1101;
    inline constexpr std::int32_t kMenuModeGlobal = 1102;
    inline constexpr std::int32_t kMenuModeDirect = 1103;
    inline constexpr std::int32_t kMenuNodesSubmenu = 1200;
    inline constexpr std::int32_t kMenuProfilesSubmenu = 1300;
    inline constexpr std::int32_t kMenuNodeBase = 2000;
    inline constexpr std::int32_t kMenuProfileBase = 3000;
    inline constexpr std::int32_t kMenuSep1 = 9001;
    inline constexpr std::int32_t kMenuSep2 = 9002;
    inline constexpr std::int32_t kMenuSep3 = 9003;
    inline constexpr std::size_t kMaxQuickNodes = 8;
    inline constexpr std::size_t kMaxProfiles = 32;

    class NativeTrayBackend {
    public:
        virtual ~NativeTrayBackend() = default;
        [[nodiscard]] virtual auto active() const noexcept -> bool = 0;
        virtual auto notify_snapshot_changed() -> void = 0;
        virtual auto show_notification(TrayNotification const& notif, TrayState icon_state) -> bool {
            (void)notif; (void)icon_state;
            return false;
        }
        virtual auto stop() noexcept -> void = 0;
    };

    struct NativeTrayHost {
        std::function<TraySnapshot()> get_snapshot;
        std::function<std::vector<TrayMenuItem>()> get_menu;
        std::function<std::string()> get_tooltip;
        std::function<bool(std::int32_t)> dispatch_menu_id;
        std::function<void()> primary_click;
        std::function<void()> secondary_click;
        std::function<bool()> is_stopped;
    };

    [[nodiscard]] auto native_tray_disabled_by_env() noexcept -> bool;
    [[nodiscard]] auto render_prism_icon_argb32(TrayState state) -> std::array<std::uint8_t, 32 * 32 * 4>;
    [[nodiscard]] auto build_win32_icon_dib(TrayState state) -> std::array<std::uint8_t, 40 + 32 * 32 * 4 + 32 * 4>;
    [[nodiscard]] auto escape_dbusmenu_label(std::string_view raw) -> std::string;
    [[nodiscard]] auto find_menu_item(std::vector<TrayMenuItem> const& items, std::int32_t id) -> TrayMenuItem const*;
    auto flatten_menu_items(std::vector<TrayMenuItem> const& items, std::vector<TrayMenuItem const*>& out) -> void;
    [[nodiscard]] auto create_linux_sni_tray(NativeTrayHost host) -> std::unique_ptr<NativeTrayBackend>;
    [[nodiscard]] auto create_win32_tray(NativeTrayHost host) -> std::unique_ptr<NativeTrayBackend>;
    [[nodiscard]] auto send_linux_dbus_notification_on_conn(
        void* dbus_dl_handle, void* dbus_conn,
        TrayNotification const& notif, TrayState icon_state) -> bool;
    [[nodiscard]] auto send_linux_desktop_notification(
        TrayNotification const& notif, TrayState icon_state) -> bool;

    inline constexpr char const* kSniIntrospectXml =
        "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\" \"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\"><node>"
        "<interface name=\"org.freedesktop.DBus.Introspectable\"><method name=\"Introspect\"><arg type=\"s\" direction=\"out\"/></method></interface>"
        "<interface name=\"org.freedesktop.DBus.Properties\"><method name=\"Get\"><arg type=\"s\" direction=\"in\"/><arg type=\"s\" direction=\"in\"/><arg type=\"v\" direction=\"out\"/></method><method name=\"GetAll\"><arg type=\"s\" direction=\"in\"/><arg type=\"a{sv}\" direction=\"out\"/></method></interface>"
        "<interface name=\"org.kde.StatusNotifierItem\"><method name=\"Activate\"><arg type=\"i\" direction=\"in\"/><arg type=\"i\" direction=\"in\"/></method><method name=\"SecondaryActivate\"><arg type=\"i\" direction=\"in\"/><arg type=\"i\" direction=\"in\"/></method><method name=\"ContextMenu\"><arg type=\"i\" direction=\"in\"/><arg type=\"i\" direction=\"in\"/></method><method name=\"Scroll\"><arg type=\"i\" direction=\"in\"/><arg type=\"s\" direction=\"in\"/></method>"
        "<signal name=\"NewTitle\"/><signal name=\"NewIcon\"/><signal name=\"NewToolTip\"/><signal name=\"NewStatus\"><arg type=\"s\"/></signal>"
        "<property name=\"Category\" type=\"s\" access=\"read\"/><property name=\"Id\" type=\"s\" access=\"read\"/><property name=\"Title\" type=\"s\" access=\"read\"/><property name=\"Status\" type=\"s\" access=\"read\"/><property name=\"WindowId\" type=\"u\" access=\"read\"/><property name=\"IconName\" type=\"s\" access=\"read\"/><property name=\"IconPixmap\" type=\"a(iiay)\" access=\"read\"/><property name=\"ItemIsMenu\" type=\"b\" access=\"read\"/><property name=\"Menu\" type=\"o\" access=\"read\"/><property name=\"ToolTip\" type=\"(sa(iiay)ss)\" access=\"read\"/></interface></node>";

    inline constexpr char const* kMenuIntrospectXml =
        "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\" \"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\"><node>"
        "<interface name=\"org.freedesktop.DBus.Introspectable\"><method name=\"Introspect\"><arg type=\"s\" direction=\"out\"/></method></interface>"
        "<interface name=\"org.freedesktop.DBus.Properties\"><method name=\"Get\"><arg type=\"s\" direction=\"in\"/><arg type=\"s\" direction=\"in\"/><arg type=\"v\" direction=\"out\"/></method><method name=\"GetAll\"><arg type=\"s\" direction=\"in\"/><arg type=\"a{sv}\" direction=\"out\"/></method></interface>"
        "<interface name=\"com.canonical.dbusmenu\"><method name=\"GetLayout\"><arg type=\"i\" direction=\"in\"/><arg type=\"i\" direction=\"in\"/><arg type=\"as\" direction=\"in\"/><arg type=\"u\" direction=\"out\"/><arg type=\"(ia{sv}av)\" direction=\"out\"/></method><method name=\"GetGroupProperties\"><arg type=\"ai\" direction=\"in\"/><arg type=\"as\" direction=\"in\"/><arg type=\"a(ia{sv})\" direction=\"out\"/></method><method name=\"GetProperty\"><arg type=\"i\" direction=\"in\"/><arg type=\"s\" direction=\"in\"/><arg type=\"v\" direction=\"out\"/></method>"
        "<method name=\"Event\"><arg type=\"i\" direction=\"in\"/><arg type=\"s\" direction=\"in\"/><arg type=\"v\" direction=\"in\"/><arg type=\"u\" direction=\"in\"/></method><method name=\"EventGroup\"><arg type=\"a(isvu)\" direction=\"in\"/><arg type=\"ai\" direction=\"out\"/></method><method name=\"AboutToShow\"><arg type=\"i\" direction=\"in\"/><arg type=\"b\" direction=\"out\"/></method><method name=\"AboutToShowGroup\"><arg type=\"ai\" direction=\"in\"/><arg type=\"ai\" direction=\"out\"/><arg type=\"ai\" direction=\"out\"/></method>"
        "<signal name=\"LayoutUpdated\"><arg type=\"u\"/><arg type=\"i\"/></signal><property name=\"Version\" type=\"u\" access=\"read\"/><property name=\"TextDirection\" type=\"s\" access=\"read\"/><property name=\"Status\" type=\"s\" access=\"read\"/><property name=\"IconThemePath\" type=\"as\" access=\"read\"/></interface></node>";
}
