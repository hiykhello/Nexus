module;
#if defined(__linux__)
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <dlfcn.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>
#endif
module desktop.tray_controller;

import std;

namespace desktop::detail {
#if defined(__linux__)
    namespace sni_abi {
        using Bool = std::uint32_t;
        struct Conn;
        struct Msg;
        struct Err { char const *name, *message; unsigned int d1:1, d2:1, d3:1, d4:1, d5:1; void* pad1; };
        struct Iter { void *d1, *d2; std::uint32_t d3; int d4, d5, d6, d7, d8, d9, d10, d11, pad1; void *pad2, *pad3; };
        using MsgFn = int (*)(Conn*, Msg*, void*);
        struct VTable { void (*unreg)(Conn*, void*); MsgFn on_msg; void (*p1)(void*), (*p2)(void*), (*p3)(void*), (*p4)(void*); };

        inline constexpr int kBusSession = 0, kHandled = 0, kNotHandled = 1, kDataRemains = 0, kProbeTimeoutMs = 500;
        inline constexpr unsigned int kNameDoNotQueue = 0x4u;
        inline constexpr int kByte = 'y', kBool = 'b', kI32 = 'i', kU32 = 'u', kStr = 's';
        inline constexpr int kPath = 'o', kArr = 'a', kVar = 'v', kStruct = 'r', kDict = 'e';

        struct DbusLib {
            void* handle = nullptr;
            Bool (*threads_init)() = nullptr;
            void (*err_init)(Err*) = nullptr, (*err_free)(Err*) = nullptr;
            Bool (*err_is_set)(Err const*) = nullptr;
            Conn* (*bus_get_priv)(int, Err*) = nullptr;
            int (*bus_req_name)(Conn*, char const*, unsigned int, Err*) = nullptr;
            void (*bus_add_match)(Conn*, char const*, Err*) = nullptr;
            void (*exit_on_disc)(Conn*, Bool) = nullptr;
            Bool (*get_unix_fd)(Conn*, int*) = nullptr;
            Bool (*is_connected)(Conn*) = nullptr, (*has_outgoing)(Conn*) = nullptr;
            Bool (*read_write)(Conn*, int) = nullptr;
            int (*dispatch)(Conn*) = nullptr;
            Bool (*send)(Conn*, Msg*, std::uint32_t*) = nullptr;
            Msg* (*send_block)(Conn*, Msg*, int, Err*) = nullptr;
            void (*flush)(Conn*) = nullptr, (*close_conn)(Conn*) = nullptr, (*unref_conn)(Conn*) = nullptr;
            Bool (*reg_obj)(Conn*, char const*, VTable const*, void*) = nullptr, (*unreg_obj)(Conn*, char const*) = nullptr;
            Bool (*add_filter)(Conn*, MsgFn, void*, void (*)(void*)) = nullptr;
            void (*rem_filter)(Conn*, MsgFn, void*) = nullptr;
            Msg* (*new_call)(char const*, char const*, char const*, char const*) = nullptr;
            Msg* (*new_ret)(Msg*) = nullptr;
            Msg* (*new_sig)(char const*, char const*, char const*) = nullptr;
            Msg* (*new_err)(Msg*, char const*, char const*) = nullptr;
            void (*set_no_reply)(Msg*, Bool) = nullptr, (*unref_msg)(Msg*) = nullptr;
            Bool (*is_call)(Msg*, char const*, char const*) = nullptr, (*is_sig)(Msg*, char const*, char const*) = nullptr;
            Bool (*iter_init)(Msg*, Iter*) = nullptr, (*next)(Iter*) = nullptr;
            int (*arg_type)(Iter*) = nullptr;
            void (*recurse)(Iter*, Iter*) = nullptr, (*get_basic)(Iter*, void*) = nullptr, (*init_append)(Msg*, Iter*) = nullptr;
            Bool (*basic)(Iter*, int, void const*) = nullptr, (*fixed_arr)(Iter*, int, void const*, int) = nullptr;
            Bool (*open)(Iter*, int, char const*, Iter*) = nullptr, (*close)(Iter*, Iter*) = nullptr;

            auto load() -> bool {
                handle = ::dlopen("libdbus-1.so.3", RTLD_LAZY | RTLD_LOCAL);
                if (!handle) handle = ::dlopen("libdbus-1.so", RTLD_LAZY | RTLD_LOCAL);
                if (!handle) return false;
                auto s = [this](auto& fn, char const* n) { fn = reinterpret_cast<std::decay_t<decltype(fn)>>(::dlsym(handle, n)); return fn != nullptr; };
                threads_init = reinterpret_cast<Bool (*)()>(::dlsym(handle, "dbus_threads_init_default"));
                bool ok = s(err_init, "dbus_error_init") && s(err_free, "dbus_error_free") && s(err_is_set, "dbus_error_is_set")
                    && s(bus_get_priv, "dbus_bus_get_private") && s(bus_req_name, "dbus_bus_request_name") && s(bus_add_match, "dbus_bus_add_match")
                    && s(exit_on_disc, "dbus_connection_set_exit_on_disconnect") && s(get_unix_fd, "dbus_connection_get_unix_fd") && s(is_connected, "dbus_connection_get_is_connected")
                    && s(has_outgoing, "dbus_connection_has_messages_to_send") && s(read_write, "dbus_connection_read_write") && s(dispatch, "dbus_connection_dispatch")
                    && s(send, "dbus_connection_send") && s(send_block, "dbus_connection_send_with_reply_and_block") && s(flush, "dbus_connection_flush")
                    && s(close_conn, "dbus_connection_close") && s(unref_conn, "dbus_connection_unref") && s(reg_obj, "dbus_connection_register_object_path")
                    && s(unreg_obj, "dbus_connection_unregister_object_path") && s(add_filter, "dbus_connection_add_filter") && s(rem_filter, "dbus_connection_remove_filter")
                    && s(new_call, "dbus_message_new_method_call") && s(new_ret, "dbus_message_new_method_return") && s(new_sig, "dbus_message_new_signal")
                    && s(new_err, "dbus_message_new_error") && s(set_no_reply, "dbus_message_set_no_reply") && s(unref_msg, "dbus_message_unref")
                    && s(is_call, "dbus_message_is_method_call") && s(is_sig, "dbus_message_is_signal") && s(iter_init, "dbus_message_iter_init")
                    && s(arg_type, "dbus_message_iter_get_arg_type") && s(next, "dbus_message_iter_next") && s(recurse, "dbus_message_iter_recurse")
                    && s(get_basic, "dbus_message_iter_get_basic") && s(init_append, "dbus_message_iter_init_append") && s(basic, "dbus_message_iter_append_basic")
                    && s(fixed_arr, "dbus_message_iter_append_fixed_array") && s(open, "dbus_message_iter_open_container") && s(close, "dbus_message_iter_close_container");
                if (!ok) { ::dlclose(handle); handle = nullptr; }
                return ok;
            }
            ~DbusLib() { if (handle) ::dlclose(handle); }
        };

        struct Marshal {
            DbusLib const& lib;
            auto var(Iter* it, char const* sig, int ty, void const* p) const -> void { Iter v{}; lib.open(it, kVar, sig, &v); lib.basic(&v, ty, p); lib.close(it, &v); }
            auto read_i32_str(Iter* it, std::int32_t& id, char const*& s) const -> bool {
                if (lib.arg_type(it) != kI32) return false;
                lib.get_basic(it, &id);
                if (!lib.next(it) || lib.arg_type(it) != kStr) return false;
                lib.get_basic(it, &s); return true;
            }
            auto pixmap_arr(Iter* it, TrayState st, bool with_icon) const -> void {
                Iter arr{}; lib.open(it, kArr, "(iiay)", &arr);
                if (with_icon) {
                    auto px = render_prism_icon_argb32(st);
                    std::int32_t dim = 32; std::uint8_t const* ptr = px.data(); Iter s{}, b{};
                    lib.open(&arr, kStruct, nullptr, &s); lib.basic(&s, kI32, &dim); lib.basic(&s, kI32, &dim);
                    lib.open(&s, kArr, "y", &b); lib.fixed_arr(&b, kByte, &ptr, static_cast<int>(px.size()));
                    lib.close(&s, &b); lib.close(&arr, &s);
                }
                lib.close(it, &arr);
            }
            auto sni_prop(Iter* it, std::string_view p, TrayState st, std::string const& tip) const -> bool {
                auto sv = [&](char const* s) { var(it, "s", kStr, &s); return true; };
                if (p == "Category") return sv("ApplicationStatus");
                if (p == "Id") return sv("nexus-desktop");
                if (p == "Title") return sv("Nexus");
                if (p == "Status") return sv("Active");
                if (p == "IconName" || p == "OverlayIconName" || p == "AttentionIconName" || p == "AttentionMovieName") return sv("");
                if (p == "WindowId") { std::uint32_t z = 0; var(it, "u", kU32, &z); return true; }
                if (p == "ItemIsMenu") { Bool f = 0; var(it, "b", kBool, &f); return true; }
                if (p == "Menu") { char const* o = "/MenuBar"; var(it, "o", kPath, &o); return true; }
                if (p == "IconPixmap" || p == "OverlayIconPixmap" || p == "AttentionIconPixmap") {
                    Iter v{}; lib.open(it, kVar, "a(iiay)", &v); pixmap_arr(&v, st, p == "IconPixmap"); lib.close(it, &v); return true;
                }
                if (p == "ToolTip") {
                    auto nl = tip.find('\n');
                    std::string t = nl == std::string::npos ? tip : tip.substr(0, nl);
                    std::string d = nl == std::string::npos ? std::string{} : tip.substr(nl + 1);
                    char const *e = "", *tp = t.c_str(), *dp = d.c_str();
                    Iter v{}, s{}; lib.open(it, kVar, "(sa(iiay)ss)", &v); lib.open(&v, kStruct, nullptr, &s);
                    lib.basic(&s, kStr, &e); pixmap_arr(&s, TrayState::offline, false);
                    lib.basic(&s, kStr, &tp); lib.basic(&s, kStr, &dp);
                    lib.close(&v, &s); lib.close(it, &v); return true;
                }
                return false;
            }
            auto menu_prop(Iter* it, std::string_view p) const -> bool {
                if (p == "Version") { std::uint32_t ver = 3u; var(it, "u", kU32, &ver); return true; }
                if (p == "TextDirection") { char const* s = "ltr"; var(it, "s", kStr, &s); return true; }
                if (p == "Status") { char const* s = "normal"; var(it, "s", kStr, &s); return true; }
                if (p == "IconThemePath") {
                    Iter v{}, a{}; lib.open(it, kVar, "as", &v); lib.open(&v, kArr, "s", &a); lib.close(&v, &a); lib.close(it, &v); return true;
                }
                return false;
            }
            auto item_prop(Iter* it, TrayMenuItem const& item, std::string_view k) const -> bool {
                Bool b = 1u; std::int32_t ts = item.checked ? 1 : 0;
                if (k == "visible") { var(it, "b", kBool, &b); return true; }
                if (k == "type" && item.kind == TrayMenuKind::separator) { char const* s = "separator"; var(it, "s", kStr, &s); return true; }
                if (item.kind == TrayMenuKind::separator) return false;
                if (k == "label") { auto esc = escape_dbusmenu_label(item.label); char const* p = esc.c_str(); var(it, "s", kStr, &p); return true; }
                if (k == "enabled") { b = (item.enabled && item.kind != TrayMenuKind::header) ? 1u : 0u; var(it, "b", kBool, &b); return true; }
                if (k == "toggle-type" && (item.kind == TrayMenuKind::checkbox || item.kind == TrayMenuKind::radio)) {
                    char const* s = item.kind == TrayMenuKind::checkbox ? "checkmark" : "radio"; var(it, "s", kStr, &s); return true;
                }
                if (k == "toggle-state" && (item.kind == TrayMenuKind::checkbox || item.kind == TrayMenuKind::radio)) { var(it, "i", kI32, &ts); return true; }
                if (k == "children-display" && item.kind == TrayMenuKind::submenu) { char const* s = "submenu"; var(it, "s", kStr, &s); return true; }
                return false;
            }
            auto item_props(Iter* it, TrayMenuItem const& item) const -> void {
                Iter d{}; lib.open(it, kArr, "{sv}", &d);
                auto add = [&](char const* k) {
                    Iter e{}; lib.open(&d, kDict, nullptr, &e); lib.basic(&e, kStr, &k); (void)item_prop(&e, item, k); lib.close(&d, &e);
                };
                add("visible");
                if (item.kind == TrayMenuKind::separator) { add("type"); }
                else {
                    add("label"); add("enabled");
                    if (item.kind == TrayMenuKind::checkbox || item.kind == TrayMenuKind::radio) { add("toggle-type"); add("toggle-state"); }
                    else if (item.kind == TrayMenuKind::submenu) add("children-display");
                }
                lib.close(it, &d);
            }
            auto layout_children(Iter* st, std::vector<TrayMenuItem> const& children, std::int32_t depth) const -> void {
                Iter ch{}; lib.open(st, kArr, "v", &ch);
                if (depth != 0) {
                    std::int32_t const nd = depth < 0 ? -1 : depth - 1;
                    for (auto const& c : children) { Iter cv{}; lib.open(&ch, kVar, "(ia{sv}av)", &cv); layout_node(&cv, c, nd); lib.close(&ch, &cv); }
                }
                lib.close(st, &ch);
            }
            auto layout_node(Iter* it, TrayMenuItem const& item, std::int32_t depth) const -> void {
                Iter s{}; lib.open(it, kStruct, nullptr, &s); lib.basic(&s, kI32, &item.id); item_props(&s, item); layout_children(&s, item.children, depth); lib.close(it, &s);
            }
            auto layout_root(Iter* it, std::vector<TrayMenuItem> const& items, std::int32_t depth) const -> void {
                Iter s{}, d{}, e{}; std::int32_t zero = 0; char const *k = "children-display", *v = "submenu";
                lib.open(it, kStruct, nullptr, &s); lib.basic(&s, kI32, &zero);
                lib.open(&s, kArr, "{sv}", &d); lib.open(&d, kDict, nullptr, &e); lib.basic(&e, kStr, &k);
                var(&e, "s", kStr, &v); lib.close(&d, &e); lib.close(&s, &d); layout_children(&s, items, depth); lib.close(it, &s);
            }
        };

        class LinuxSniBackend final : public NativeTrayBackend {
            NativeTrayHost host_;
            DbusLib lib_;
            std::thread worker_;
            std::mutex wake_mu_, notif_mu_;
            std::deque<std::pair<TrayNotification, TrayState>> pending_notifs_;
            int wake_fd_ = -1;
            std::atomic<bool> active_{false}, stopping_{false}, dirty_{false}, reprobe_{false};
            std::uint32_t menu_rev_{1};
            TrayState last_state_{TrayState::offline};
            std::string reg_arg_;

            auto drain_notifications(Conn* c) -> void {
                std::deque<std::pair<TrayNotification, TrayState>> batch;
                { std::lock_guard lk(notif_mu_); batch.swap(pending_notifs_); }
                for (auto const& [notif, st] : batch) (void)send_linux_dbus_notification_on_conn(lib_.handle, c, notif, st);
            }
            auto send_unref(Conn* c, Msg* m) -> void { if (m) { lib_.send(c, m, nullptr); lib_.flush(c); lib_.unref_msg(m); } }
            auto reply_empty_i32_arrs(Conn* c, Msg* req, int count) -> int {
                if (auto* r = lib_.new_ret(req)) {
                    Iter o{}; lib_.init_append(r, &o);
                    for (int i = 0; i < count; ++i) { Iter a{}; lib_.open(&o, kArr, "i", &a); lib_.close(&o, &a); }
                    send_unref(c, r);
                }
                return kHandled;
            }
            template <class AppendProp>
            auto handle_std(Conn* c, Msg* msg, char const* xml, std::initializer_list<char const*> keys, AppendProp&& app) -> int {
                auto& l = lib_;
                if (l.is_call(msg, "org.freedesktop.DBus.Introspectable", "Introspect")) {
                    if (auto* r = l.new_ret(msg)) { Iter o{}; l.init_append(r, &o); l.basic(&o, kStr, &xml); send_unref(c, r); }
                    return kHandled;
                }
                if (l.is_call(msg, "org.freedesktop.DBus.Properties", "Get")) {
                    Iter in{}; char const* prop = nullptr;
                    if (l.iter_init(msg, &in) && l.next(&in) && l.arg_type(&in) == kStr) l.get_basic(&in, &prop);
                    if (auto* r = l.new_ret(msg)) {
                        Iter o{}; l.init_append(r, &o);
                        if (prop && app(&o, std::string_view(prop))) { send_unref(c, r); return kHandled; }
                        l.unref_msg(r);
                    }
                    send_unref(c, l.new_err(msg, "org.freedesktop.DBus.Error.UnknownProperty", "unknown"));
                    return kHandled;
                }
                if (l.is_call(msg, "org.freedesktop.DBus.Properties", "GetAll")) {
                    if (auto* r = l.new_ret(msg)) {
                        Iter o{}, d{}; l.init_append(r, &o); l.open(&o, kArr, "{sv}", &d);
                        for (char const* p : keys) {
                            Iter e{}; l.open(&d, kDict, nullptr, &e); l.basic(&e, kStr, &p); (void)app(&e, std::string_view(p)); l.close(&d, &e);
                        }
                        l.close(&o, &d); send_unref(c, r);
                    }
                    return kHandled;
                }
                return kNotHandled;
            }
            auto register_watcher(Conn* c) -> void {
                auto* m = lib_.new_call("org.kde.StatusNotifierWatcher", "/StatusNotifierWatcher",
                    "org.kde.StatusNotifierWatcher", "RegisterStatusNotifierItem");
                if (!m) return;
                lib_.set_no_reply(m, 1u);
                Iter it{}; char const* arg = reg_arg_.c_str();
                lib_.init_append(m, &it); lib_.basic(&it, kStr, &arg);
                send_unref(c, m);
            }
            auto probe_watcher_and_host(Conn* c) -> std::pair<bool, bool> {
                auto& l = lib_; Err err{}; l.err_init(&err);
                bool has_watcher = false, has_host = false;
                if (auto* m = l.new_call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "NameHasOwner")) {
                    char const* w = "org.kde.StatusNotifierWatcher"; Iter it{}; l.init_append(m, &it); l.basic(&it, kStr, &w);
                    auto* rep = l.send_block(c, m, kProbeTimeoutMs, &err); l.unref_msg(m);
                    if (rep && !l.err_is_set(&err)) {
                        Iter ri{}; Bool owned = 0u;
                        if (l.iter_init(rep, &ri) && l.arg_type(&ri) == kBool) { l.get_basic(&ri, &owned); has_watcher = (owned != 0u); }
                    }
                    if (rep) l.unref_msg(rep);
                    l.err_free(&err);
                }
                if (!has_watcher) return {false, false};
                if (auto* m = l.new_call("org.kde.StatusNotifierWatcher", "/StatusNotifierWatcher", "org.freedesktop.DBus.Properties", "Get")) {
                    char const *iface = "org.kde.StatusNotifierWatcher", *prop = "IsStatusNotifierHostRegistered";
                    Iter it{}; l.init_append(m, &it); l.basic(&it, kStr, &iface); l.basic(&it, kStr, &prop);
                    auto* rep = l.send_block(c, m, kProbeTimeoutMs, &err); l.unref_msg(m);
                    if (rep && !l.err_is_set(&err)) {
                        Iter ri{}, sub{}; Bool reg = 0u;
                        if (l.iter_init(rep, &ri) && l.arg_type(&ri) == kVar) {
                            l.recurse(&ri, &sub);
                            if (l.arg_type(&sub) == kBool) { l.get_basic(&sub, &reg); has_host = (reg != 0u); }
                        }
                    }
                    if (rep) l.unref_msg(rep);
                    l.err_free(&err);
                }
                return {has_watcher, has_host};
            }
            auto sync_watcher_state(Conn* c) -> void {
                auto [has_watcher, has_host] = probe_watcher_and_host(c);
                if (has_watcher) register_watcher(c);
                active_.store(has_watcher && has_host, std::memory_order_release);
            }
            auto emit_updates(Conn* c) -> void {
                auto snap = host_.get_snapshot();
                bool const icon_dirty = (snap.state != last_state_);
                last_state_ = snap.state;
                auto sig0 = [&](char const* name) {
                    if (auto* m = lib_.new_sig("/StatusNotifierItem", "org.kde.StatusNotifierItem", name)) {
                        lib_.send(c, m, nullptr); lib_.unref_msg(m);
                    }
                };
                if (icon_dirty) sig0("NewIcon");
                sig0("NewToolTip");
                if (auto* m = lib_.new_sig("/MenuBar", "com.canonical.dbusmenu", "LayoutUpdated")) {
                    Iter it{}; std::uint32_t rev = ++menu_rev_; std::int32_t root = 0;
                    lib_.init_append(m, &it); lib_.basic(&it, kU32, &rev); lib_.basic(&it, kI32, &root);
                    lib_.send(c, m, nullptr); lib_.unref_msg(m);
                }
                lib_.flush(c);
            }
            static auto on_sni(Conn* c, Msg* msg, void* ud) -> int {
                auto* s = static_cast<LinuxSniBackend*>(ud); auto& l = s->lib_; Marshal m{l};
                static constexpr std::initializer_list<char const*> kProps = {
                    "Category", "Id", "Title", "Status", "WindowId", "IconName", "IconPixmap", "OverlayIconName",
                    "OverlayIconPixmap", "AttentionIconName", "AttentionIconPixmap", "AttentionMovieName", "ItemIsMenu", "Menu", "ToolTip",
                };
                std::optional<TraySnapshot> snap; std::optional<std::string> tip;
                if (s->handle_std(c, msg, kSniIntrospectXml, kProps, [&](Iter* o, std::string_view p) {
                    if (!snap) { snap = s->host_.get_snapshot(); tip = s->host_.get_tooltip(); }
                    return m.sni_prop(o, p, snap->state, *tip);
                }) == kHandled) return kHandled;
                if (l.is_call(msg, "org.kde.StatusNotifierItem", "Activate")) {
                    if (!s->host_.is_stopped()) s->host_.primary_click();
                } else if (l.is_call(msg, "org.kde.StatusNotifierItem", "SecondaryActivate")) {
                    if (!s->host_.is_stopped()) s->host_.secondary_click();
                } else if (!l.is_call(msg, "org.kde.StatusNotifierItem", "ContextMenu") && !l.is_call(msg, "org.kde.StatusNotifierItem", "Scroll")) {
                    return kNotHandled;
                }
                s->send_unref(c, l.new_ret(msg));
                return kHandled;
            }
            static auto on_menu(Conn* c, Msg* msg, void* ud) -> int {
                auto* s = static_cast<LinuxSniBackend*>(ud); auto& l = s->lib_; Marshal m{l};
                static constexpr std::initializer_list<char const*> kProps = {"Version", "TextDirection", "Status", "IconThemePath"};
                if (s->handle_std(c, msg, kMenuIntrospectXml, kProps, [&](Iter* o, std::string_view p) { return m.menu_prop(o, p); }) == kHandled) return kHandled;
                if (l.is_call(msg, "com.canonical.dbusmenu", "GetLayout")) {
                    std::int32_t pid = 0, depth = -1; Iter in{};
                    if (l.iter_init(msg, &in) && l.arg_type(&in) == kI32) {
                        l.get_basic(&in, &pid); if (l.next(&in) && l.arg_type(&in) == kI32) l.get_basic(&in, &depth);
                    }
                    if (auto* r = l.new_ret(msg)) {
                        auto items = s->host_.get_menu(); Iter o{}; std::uint32_t rev = s->menu_rev_;
                        l.init_append(r, &o); l.basic(&o, kU32, &rev);
                        if (pid == 0) m.layout_root(&o, items, depth);
                        else if (auto const* sub = find_menu_item(items, pid)) m.layout_node(&o, *sub, depth);
                        else m.layout_node(&o, TrayMenuItem{pid, TrayMenuKind::header, {}, false, false, {}}, 0);
                        s->send_unref(c, r);
                    }
                    return kHandled;
                }
                if (l.is_call(msg, "com.canonical.dbusmenu", "GetGroupProperties")) {
                    std::vector<std::int32_t> ids; Iter in{};
                    if (l.iter_init(msg, &in) && l.arg_type(&in) == kArr) {
                        Iter a{}; l.recurse(&in, &a);
                        while (l.arg_type(&a) == kI32) { std::int32_t id = 0; l.get_basic(&a, &id); ids.push_back(id); l.next(&a); }
                    }
                    if (auto* r = l.new_ret(msg)) {
                        auto items = s->host_.get_menu(); Iter o{}, arr{}; l.init_append(r, &o); l.open(&o, kArr, "(ia{sv})", &arr);
                        auto emit = [&](TrayMenuItem const& it) {
                            Iter st{}; l.open(&arr, kStruct, nullptr, &st); l.basic(&st, kI32, &it.id); m.item_props(&st, it); l.close(&arr, &st);
                        };
                        if (ids.empty()) { std::vector<TrayMenuItem const*> all; flatten_menu_items(items, all); for (auto* p : all) emit(*p); }
                        else for (auto id : ids) if (auto* p = find_menu_item(items, id)) emit(*p);
                        l.close(&o, &arr); s->send_unref(c, r);
                    }
                    return kHandled;
                }
                if (l.is_call(msg, "com.canonical.dbusmenu", "GetProperty")) {
                    std::int32_t id = 0; char const* name = nullptr; Iter in{};
                    if (l.iter_init(msg, &in) && m.read_i32_str(&in, id, name) && name) {
                        if (auto* r = l.new_ret(msg)) {
                            auto items = s->host_.get_menu(); Iter o{}; l.init_append(r, &o); bool ok = false;
                            if (id == 0 && std::string_view(name) == "children-display") { char const* v = "submenu"; m.var(&o, "s", kStr, &v); ok = true; }
                            else if (auto const* it = find_menu_item(items, id)) ok = m.item_prop(&o, *it, name);
                            if (ok) { s->send_unref(c, r); return kHandled; }
                            l.unref_msg(r);
                        }
                    }
                    s->send_unref(c, l.new_err(msg, "org.freedesktop.DBus.Error.UnknownProperty", "unknown"));
                    return kHandled;
                }
                if (l.is_call(msg, "com.canonical.dbusmenu", "AboutToShow")) {
                    if (auto* r = l.new_ret(msg)) { Iter o{}; Bool need = 0u; l.init_append(r, &o); l.basic(&o, kBool, &need); s->send_unref(c, r); }
                    return kHandled;
                }
                if (l.is_call(msg, "com.canonical.dbusmenu", "AboutToShowGroup")) return s->reply_empty_i32_arrs(c, msg, 2);
                auto maybe_click = [&](Iter* it) {
                    std::int32_t id = 0; char const* ev = nullptr;
                    if (m.read_i32_str(it, id, ev) && ev && std::strcmp(ev, "clicked") == 0 && !s->host_.is_stopped()) (void)s->host_.dispatch_menu_id(id);
                };
                if (l.is_call(msg, "com.canonical.dbusmenu", "Event")) {
                    Iter in{}; if (l.iter_init(msg, &in)) maybe_click(&in); s->send_unref(c, l.new_ret(msg)); return kHandled;
                }
                if (l.is_call(msg, "com.canonical.dbusmenu", "EventGroup")) {
                    Iter in{};
                    if (l.iter_init(msg, &in) && l.arg_type(&in) == kArr) {
                        Iter arr{}; l.recurse(&in, &arr);
                        while (l.arg_type(&arr) == kStruct) { Iter st{}; l.recurse(&arr, &st); maybe_click(&st); l.next(&arr); }
                    }
                    return s->reply_empty_i32_arrs(c, msg, 1);
                }
                return kNotHandled;
            }
            static auto on_filter(Conn*, Msg* msg, void* ud) -> int {
                auto* s = static_cast<LinuxSniBackend*>(ud); auto& l = s->lib_;
                if (l.is_sig(msg, "org.freedesktop.DBus", "NameOwnerChanged")) {
                    Iter in{}; char const *name = nullptr, *old_o = nullptr, *new_o = nullptr;
                    if (l.iter_init(msg, &in) && l.arg_type(&in) == kStr) {
                        l.get_basic(&in, &name);
                        if (l.next(&in) && l.arg_type(&in) == kStr && (l.get_basic(&in, &old_o), l.next(&in)) && l.arg_type(&in) == kStr) l.get_basic(&in, &new_o);
                    }
                    if (name && std::strcmp(name, "org.kde.StatusNotifierWatcher") == 0) {
                        if (new_o && *new_o) s->reprobe_.store(true, std::memory_order_release);
                        else s->active_.store(false, std::memory_order_release);
                    }
                } else if (l.is_sig(msg, "org.kde.StatusNotifierWatcher", "StatusNotifierHostRegistered") ||
                           l.is_sig(msg, "org.kde.StatusNotifierWatcher", "StatusNotifierHostUnregistered")) {
                    s->reprobe_.store(true, std::memory_order_release);
                }
                return kNotHandled;
            }
            auto wake() noexcept -> void { std::lock_guard lk(wake_mu_); if (wake_fd_ >= 0) { std::uint64_t one = 1; (void)::write(wake_fd_, &one, sizeof(one)); } }
            auto close_wake_fd() noexcept -> void { std::lock_guard lk(wake_mu_); if (wake_fd_ >= 0) { ::close(wake_fd_); wake_fd_ = -1; } }
            auto run_loop(int wake_fd, std::promise<bool> ready) -> void {
                if (lib_.threads_init) (void)lib_.threads_init();
                Err err{}; lib_.err_init(&err); auto* conn = lib_.bus_get_priv(kBusSession, &err); int dbus_fd = -1;
                if (!conn || lib_.err_is_set(&err) || !lib_.get_unix_fd(conn, &dbus_fd) || dbus_fd < 0) {
                    lib_.err_free(&err); if (conn) { lib_.close_conn(conn); lib_.unref_conn(conn); }
                    ready.set_value(false); return;
                }
                lib_.exit_on_disc(conn, 0u);
                static std::atomic<std::uint64_t> seq{1};
                reg_arg_ = std::format("org.kde.StatusNotifierItem-{}-{}", static_cast<long>(::getpid()), seq.fetch_add(1, std::memory_order_relaxed));
                (void)lib_.bus_req_name(conn, reg_arg_.c_str(), kNameDoNotQueue, &err);
                if (lib_.err_is_set(&err)) reg_arg_ = "/StatusNotifierItem";
                lib_.err_free(&err);

                static VTable const kSniVt{nullptr, &LinuxSniBackend::on_sni, nullptr, nullptr, nullptr, nullptr};
                static VTable const kMenuVt{nullptr, &LinuxSniBackend::on_menu, nullptr, nullptr, nullptr, nullptr};
                lib_.reg_obj(conn, "/StatusNotifierItem", &kSniVt, this); lib_.reg_obj(conn, "/MenuBar", &kMenuVt, this);
                lib_.add_filter(conn, &LinuxSniBackend::on_filter, this, nullptr);
                for (char const* rule : {
                    "type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',member='NameOwnerChanged',arg0='org.kde.StatusNotifierWatcher'",
                    "type='signal',interface='org.kde.StatusNotifierWatcher',member='StatusNotifierHostRegistered'",
                    "type='signal',interface='org.kde.StatusNotifierWatcher',member='StatusNotifierHostUnregistered'",
                }) { lib_.bus_add_match(conn, rule, &err); lib_.err_free(&err); }

                last_state_ = host_.get_snapshot().state; sync_watcher_state(conn); ready.set_value(true);
                while (!stopping_.load(std::memory_order_acquire) && lib_.is_connected(conn)) {
                    while (lib_.dispatch(conn) == kDataRemains && !stopping_.load(std::memory_order_acquire)) {}
                    if (reprobe_.exchange(false, std::memory_order_acq_rel) && !stopping_.load(std::memory_order_acquire)) { sync_watcher_state(conn); continue; }
                    if (dirty_.exchange(false, std::memory_order_acq_rel) && !stopping_.load(std::memory_order_acquire)) emit_updates(conn);
                    if (!stopping_.load(std::memory_order_acquire)) drain_notifications(conn);
                    pollfd fds[2]{{dbus_fd, static_cast<short>(POLLIN | (lib_.has_outgoing(conn) ? POLLOUT : 0)), 0}, {wake_fd, POLLIN, 0}};
                    if (::poll(fds, 2, -1) < 0) { if (errno == EINTR) continue; break; }
                    if (fds[1].revents & POLLIN) { std::uint64_t d = 0; while (::read(wake_fd, &d, sizeof(d)) > 0) {} }
                    if (stopping_.load(std::memory_order_acquire) || (fds[0].revents & (POLLHUP | POLLERR | POLLNVAL))) break;
                    if (fds[0].revents & (POLLIN | POLLOUT)) (void)lib_.read_write(conn, 0);
                }
                active_.store(false, std::memory_order_release);
                lib_.rem_filter(conn, &LinuxSniBackend::on_filter, this);
                lib_.unreg_obj(conn, "/MenuBar"); lib_.unreg_obj(conn, "/StatusNotifierItem");
                lib_.close_conn(conn); lib_.unref_conn(conn);
            }
        public:
            explicit LinuxSniBackend(NativeTrayHost host) : host_(std::move(host)) {}
            ~LinuxSniBackend() override { stop(); if (worker_.joinable()) worker_.detach(); }
            auto start() -> bool {
                char const* bus_addr = std::getenv("DBUS_SESSION_BUS_ADDRESS");
                if (!bus_addr || !*bus_addr || !lib_.load()) return false;
                int fd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
                if (fd < 0) return false;
                wake_fd_ = fd; std::promise<bool> ready; auto fut = ready.get_future();
                worker_ = std::thread([this, fd, p = std::move(ready)]() mutable { run_loop(fd, std::move(p)); });
                if (!fut.get()) { stop(); return false; }
                return true;
            }
            auto active() const noexcept -> bool override { return active_.load(std::memory_order_acquire); }
            auto notify_snapshot_changed() -> void override {
                if (!stopping_.load(std::memory_order_acquire)) { dirty_.store(true, std::memory_order_release); wake(); }
            }
            auto show_notification(TrayNotification const& notif, TrayState icon_state) -> bool override {
                if (stopping_.load(std::memory_order_acquire)) return false;
                { std::lock_guard lk(notif_mu_); if (pending_notifs_.size() >= 8) pending_notifs_.pop_front(); pending_notifs_.emplace_back(notif, icon_state); }
                wake(); return true;
            }
            auto stop() noexcept -> void override {
                stopping_.store(true, std::memory_order_seq_cst); active_.store(false, std::memory_order_release); wake();
                if (worker_.joinable()) { if (worker_.get_id() == std::this_thread::get_id()) return; worker_.join(); }
                close_wake_fd();
            }
        };
    }

    auto create_linux_sni_tray(NativeTrayHost host) -> std::unique_ptr<NativeTrayBackend> {
        auto backend = std::make_unique<sni_abi::LinuxSniBackend>(std::move(host));
        return backend->start() ? std::move(backend) : nullptr;
    }
#else
    auto create_linux_sni_tray(NativeTrayHost) -> std::unique_ptr<NativeTrayBackend> { return nullptr; }
#endif
}
