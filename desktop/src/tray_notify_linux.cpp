module;
#if defined(__linux__)
#include <cstdint>
#include <cstdlib>
#include <dlfcn.h>
#endif
module desktop.tray_controller;

import std;

namespace desktop::detail {
#if defined(__linux__)
    namespace notify_abi {
        using Bool = std::uint32_t;
        struct Conn;
        struct Msg;
        struct Err { char const *name, *message; unsigned int d1:1, d2:1, d3:1, d4:1, d5:1; void* pad1; };
        struct Iter { void *d1, *d2; std::uint32_t d3; int d4, d5, d6, d7, d8, d9, d10, d11, pad1; void *pad2, *pad3; };

        inline constexpr int kBusSession = 0;
        inline constexpr int kByte = 'y', kBool = 'b', kI32 = 'i', kU32 = 'u', kStr = 's';
        inline constexpr int kArr = 'a', kVar = 'v', kStruct = 'r', kDict = 'e';

        struct NotifySyms {
            void (*err_init)(Err*) = nullptr;
            void (*err_free)(Err*) = nullptr;
            Bool (*err_is_set)(Err const*) = nullptr;
            Conn* (*bus_get_priv)(int, Err*) = nullptr;
            void (*exit_on_disc)(Conn*, Bool) = nullptr;
            Bool (*send)(Conn*, Msg*, std::uint32_t*) = nullptr;
            void (*flush)(Conn*) = nullptr;
            void (*close_conn)(Conn*) = nullptr;
            void (*unref_conn)(Conn*) = nullptr;
            Msg* (*new_call)(char const*, char const*, char const*, char const*) = nullptr;
            void (*set_no_reply)(Msg*, Bool) = nullptr;
            void (*unref_msg)(Msg*) = nullptr;
            void (*init_append)(Msg*, Iter*) = nullptr;
            Bool (*basic)(Iter*, int, void const*) = nullptr;
            Bool (*fixed_arr)(Iter*, int, void const*, int) = nullptr;
            Bool (*open)(Iter*, int, char const*, Iter*) = nullptr;
            Bool (*close)(Iter*, Iter*) = nullptr;

            auto resolve_send(void* handle) -> bool {
                if (!handle) return false;
                auto s = [handle](auto& fn, char const* n) {
                    fn = reinterpret_cast<std::decay_t<decltype(fn)>>(::dlsym(handle, n));
                    return fn != nullptr;
                };
                return s(send, "dbus_connection_send")
                    && s(flush, "dbus_connection_flush")
                    && s(new_call, "dbus_message_new_method_call")
                    && s(set_no_reply, "dbus_message_set_no_reply")
                    && s(unref_msg, "dbus_message_unref")
                    && s(init_append, "dbus_message_iter_init_append")
                    && s(basic, "dbus_message_iter_append_basic")
                    && s(fixed_arr, "dbus_message_iter_append_fixed_array")
                    && s(open, "dbus_message_iter_open_container")
                    && s(close, "dbus_message_iter_close_container");
            }

            auto resolve_bus(void* handle) -> bool {
                if (!resolve_send(handle)) return false;
                auto s = [handle](auto& fn, char const* n) {
                    fn = reinterpret_cast<std::decay_t<decltype(fn)>>(::dlsym(handle, n));
                    return fn != nullptr;
                };
                return s(err_init, "dbus_error_init")
                    && s(err_free, "dbus_error_free")
                    && s(err_is_set, "dbus_error_is_set")
                    && s(bus_get_priv, "dbus_bus_get_private")
                    && s(exit_on_disc, "dbus_connection_set_exit_on_disconnect")
                    && s(close_conn, "dbus_connection_close")
                    && s(unref_conn, "dbus_connection_unref");
            }
        };

        auto emit_notify(NotifySyms const& l, Conn* c, TrayNotification const& notif, TrayState icon_state) -> bool {
            if (!c) return false;
            auto* msg = l.new_call("org.freedesktop.Notifications", "/org/freedesktop/Notifications",
                "org.freedesktop.Notifications", "Notify");
            if (!msg) return false;
            l.set_no_reply(msg, 1u);

            std::string title_str = notif.title.empty() ? std::string("Nexus") : notif.title;
            char const* app_name = "Nexus";
            std::uint32_t replaces_id = 0u;
            char const* app_icon = "";
            char const* summary = title_str.c_str();
            char const* body = notif.body.c_str();
            std::int32_t expire_ms = notif.urgency == TrayNotificationUrgency::error ? 8000 : 5000;

            Iter it{}, actions{}, hints{};
            l.init_append(msg, &it);
            l.basic(&it, kStr, &app_name);
            l.basic(&it, kU32, &replaces_id);
            l.basic(&it, kStr, &app_icon);
            l.basic(&it, kStr, &summary);
            l.basic(&it, kStr, &body);
            l.open(&it, kArr, "s", &actions);
            l.close(&it, &actions);

            l.open(&it, kArr, "{sv}", &hints);
            {
                Iter e{}, v{};
                char const* k = "urgency";
                std::uint8_t u = notif.urgency == TrayNotificationUrgency::error ? 2u : 1u;
                l.open(&hints, kDict, nullptr, &e);
                l.basic(&e, kStr, &k);
                l.open(&e, kVar, "y", &v);
                l.basic(&v, kByte, &u);
                l.close(&e, &v);
                l.close(&hints, &e);
            }
            {
                Iter e{}, v{};
                char const *k = "desktop-entry", *val = "nexus-desktop";
                l.open(&hints, kDict, nullptr, &e);
                l.basic(&e, kStr, &k);
                l.open(&e, kVar, "s", &v);
                l.basic(&v, kStr, &val);
                l.close(&e, &v);
                l.close(&hints, &e);
            }
            {
                auto argb = render_prism_icon_argb32(icon_state);
                std::array<std::uint8_t, 32 * 32 * 4> rgba{};
                for (std::size_t i = 0; i < rgba.size(); i += 4) {
                    rgba[i + 0] = argb[i + 1]; // R
                    rgba[i + 1] = argb[i + 2]; // G
                    rgba[i + 2] = argb[i + 3]; // B
                    rgba[i + 3] = argb[i + 0]; // A
                }
                Iter e{}, v{}, st{}, px{};
                char const* k = "image-data";
                std::int32_t w = 32, h = 32, stride = 32 * 4, bps = 8, ch = 4;
                Bool has_alpha = 1u;
                std::uint8_t const* ptr = rgba.data();
                l.open(&hints, kDict, nullptr, &e);
                l.basic(&e, kStr, &k);
                l.open(&e, kVar, "(iiibiiay)", &v);
                l.open(&v, kStruct, nullptr, &st);
                l.basic(&st, kI32, &w);
                l.basic(&st, kI32, &h);
                l.basic(&st, kI32, &stride);
                l.basic(&st, kBool, &has_alpha);
                l.basic(&st, kI32, &bps);
                l.basic(&st, kI32, &ch);
                l.open(&st, kArr, "y", &px);
                l.fixed_arr(&px, kByte, &ptr, static_cast<int>(rgba.size()));
                l.close(&st, &px);
                l.close(&v, &st);
                l.close(&e, &v);
                l.close(&hints, &e);
            }
            l.close(&it, &hints);
            l.basic(&it, kI32, &expire_ms);

            bool const ok = l.send(c, msg, nullptr) != 0u;
            if (ok) l.flush(c);
            l.unref_msg(msg);
            return ok;
        }
    }

    auto send_linux_dbus_notification_on_conn(
        void* dbus_dl_handle, void* dbus_conn,
        TrayNotification const& notif, TrayState icon_state) -> bool {
        if (!dbus_dl_handle || !dbus_conn) return false;
        notify_abi::NotifySyms syms{};
        if (!syms.resolve_send(dbus_dl_handle)) return false;
        return notify_abi::emit_notify(syms, static_cast<notify_abi::Conn*>(dbus_conn), notif, icon_state);
    }

    auto send_linux_desktop_notification(TrayNotification const& notif, TrayState icon_state) -> bool {
        if (native_tray_disabled_by_env()) return false;
        char const* bus_addr = std::getenv("DBUS_SESSION_BUS_ADDRESS");
        if (!bus_addr || !*bus_addr) return false;

        struct SharedDbus {
            void* handle = nullptr;
            notify_abi::NotifySyms syms{};
            bool ok = false;
            SharedDbus() {
                handle = ::dlopen("libdbus-1.so.3", RTLD_LAZY | RTLD_LOCAL);
                if (!handle) handle = ::dlopen("libdbus-1.so", RTLD_LAZY | RTLD_LOCAL);
                if (handle) {
                    ok = syms.resolve_bus(handle);
                    if (!ok) { ::dlclose(handle); handle = nullptr; }
                }
            }
            ~SharedDbus() { if (handle) ::dlclose(handle); }
        };
        static SharedDbus dbus;
        if (!dbus.ok) return false;

        notify_abi::Err err{};
        dbus.syms.err_init(&err);
        auto* conn = dbus.syms.bus_get_priv(notify_abi::kBusSession, &err);
        if (!conn || dbus.syms.err_is_set(&err)) {
            dbus.syms.err_free(&err);
            if (conn) { dbus.syms.close_conn(conn); dbus.syms.unref_conn(conn); }
            return false;
        }
        dbus.syms.err_free(&err);
        dbus.syms.exit_on_disc(conn, 0u);
        bool const sent = notify_abi::emit_notify(dbus.syms, conn, notif, icon_state);
        dbus.syms.close_conn(conn);
        dbus.syms.unref_conn(conn);
        return sent;
    }
#else
    auto send_linux_dbus_notification_on_conn(void*, void*, TrayNotification const&, TrayState) -> bool {
        return false;
    }
    auto send_linux_desktop_notification(TrayNotification const&, TrayState) -> bool {
        return false;
    }
#endif
}
