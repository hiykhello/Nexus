module;
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#elif !defined(__APPLE__)
#include <cstdint>
#include <cstring>
#include <dlfcn.h>
#endif
module desktop.window_blur;

import std;

namespace desktop {
#if !defined(_WIN32) && !defined(__APPLE__)
    namespace wayland_abi {
        struct wl_interface;
        struct wl_message {
            char const* name;
            char const* signature;
            wl_interface const** types;
        };
        struct wl_interface {
            char const* name;
            int version;
            int method_count;
            wl_message const* methods;
            int event_count;
            wl_message const* events;
        };
        struct wl_registry_listener {
            void (*global)(void* data, void* registry, std::uint32_t name, char const* iface, std::uint32_t version);
            void (*global_remove)(void* data, void* registry, std::uint32_t name);
        };
        struct ext_mgr_listener {
            void (*capabilities)(void* data, void* mgr, std::uint32_t flags);
        };

        inline constexpr std::uint32_t kMarshalDestroy = 1u << 0;
        inline constexpr std::uint32_t kWlDisplayGetRegistry = 1;
        inline constexpr std::uint32_t kWlRegistryBind = 0;
        inline constexpr std::uint32_t kWlCompositorCreateRegion = 1;
        inline constexpr std::uint32_t kWlSurfaceSetOpaqueRegion = 4;
        inline constexpr std::uint32_t kWlRegionDestroy = 0;
        inline constexpr std::uint32_t kWlRegionAdd = 1;
        inline constexpr std::uint32_t kExtMgrDestroy = 0;
        inline constexpr std::uint32_t kExtMgrGetBackgroundEffect = 1;
        inline constexpr std::uint32_t kExtSurfDestroy = 0;
        inline constexpr std::uint32_t kExtSurfSetBlurRegion = 1;
        inline constexpr std::uint32_t kExtCapBlur = 1;
        inline constexpr std::uint32_t kKwinMgrCreate = 0;
        inline constexpr std::uint32_t kKwinMgrUnset = 1;
        inline constexpr std::uint32_t kKwinBlurCommit = 0;
        inline constexpr std::uint32_t kKwinBlurSetRegion = 1;
        inline constexpr std::uint32_t kKwinBlurRelease = 2;

        struct WaylandFuncs {
            void* lib = nullptr;
            void* (*create_queue)(void*) = nullptr;
            void (*destroy_queue)(void*) = nullptr;
            int (*roundtrip_queue)(void*, void*) = nullptr;
            int (*flush)(void*) = nullptr;
            void* (*create_wrapper)(void*) = nullptr;
            void (*destroy_wrapper)(void*) = nullptr;
            void (*destroy_proxy)(void*) = nullptr;
            std::uint32_t (*proxy_version)(void*) = nullptr;
            int (*add_listener)(void*, void (**)(void), void*) = nullptr;
            void* (*marshal_flags)(void*, std::uint32_t, wl_interface const*, std::uint32_t, std::uint32_t, ...) = nullptr;
            wl_interface const* registry_iface = nullptr;
            wl_interface const* compositor_iface = nullptr;
            wl_interface const* region_iface = nullptr;
            bool loaded = false;

            auto load() -> bool {
                if (loaded) return true;
                lib = ::dlopen("libwayland-client.so.0", RTLD_LAZY | RTLD_NOLOAD);
                if (!lib) lib = ::dlopen("libwayland-client.so.0", RTLD_LAZY);
                if (!lib) return false;
                auto sym = [this](auto& fn, char const* name) {
                    using Fn = std::decay_t<decltype(fn)>;
                    fn = reinterpret_cast<Fn>(::dlsym(lib, name));
                    return fn != nullptr;
                };
                loaded = sym(create_queue, "wl_display_create_queue")
                    && sym(destroy_queue, "wl_event_queue_destroy")
                    && sym(roundtrip_queue, "wl_display_roundtrip_queue")
                    && sym(flush, "wl_display_flush")
                    && sym(create_wrapper, "wl_proxy_create_wrapper")
                    && sym(destroy_wrapper, "wl_proxy_wrapper_destroy")
                    && sym(destroy_proxy, "wl_proxy_destroy")
                    && sym(proxy_version, "wl_proxy_get_version")
                    && sym(add_listener, "wl_proxy_add_listener")
                    && sym(marshal_flags, "wl_proxy_marshal_flags")
                    && sym(registry_iface, "wl_registry_interface")
                    && sym(compositor_iface, "wl_compositor_interface")
                    && sym(region_iface, "wl_region_interface");
                if (!loaded) {
                    ::dlclose(lib);
                    lib = nullptr;
                }
                return loaded;
            }

            ~WaylandFuncs() {
                if (lib) {
                    ::dlclose(lib);
                    lib = nullptr;
                }
            }
        };

        wl_interface const* kNullTypes[4] = {nullptr, nullptr, nullptr, nullptr};
        wl_message const kExtMgrRequests[2] = {{"destroy", "", kNullTypes}, {"get_background_effect", "no", kNullTypes}};
        wl_message const kExtMgrEvents[1] = {{"capabilities", "u", kNullTypes}};
        wl_interface const kExtMgrIface = {"ext_background_effect_manager_v1", 1, 2, kExtMgrRequests, 1, kExtMgrEvents};
        wl_message const kExtSurfRequests[2] = {{"destroy", "", kNullTypes}, {"set_blur_region", "?o", kNullTypes}};
        wl_interface const kExtSurfIface = {"ext_background_effect_surface_v1", 1, 2, kExtSurfRequests, 0, nullptr};

        wl_message const kKwinMgrRequests[2] = {{"create", "no", kNullTypes}, {"unset", "o", kNullTypes}};
        wl_interface const kKwinMgrIface = {"org_kde_kwin_blur_manager", 1, 2, kKwinMgrRequests, 0, nullptr};
        wl_message const kKwinBlurRequests[3] = {{"commit", "", kNullTypes}, {"set_region", "?o", kNullTypes}, {"release", "", kNullTypes}};
        wl_interface const kKwinBlurIface = {"org_kde_kwin_blur", 1, 3, kKwinBlurRequests, 0, nullptr};
    }
#elif defined(_WIN32)
    namespace win_abi {
        struct Margins { int left, right, top, bottom; };
        using FnSetAttr = HRESULT (WINAPI*)(HWND, DWORD, void const*, DWORD);
        using FnExtend = HRESULT (WINAPI*)(HWND, Margins const*);
    }
#endif

    struct WindowBlurController::Impl {
        bool is_active = false;
        std::string backend;
        bool has_synced = false;
        bool last_enabled = false;
        bool last_dark = false;
        int last_w = 0;
        int last_h = 0;

#if !defined(_WIN32) && !defined(__APPLE__)
        wayland_abi::WaylandFuncs wl;
        void* display = nullptr;
        void* surface = nullptr;
        void* queue = nullptr;
        void* display_wrapper = nullptr;
        void* registry = nullptr;
        void* compositor = nullptr;
        void* ext_mgr = nullptr;
        void* ext_surf = nullptr;
        void* kwin_mgr = nullptr;
        void* kwin_blur = nullptr;
        std::uint32_t ext_caps = 0;
#elif defined(_WIN32)
        HWND hwnd = nullptr;
        HMODULE dwm = nullptr;
        win_abi::FnSetAttr set_attr = nullptr;
        win_abi::FnExtend extend_frame = nullptr;
#endif

        static auto on_global(void* data, void* reg, std::uint32_t name, char const* iface, std::uint32_t) -> void {
#if !defined(_WIN32) && !defined(__APPLE__)
            auto* s = static_cast<Impl*>(data);
            if (std::strcmp(iface, "wl_compositor") == 0 && !s->compositor) {
                s->compositor = s->wl.marshal_flags(reg, wayland_abi::kWlRegistryBind,
                    s->wl.compositor_iface, 1, 0, name, s->wl.compositor_iface->name, 1u, nullptr);
            } else if (std::strcmp(iface, "ext_background_effect_manager_v1") == 0 && !s->ext_mgr) {
                s->ext_mgr = s->wl.marshal_flags(reg, wayland_abi::kWlRegistryBind,
                    &wayland_abi::kExtMgrIface, 1, 0, name, wayland_abi::kExtMgrIface.name, 1u, nullptr);
            } else if (std::strcmp(iface, "org_kde_kwin_blur_manager") == 0 && !s->kwin_mgr) {
                s->kwin_mgr = s->wl.marshal_flags(reg, wayland_abi::kWlRegistryBind,
                    &wayland_abi::kKwinMgrIface, 1, 0, name, wayland_abi::kKwinMgrIface.name, 1u, nullptr);
            }
#else
            (void)data; (void)reg; (void)name; (void)iface;
#endif
        }

        static auto on_global_remove(void*, void*, std::uint32_t) -> void {}

        static auto on_ext_caps(void* data, void*, std::uint32_t flags) -> void {
#if !defined(_WIN32) && !defined(__APPLE__)
            static_cast<Impl*>(data)->ext_caps = flags;
#else
            (void)data; (void)flags;
#endif
        }
        auto detach_impl() noexcept -> void {
#if !defined(_WIN32) && !defined(__APPLE__)
            if (wl.loaded) {
                if (ext_surf) { wl.marshal_flags(ext_surf, wayland_abi::kExtSurfDestroy, nullptr, 1, wayland_abi::kMarshalDestroy); ext_surf = nullptr; }
                if (ext_mgr) { wl.marshal_flags(ext_mgr, wayland_abi::kExtMgrDestroy, nullptr, 1, wayland_abi::kMarshalDestroy); ext_mgr = nullptr; }
                if (kwin_blur) { wl.marshal_flags(kwin_blur, wayland_abi::kKwinBlurRelease, nullptr, 1, wayland_abi::kMarshalDestroy); kwin_blur = nullptr; }
                if (kwin_mgr) { wl.destroy_proxy(kwin_mgr); kwin_mgr = nullptr; }
                if (compositor) { wl.destroy_proxy(compositor); compositor = nullptr; }
                if (registry) { wl.destroy_proxy(registry); registry = nullptr; }
                if (display_wrapper) { wl.destroy_wrapper(display_wrapper); display_wrapper = nullptr; }
                if (queue) { wl.destroy_queue(queue); queue = nullptr; }
                if (display) wl.flush(display);
            }
            display = nullptr; surface = nullptr; ext_caps = 0;
#elif defined(_WIN32)
            if (dwm) { ::FreeLibrary(dwm); dwm = nullptr; }
            hwnd = nullptr; set_attr = nullptr; extend_frame = nullptr;
#endif
            is_active = false;
            has_synced = false;
            backend.clear();
        }

        ~Impl() { detach_impl(); }
    };

    WindowBlurController::WindowBlurController() : impl_(std::make_unique<Impl>()) {}
    WindowBlurController::~WindowBlurController() = default;
    WindowBlurController::WindowBlurController(WindowBlurController&&) noexcept = default;
    auto WindowBlurController::operator=(WindowBlurController&&) noexcept -> WindowBlurController& = default;

    auto WindowBlurController::attach_wayland(void* wl_display_ptr, void* wl_surface_ptr) -> bool {
        if (!impl_) return false;
        detach();
#if !defined(_WIN32) && !defined(__APPLE__)
        if (!wl_display_ptr || !wl_surface_ptr || !impl_->wl.load()) return false;
        auto& s = *impl_;
        s.display = wl_display_ptr;
        s.surface = wl_surface_ptr;
        // Dedicated event queue keeps protocol roundtrips isolated from winit's default queue.
        s.queue = s.wl.create_queue(s.display);
        if (!s.queue) return false;
        s.display_wrapper = s.wl.create_wrapper(s.display);
        if (!s.display_wrapper) { detach(); return false; }
        if (auto* set_q = reinterpret_cast<void (*)(void*, void*)>(::dlsym(s.wl.lib, "wl_proxy_set_queue"))) {
            set_q(s.display_wrapper, s.queue);
        } else {
            detach();
            return false;
        }
        s.registry = s.wl.marshal_flags(s.display_wrapper, wayland_abi::kWlDisplayGetRegistry,
            s.wl.registry_iface, s.wl.proxy_version(s.display_wrapper), 0, nullptr);
        if (!s.registry) { detach(); return false; }
        static wayland_abi::wl_registry_listener const reg_listener{&Impl::on_global, &Impl::on_global_remove};
        s.wl.add_listener(s.registry, reinterpret_cast<void (**)(void)>(const_cast<wayland_abi::wl_registry_listener*>(&reg_listener)), &s);
        if (s.wl.roundtrip_queue(s.display, s.queue) < 0) { detach(); return false; }

        if (s.ext_mgr) {
            static wayland_abi::ext_mgr_listener const caps_listener{&Impl::on_ext_caps};
            s.wl.add_listener(s.ext_mgr, reinterpret_cast<void (**)(void)>(const_cast<wayland_abi::ext_mgr_listener*>(&caps_listener)), &s);
            if (s.wl.roundtrip_queue(s.display, s.queue) >= 0 && (s.ext_caps & wayland_abi::kExtCapBlur) != 0) {
                s.ext_surf = s.wl.marshal_flags(s.ext_mgr, wayland_abi::kExtMgrGetBackgroundEffect,
                    &wayland_abi::kExtSurfIface, 1, 0, nullptr, s.surface);
                if (s.ext_surf) {
                    s.is_active = true;
                    s.backend = "Wayland Blur";
                    std::clog << "[nexus-desktop] native blur attached: " << s.backend << '\n';
                    return true;
                }
            }
        }
        if (s.kwin_mgr) {
            s.is_active = true;
            s.backend = "KWin Blur";
            std::clog << "[nexus-desktop] native blur attached: " << s.backend << '\n';
            return true;
        }
        detach();
        return false;
#else
        (void)wl_display_ptr; (void)wl_surface_ptr;
        return false;
#endif
    }

    auto WindowBlurController::attach_win32(void* hwnd_ptr) -> bool {
        if (!impl_) return false;
        detach();
#ifdef _WIN32
        if (!hwnd_ptr) return false;
        auto& s = *impl_;
        s.dwm = ::LoadLibraryW(L"dwmapi.dll");
        if (!s.dwm) return false;
        s.set_attr = reinterpret_cast<win_abi::FnSetAttr>(::GetProcAddress(s.dwm, "DwmSetWindowAttribute"));
        s.extend_frame = reinterpret_cast<win_abi::FnExtend>(::GetProcAddress(s.dwm, "DwmExtendFrameIntoClientArea"));
        if (!s.set_attr || !s.extend_frame) { detach(); return false; }
        s.hwnd = static_cast<HWND>(hwnd_ptr);
        int probe = 1; // DWMSBT_NONE (requires Win11 22H2+ DWMWA_SYSTEMBACKDROP_TYPE)
        if (FAILED(s.set_attr(s.hwnd, 38, &probe, sizeof(probe)))) {
            detach();
            return false;
        }
        s.is_active = true;
        s.backend = "DWM Acrylic";
        std::clog << "[nexus-desktop] native blur attached: " << s.backend << '\n';
        return true;
#else
        (void)hwnd_ptr;
        return false;
#endif
    }

    auto WindowBlurController::sync(bool enabled, int logical_width, int logical_height, bool dark_mode) -> void {
        if (!impl_) return;
        auto& s = *impl_;
        if (!s.is_active) return;
        int lw = std::max(1, logical_width), lh = std::max(1, logical_height);
        if (s.has_synced && enabled == s.last_enabled && (!enabled || (lw == s.last_w && lh == s.last_h && dark_mode == s.last_dark))) {
            return;
        }
        s.has_synced = true;
        s.last_enabled = enabled;
        s.last_dark = dark_mode;
        s.last_w = lw;
        s.last_h = lh;

#if !defined(_WIN32) && !defined(__APPLE__)
        if (s.ext_surf) {
            void* region = nullptr;
            if (enabled && s.compositor) {
                region = s.wl.marshal_flags(s.compositor, wayland_abi::kWlCompositorCreateRegion,
                    s.wl.region_iface, s.wl.proxy_version(s.compositor), 0, nullptr);
                if (region) s.wl.marshal_flags(region, wayland_abi::kWlRegionAdd, nullptr, s.wl.proxy_version(region), 0, 0, 0, lw, lh);
            }
            s.wl.marshal_flags(s.ext_surf, wayland_abi::kExtSurfSetBlurRegion, nullptr, 1, 0, region);
            if (region) s.wl.marshal_flags(region, wayland_abi::kWlRegionDestroy, nullptr, s.wl.proxy_version(region), wayland_abi::kMarshalDestroy);
            if (enabled) s.wl.marshal_flags(s.surface, wayland_abi::kWlSurfaceSetOpaqueRegion, nullptr, s.wl.proxy_version(s.surface), 0, nullptr);
            s.wl.flush(s.display);
        } else if (s.kwin_mgr) {
            if (enabled) {
                if (!s.kwin_blur) {
                    s.kwin_blur = s.wl.marshal_flags(s.kwin_mgr, wayland_abi::kKwinMgrCreate, &wayland_abi::kKwinBlurIface, 1, 0, nullptr, s.surface);
                }
                if (s.kwin_blur) {
                    void* region = s.compositor ? s.wl.marshal_flags(s.compositor, wayland_abi::kWlCompositorCreateRegion,
                        s.wl.region_iface, s.wl.proxy_version(s.compositor), 0, nullptr) : nullptr;
                    if (region) s.wl.marshal_flags(region, wayland_abi::kWlRegionAdd, nullptr, s.wl.proxy_version(region), 0, 0, 0, lw, lh);
                    s.wl.marshal_flags(s.kwin_blur, wayland_abi::kKwinBlurSetRegion, nullptr, 1, 0, region);
                    if (region) s.wl.marshal_flags(region, wayland_abi::kWlRegionDestroy, nullptr, s.wl.proxy_version(region), wayland_abi::kMarshalDestroy);
                    s.wl.marshal_flags(s.kwin_blur, wayland_abi::kKwinBlurCommit, nullptr, 1, 0);
                }
            } else {
                s.wl.marshal_flags(s.kwin_mgr, wayland_abi::kKwinMgrUnset, nullptr, 1, 0, s.surface);
                if (s.kwin_blur) {
                    s.wl.marshal_flags(s.kwin_blur, wayland_abi::kKwinBlurRelease, nullptr, 1, wayland_abi::kMarshalDestroy);
                    s.kwin_blur = nullptr;
                }
            }
            s.wl.flush(s.display);
        }
#elif defined(_WIN32)
        if (s.hwnd && s.set_attr && s.extend_frame) {
            BOOL dark = dark_mode ? TRUE : FALSE;
            (void)s.set_attr(s.hwnd, 20, &dark, sizeof(dark));
            int backdrop = enabled ? 3 : 1; // 3=Acrylic, 1=None
            (void)s.set_attr(s.hwnd, 38, &backdrop, sizeof(backdrop));
            win_abi::Margins m = enabled ? win_abi::Margins{-1, -1, -1, -1} : win_abi::Margins{0, 0, 0, 0};
            (void)s.extend_frame(s.hwnd, &m);
        }
#endif
    }

    auto WindowBlurController::detach() -> void {
        if (!impl_) return;
        impl_->detach_impl();
    }

    auto WindowBlurController::active() const noexcept -> bool { return impl_ && impl_->is_active; }
    auto WindowBlurController::backend_name() const noexcept -> std::string_view { return impl_ ? std::string_view(impl_->backend) : std::string_view{}; }
}
