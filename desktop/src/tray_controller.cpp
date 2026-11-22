module;

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shellapi.h>
#endif

module desktop.tray_controller;

import std;

namespace desktop {
    namespace {
        auto format_tooltip(TrayState st, std::string_view detail) -> std::string {
            std::string_view base = "Nexus - 已停止";
            if (st == TrayState::running) base = "Nexus - 运行中";
            else if (st == TrayState::tun_active) base = "Nexus - TUN 已接管";
            if (detail.empty()) return std::string(base);
            return std::format("{} ({})", base, detail);
        }

#ifdef _WIN32
        constexpr UINT kTrayCallbackMsg = WM_APP + 101;
        constexpr UINT kTrayQuitMsg = WM_APP + 102;
        constexpr UINT kMenuShowId = 1001;
        constexpr UINT kMenuReloadId = 1002;
        constexpr UINT kMenuQuitId = 1003;

        auto to_wide(std::string_view utf8) -> std::wstring {
            if (utf8.empty()) return {};
            int len = ::MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
            if (len <= 0) return L"Nexus";
            std::wstring out(static_cast<std::size_t>(len), L'\0');
            ::MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), out.data(), len);
            return out;
        }
#endif
    }

    struct TrayController::Impl {
        TrayCallbacks callbacks;
        mutable std::mutex mutex;
        std::atomic<TrayState> state{TrayState::offline};
        std::atomic<bool> quit{false};
        std::atomic<bool> stopped{false};
        std::string tooltip_text{"Nexus - 已停止"};
#ifdef _WIN32
        std::thread ui_thread;
        std::atomic<HWND> hwnd{nullptr};

        static auto CALLBACK wnd_proc(HWND w, UINT msg, WPARAM wp, LPARAM lp) -> LRESULT {
            auto* self = reinterpret_cast<Impl*>(::GetWindowLongPtrW(w, GWLP_USERDATA));
            if (msg == WM_NCCREATE) {
                auto* cs = reinterpret_cast<CREATESTRUCTW const*>(lp);
                self = static_cast<Impl*>(cs->lpCreateParams);
                ::SetWindowLongPtrW(w, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
            }
            if (self && msg == kTrayCallbackMsg) {
                if (lp == WM_LBUTTONDBLCLK && self->callbacks.on_show) self->callbacks.on_show();
                else if (lp == WM_RBUTTONUP) {
                    POINT pt{};
                    ::GetCursorPos(&pt);
                    HMENU menu = ::CreatePopupMenu();
                    ::AppendMenuW(menu, MF_STRING, kMenuShowId, L"打开 Nexus");
                    ::AppendMenuW(menu, MF_STRING, kMenuReloadId, L"热重载配置");
                    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
                    ::AppendMenuW(menu, MF_STRING, kMenuQuitId, L"退出");
                    ::SetForegroundWindow(w);
                    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, w, nullptr);
                    ::DestroyMenu(menu);
                }
                return 0;
            }
            if (msg == kTrayQuitMsg) {
                ::PostQuitMessage(0);
                return 0;
            }
            if (self && msg == WM_COMMAND) {
                switch (LOWORD(wp)) {
                case kMenuShowId:
                    if (self->callbacks.on_show) self->callbacks.on_show();
                    return 0;
                case kMenuReloadId:
                    if (self->callbacks.on_reload) self->callbacks.on_reload();
                    return 0;
                case kMenuQuitId:
                    self->quit.store(true, std::memory_order_release);
                    if (self->callbacks.on_quit) self->callbacks.on_quit();
                    return 0;
                }
            }
            return ::DefWindowProcW(w, msg, wp, lp);
        }

        auto start_win32() -> void {
            ui_thread = std::thread([this] {
                HINSTANCE hinst = ::GetModuleHandleW(nullptr);
                WNDCLASSW wc{};
                wc.lpfnWndProc = &Impl::wnd_proc;
                wc.hInstance = hinst;
                wc.lpszClassName = L"NexusTrayHiddenWnd";
                ::RegisterClassW(&wc);
                HWND w = ::CreateWindowExW(0, wc.lpszClassName, L"NexusTray", 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, hinst, this);
                hwnd.store(w, std::memory_order_seq_cst);
                if (w) {
                    NOTIFYICONDATAW nid{};
                    nid.cbSize = sizeof(nid);
                    nid.hWnd = w;
                    nid.uID = 1;
                    nid.uFlags = NIF_MESSAGE | NIF_TIP | NIF_ICON;
                    nid.uCallbackMessage = kTrayCallbackMsg;
                    nid.hIcon = ::LoadIconW(nullptr, MAKEINTRESOURCEW(32512) /* IDI_APPLICATION */);
                    wcsncpy_s(nid.szTip, L"Nexus - 已停止", _TRUNCATE);
                    ::Shell_NotifyIconW(NIM_ADD, &nid);
                }
                MSG m{};
                while (!stopped.load(std::memory_order_seq_cst) && ::GetMessageW(&m, nullptr, 0, 0) > 0) {
                    ::TranslateMessage(&m);
                    ::DispatchMessageW(&m);
                }
                if (HWND cur = hwnd.exchange(nullptr, std::memory_order_acq_rel)) {
                    NOTIFYICONDATAW nid{};
                    nid.cbSize = sizeof(nid);
                    nid.hWnd = cur;
                    nid.uID = 1;
                    ::Shell_NotifyIconW(NIM_DELETE, &nid);
                    ::DestroyWindow(cur);
                }
            });
        }
#endif
    };

    TrayController::TrayController(TrayCallbacks callbacks) : impl_(std::make_unique<Impl>()) {
        impl_->callbacks = std::move(callbacks);
#ifdef _WIN32
        impl_->start_win32();
#endif
    }

    TrayController::~TrayController() { stop(); }
    TrayController::TrayController(TrayController&&) noexcept = default;
    auto TrayController::operator=(TrayController&&) noexcept -> TrayController& = default;

    auto TrayController::set_status(this TrayController& self, TrayState state, std::string_view summary) -> void {
        if (!self.impl_ || self.impl_->stopped.load(std::memory_order_acquire)) return;
        self.impl_->state.store(state, std::memory_order_release);
        auto tip = format_tooltip(state, summary);
        {
            std::lock_guard lock(self.impl_->mutex);
            self.impl_->tooltip_text = tip;
        }
#ifdef _WIN32
        if (HWND w = self.impl_->hwnd.load(std::memory_order_acquire)) {
            NOTIFYICONDATAW nid{};
            nid.cbSize = sizeof(nid);
            nid.hWnd = w;
            nid.uID = 1;
            nid.uFlags = NIF_TIP;
            auto wide = to_wide(tip);
            wcsncpy_s(nid.szTip, wide.c_str(), _TRUNCATE);
            ::Shell_NotifyIconW(NIM_MODIFY, &nid);
        }
#endif
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
        if (!self.impl_) return;
        if (self.impl_->stopped.exchange(true, std::memory_order_seq_cst)) return;
#ifdef _WIN32
        if (HWND w = self.impl_->hwnd.load(std::memory_order_seq_cst))
            ::PostMessageW(w, kTrayQuitMsg, 0, 0);
        if (self.impl_->ui_thread.joinable()) self.impl_->ui_thread.join();
#endif
    }
}
