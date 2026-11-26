module;
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shellapi.h>
#endif
module desktop.tray_controller;

import std;

namespace desktop::detail {
#ifdef _WIN32
    namespace win32_tray {
        constexpr UINT kTrayCallbackMsg = WM_APP + 101;
        constexpr UINT kTrayQuitMsg = WM_APP + 102;
        constexpr UINT kTraySyncMsg = WM_APP + 103;
        constexpr UINT kTrayNotifyMsg = WM_APP + 104;
        constexpr UINT kTrayIconId = 1;

        auto to_wide(std::string_view utf8) -> std::wstring {
            if (utf8.empty()) return {};
            int len = ::MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
            if (len <= 0) return L"Nexus";
            std::wstring out(static_cast<std::size_t>(len), L'\0');
            ::MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), out.data(), len);
            return out;
        }

        auto escape_win32_label(std::string_view utf8) -> std::wstring {
            auto wide = to_wide(utf8);
            std::wstring escaped;
            escaped.reserve(wide.size() + 4);
            for (wchar_t ch : wide) {
                if (ch == L'&') escaped.append(L"&&");
                else escaped.push_back(ch);
            }
            return escaped;
        }

        template <std::size_t N>
        auto copy_wide_trunc(wchar_t (&dst)[N], std::string_view utf8, wchar_t const* fallback = L"") -> void {
            auto wide = to_wide(utf8);
            if (wide.empty() && fallback) wide = fallback;
            auto const n = std::min(wide.size(), N - 1);
            std::copy_n(wide.data(), n, dst);
            dst[n] = L'\0';
        }

        auto make_prism_hicon(TrayState st) -> HICON {
            auto dib = build_win32_icon_dib(st);
            return ::CreateIconFromResourceEx(
                dib.data(), static_cast<DWORD>(dib.size()), TRUE, 0x00030000u, 32, 32, LR_DEFAULTCOLOR);
        }

        auto build_hmenu(std::vector<TrayMenuItem> const& items) -> HMENU {
            HMENU menu = ::CreatePopupMenu();
            if (!menu) return nullptr;
            UINT pos = 0;
            for (auto const& item : items) {
                MENUITEMINFOW mii{};
                mii.cbSize = sizeof(mii);
                if (item.kind == TrayMenuKind::separator) {
                    mii.fMask = MIIM_FTYPE;
                    mii.fType = MFT_SEPARATOR;
                    ::InsertMenuItemW(menu, pos++, TRUE, &mii);
                    continue;
                }
                auto label = escape_win32_label(item.label);
                mii.dwTypeData = label.data();
                if (item.kind == TrayMenuKind::submenu) {
                    HMENU sub = build_hmenu(item.children);
                    if (!sub) continue;
                    mii.fMask = MIIM_FTYPE | MIIM_STRING | MIIM_STATE | MIIM_SUBMENU;
                    mii.fType = MFT_STRING;
                    mii.fState = item.enabled ? MFS_ENABLED : MFS_DISABLED;
                    mii.hSubMenu = sub;
                    if (!::InsertMenuItemW(menu, pos, TRUE, &mii)) ::DestroyMenu(sub);
                    else ++pos;
                    continue;
                }
                mii.fMask = MIIM_FTYPE | MIIM_STRING | MIIM_STATE | MIIM_ID;
                mii.wID = static_cast<UINT>(item.id);
                mii.fType = MFT_STRING | (item.kind == TrayMenuKind::radio ? MFT_RADIOCHECK : 0u);
                bool const enabled = item.enabled && item.kind != TrayMenuKind::header;
                bool const checked = (item.kind == TrayMenuKind::checkbox || item.kind == TrayMenuKind::radio) && item.checked;
                mii.fState = (enabled ? MFS_ENABLED : MFS_DISABLED) | (checked ? MFS_CHECKED : MFS_UNCHECKED);
                ::InsertMenuItemW(menu, pos++, TRUE, &mii);
            }
            return menu;
        }

        class Win32TrayBackend final : public NativeTrayBackend {
            NativeTrayHost host_;
            std::thread ui_thread_;
            std::mutex notif_mu_;
            std::deque<TrayNotification> pending_notifs_;
            std::atomic<HWND> hwnd_{nullptr};
            std::atomic<bool> active_{false};
            std::atomic<bool> stopping_{false};
            HICON dynamic_icon_{nullptr};
            TrayState icon_state_{TrayState::offline};
            bool has_icon_state_{false};
            UINT taskbar_created_msg_{0};

            auto destroy_dynamic_icon() noexcept -> void {
                if (dynamic_icon_) {
                    ::DestroyIcon(dynamic_icon_);
                    dynamic_icon_ = nullptr;
                }
                has_icon_state_ = false;
            }

            auto add_icon(HWND w) -> bool {
                auto const snap = host_.get_snapshot();
                HICON next = make_prism_hicon(snap.state);
                NOTIFYICONDATAW nid{};
                nid.cbSize = sizeof(nid);
                nid.hWnd = w;
                nid.uID = kTrayIconId;
                nid.uFlags = NIF_MESSAGE | NIF_TIP | NIF_ICON;
                nid.uCallbackMessage = kTrayCallbackMsg;
                if (next) {
                    nid.hIcon = next;
                } else {
                    HINSTANCE hinst = ::GetModuleHandleW(nullptr);
                    nid.hIcon = ::LoadIconW(hinst, MAKEINTRESOURCEW(1));
                    if (!nid.hIcon) nid.hIcon = ::LoadIconW(nullptr, MAKEINTRESOURCEW(32512));
                }
                copy_wide_trunc(nid.szTip, host_.get_tooltip(), L"Nexus");
                bool const added = ::Shell_NotifyIconW(NIM_ADD, &nid) != FALSE;
                if (next) {
                    if (added) {
                        if (dynamic_icon_) ::DestroyIcon(dynamic_icon_);
                        dynamic_icon_ = next;
                        icon_state_ = snap.state;
                        has_icon_state_ = true;
                    } else {
                        ::DestroyIcon(next);
                    }
                }
                return added;
            }

            auto sync_icon_and_tooltip(HWND w) -> void {
                auto const snap = host_.get_snapshot();
                NOTIFYICONDATAW nid{};
                nid.cbSize = sizeof(nid);
                nid.hWnd = w;
                nid.uID = kTrayIconId;
                nid.uFlags = NIF_TIP;
                copy_wide_trunc(nid.szTip, host_.get_tooltip(), L"Nexus");
                HICON next = nullptr;
                if (!has_icon_state_ || snap.state != icon_state_) {
                    next = make_prism_hicon(snap.state);
                    if (next) {
                        nid.uFlags |= NIF_ICON;
                        nid.hIcon = next;
                    }
                }
                ::Shell_NotifyIconW(NIM_MODIFY, &nid);
                if (next) {
                    if (dynamic_icon_) ::DestroyIcon(dynamic_icon_);
                    dynamic_icon_ = next;
                    icon_state_ = snap.state;
                    has_icon_state_ = true;
                }
            }

            auto drain_notifications(HWND w) -> void {
                std::deque<TrayNotification> batch;
                { std::lock_guard lk(notif_mu_); batch.swap(pending_notifs_); }
                for (auto const& n : batch) {
                    NOTIFYICONDATAW nid{};
                    nid.cbSize = sizeof(nid);
                    nid.hWnd = w;
                    nid.uID = kTrayIconId;
                    nid.uFlags = NIF_INFO;
                    copy_wide_trunc(nid.szInfoTitle, n.title, L"Nexus");
                    copy_wide_trunc(nid.szInfo, n.body, L"");
                    nid.dwInfoFlags = n.urgency == TrayNotificationUrgency::error ? NIIF_ERROR
                        : (n.urgency == TrayNotificationUrgency::warning ? NIIF_WARNING : NIIF_INFO);
                    ::Shell_NotifyIconW(NIM_MODIFY, &nid);
                }
            }

            auto show_context_menu(HWND w) -> void {
                auto items = host_.get_menu();
                HMENU menu = build_hmenu(items);
                if (!menu) return;
                POINT pt{};
                ::GetCursorPos(&pt);
                ::SetForegroundWindow(w);
                ::TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_LEFTALIGN | TPM_BOTTOMALIGN, pt.x, pt.y, 0, w, nullptr);
                ::PostMessageW(w, WM_NULL, 0, 0);
                ::DestroyMenu(menu);
            }

            static LRESULT CALLBACK wnd_proc(HWND w, UINT msg, WPARAM wp, LPARAM lp) {
                auto* self = reinterpret_cast<Win32TrayBackend*>(::GetWindowLongPtrW(w, GWLP_USERDATA));
                if (msg == WM_NCCREATE) {
                    auto* cs = reinterpret_cast<CREATESTRUCTW const*>(lp);
                    self = static_cast<Win32TrayBackend*>(cs->lpCreateParams);
                    ::SetWindowLongPtrW(w, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
                }
                if (!self) return ::DefWindowProcW(w, msg, wp, lp);

                if (self->taskbar_created_msg_ != 0 && msg == self->taskbar_created_msg_) {
                    self->active_.store(self->add_icon(w), std::memory_order_release);
                    return 0;
                }
                if (msg == kTrayCallbackMsg) {
                    if (self->host_.is_stopped()) return 0;
                    if (lp == WM_LBUTTONUP) self->host_.primary_click();
                    else if (lp == WM_MBUTTONUP) self->host_.secondary_click();
                    else if (lp == WM_RBUTTONUP || lp == WM_CONTEXTMENU) self->show_context_menu(w);
                    return 0;
                }
                if (msg == kTraySyncMsg) {
                    self->sync_icon_and_tooltip(w);
                    return 0;
                }
                if (msg == kTrayNotifyMsg) {
                    self->drain_notifications(w);
                    return 0;
                }
                if (msg == kTrayQuitMsg) {
                    ::PostQuitMessage(0);
                    return 0;
                }
                if (msg == WM_COMMAND) {
                    if (!self->host_.is_stopped()) {
                        (void)self->host_.dispatch_menu_id(static_cast<std::int32_t>(LOWORD(wp)));
                    }
                    return 0;
                }
                return ::DefWindowProcW(w, msg, wp, lp);
            }

            auto run_loop(std::promise<bool> ready) -> void {
                HINSTANCE hinst = ::GetModuleHandleW(nullptr);
                WNDCLASSW wc{};
                wc.lpfnWndProc = &Win32TrayBackend::wnd_proc;
                wc.hInstance = hinst;
                wc.lpszClassName = L"NexusTrayHiddenWnd";
                ::RegisterClassW(&wc);
                taskbar_created_msg_ = ::RegisterWindowMessageW(L"TaskbarCreated");

                HWND w = ::CreateWindowExW(
                    0, wc.lpszClassName, L"NexusTray", WS_OVERLAPPED, 0, 0, 0, 0,
                    nullptr, nullptr, hinst, this);
                if (!w) {
                    ready.set_value(false);
                    return;
                }
                hwnd_.store(w, std::memory_order_seq_cst);
                bool const added = add_icon(w);
                active_.store(added, std::memory_order_release);
                ready.set_value(added);

                if (added) {
                    MSG m{};
                    while (!stopping_.load(std::memory_order_seq_cst) && ::GetMessageW(&m, nullptr, 0, 0) > 0) {
                        ::TranslateMessage(&m);
                        ::DispatchMessageW(&m);
                    }
                }

                active_.store(false, std::memory_order_release);
                if (HWND cur = hwnd_.exchange(nullptr, std::memory_order_acq_rel)) {
                    NOTIFYICONDATAW nid{};
                    nid.cbSize = sizeof(nid);
                    nid.hWnd = cur;
                    nid.uID = kTrayIconId;
                    ::Shell_NotifyIconW(NIM_DELETE, &nid);
                    ::DestroyWindow(cur);
                }
                destroy_dynamic_icon();
            }

        public:
            explicit Win32TrayBackend(NativeTrayHost host) : host_(std::move(host)) {}
            ~Win32TrayBackend() override { stop(); }

            auto start() -> bool {
                std::promise<bool> ready;
                auto fut = ready.get_future();
                ui_thread_ = std::thread([this, p = std::move(ready)]() mutable { run_loop(std::move(p)); });
                if (!fut.get()) {
                    stop();
                    return false;
                }
                return true;
            }

            auto active() const noexcept -> bool override {
                return active_.load(std::memory_order_acquire);
            }

            auto notify_snapshot_changed() -> void override {
                if (stopping_.load(std::memory_order_acquire)) return;
                if (HWND w = hwnd_.load(std::memory_order_acquire)) {
                    ::PostMessageW(w, kTraySyncMsg, 0, 0);
                }
            }

            auto show_notification(TrayNotification const& notif, TrayState) -> bool override {
                if (stopping_.load(std::memory_order_acquire) || !active_.load(std::memory_order_acquire)) return false;
                HWND w = hwnd_.load(std::memory_order_acquire);
                if (!w) return false;
                {
                    std::lock_guard lk(notif_mu_);
                    if (pending_notifs_.size() >= 8) pending_notifs_.pop_front();
                    pending_notifs_.push_back(notif);
                }
                return ::PostMessageW(w, kTrayNotifyMsg, 0, 0) != FALSE;
            }

            auto stop() noexcept -> void override {
                stopping_.store(true, std::memory_order_seq_cst);
                active_.store(false, std::memory_order_release);
                if (HWND w = hwnd_.load(std::memory_order_seq_cst)) {
                    ::PostMessageW(w, kTrayQuitMsg, 0, 0);
                }
                if (ui_thread_.joinable()) {
                    if (ui_thread_.get_id() == std::this_thread::get_id()) ui_thread_.detach();
                    else ui_thread_.join();
                }
            }
        };
    }

    auto create_win32_tray(NativeTrayHost host) -> std::unique_ptr<NativeTrayBackend> {
        auto backend = std::make_unique<win32_tray::Win32TrayBackend>(std::move(host));
        if (!backend->start()) return nullptr;
        return backend;
    }
#else
    auto create_win32_tray(NativeTrayHost) -> std::unique_ptr<NativeTrayBackend> {
        return nullptr;
    }
#endif
}
