module;
#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

module packet.tun_windows;
import std;

namespace packet {
#if defined(_WIN32)
    namespace {
        using AdapterHandle = void*;
        using SessionHandle = void*;
        using CreateAdapterFn = AdapterHandle (WINAPI*)(LPCWSTR, LPCWSTR, GUID const*);
        using CloseAdapterFn = void (WINAPI*)(AdapterHandle);
        using StartSessionFn = SessionHandle (WINAPI*)(AdapterHandle, DWORD);
        using EndSessionFn = void (WINAPI*)(SessionHandle);
        using ReceivePacketFn = BYTE* (WINAPI*)(SessionHandle, DWORD*);
        using ReleaseReceivePacketFn = void (WINAPI*)(SessionHandle, BYTE const*);
        using AllocateSendPacketFn = BYTE* (WINAPI*)(SessionHandle, DWORD);
        using SendPacketFn = void (WINAPI*)(SessionHandle, BYTE const*);

        auto to_wide(std::string_view text) -> std::wstring {
            if (text.empty()) return {};
            int len = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
            if (len <= 0) return {};
            std::wstring out(static_cast<std::size_t>(len), L'\0');
            ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), len);
            return out;
        }
    }

    struct WindowsTun::Impl {
        HMODULE dll = nullptr;
        AdapterHandle adapter = nullptr;
        SessionHandle session = nullptr;
        CloseAdapterFn close_adapter = nullptr;
        EndSessionFn end_session = nullptr;
        ReceivePacketFn receive_packet = nullptr;
        ReleaseReceivePacketFn release_packet = nullptr;
        AllocateSendPacketFn alloc_send = nullptr;
        SendPacketFn send_packet = nullptr;
        std::string name;

        ~Impl() { shutdown(); }
        auto shutdown() noexcept -> void {
            if (session && end_session) { end_session(session); session = nullptr; }
            if (adapter && close_adapter) { close_adapter(adapter); adapter = nullptr; }
            if (dll) { ::FreeLibrary(dll); dll = nullptr; }
        }
    };

    WindowsTun::WindowsTun(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
    WindowsTun::~WindowsTun() = default;
    WindowsTun::WindowsTun(WindowsTun&&) noexcept = default;
    auto WindowsTun::operator=(WindowsTun&&) noexcept -> WindowsTun& = default;

    auto WindowsTun::open(WintunConfig const& cfg) -> std::expected<WindowsTun, WintunFailure> {
        if (cfg.name.empty() || cfg.name.size() > 127 || cfg.ring_capacity < 0x20000 || cfg.ring_capacity > 0x4000000)
            return std::unexpected(WintunFailure{WintunError::invalid_name});
        HMODULE dll = ::LoadLibraryExW(L"wintun.dll", nullptr, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!dll) dll = ::LoadLibraryW(L"wintun.dll");
        if (!dll) return std::unexpected(WintunFailure{WintunError::dll_missing});

        auto impl = std::make_unique<Impl>();
        impl->dll = dll;
        impl->name = cfg.name;
        auto create_adapter = reinterpret_cast<CreateAdapterFn>(::GetProcAddress(dll, "WintunCreateAdapter"));
        impl->close_adapter = reinterpret_cast<CloseAdapterFn>(::GetProcAddress(dll, "WintunCloseAdapter"));
        auto start_session = reinterpret_cast<StartSessionFn>(::GetProcAddress(dll, "WintunStartSession"));
        impl->end_session = reinterpret_cast<EndSessionFn>(::GetProcAddress(dll, "WintunEndSession"));
        impl->receive_packet = reinterpret_cast<ReceivePacketFn>(::GetProcAddress(dll, "WintunReceivePacket"));
        impl->release_packet = reinterpret_cast<ReleaseReceivePacketFn>(::GetProcAddress(dll, "WintunReleaseReceivePacket"));
        impl->alloc_send = reinterpret_cast<AllocateSendPacketFn>(::GetProcAddress(dll, "WintunAllocateSendPacket"));
        impl->send_packet = reinterpret_cast<SendPacketFn>(::GetProcAddress(dll, "WintunSendPacket"));
        if (!create_adapter || !impl->close_adapter || !start_session || !impl->end_session ||
            !impl->receive_packet || !impl->release_packet || !impl->alloc_send || !impl->send_packet) {
            return std::unexpected(WintunFailure{WintunError::symbol_missing});
        }
        auto wname = to_wide(cfg.name);
        auto wtype = to_wide(cfg.tunnel_type.empty() ? cfg.name : cfg.tunnel_type);
        impl->adapter = create_adapter(wname.c_str(), wtype.c_str(), nullptr);
        if (!impl->adapter)
            return std::unexpected(WintunFailure{std::error_code{static_cast<int>(::GetLastError()), std::system_category()}});
        impl->session = start_session(impl->adapter, cfg.ring_capacity);
        if (!impl->session)
            return std::unexpected(WintunFailure{std::error_code{static_cast<int>(::GetLastError()), std::system_category()}});
        return WindowsTun(std::move(impl));
    }

    auto WindowsTun::adapter_name() const noexcept -> std::string_view {
        return impl_ ? std::string_view(impl_->name) : std::string_view{};
    }

    auto WindowsTun::read_packet(std::span<std::uint8_t> out)
        -> std::expected<std::optional<std::size_t>, WintunFailure> {
        if (!impl_ || !impl_->session) return std::unexpected(WintunFailure{WintunError::invalid_state});
        DWORD sz = 0;
        BYTE* pkt = impl_->receive_packet(impl_->session, &sz);
        if (!pkt) {
            DWORD err = ::GetLastError();
            if (err == ERROR_NO_MORE_ITEMS) return std::optional<std::size_t>{};
            return std::unexpected(WintunFailure{std::error_code{static_cast<int>(err), std::system_category()}});
        }
        std::optional<std::size_t> copied;
        if (sz <= out.size()) {
            std::copy_n(reinterpret_cast<std::uint8_t const*>(pkt), sz, out.begin());
            copied = sz;
        }
        impl_->release_packet(impl_->session, pkt);
        if (!copied) return std::unexpected(WintunFailure{std::make_error_code(std::errc::message_size)});
        return copied;
    }

    auto WindowsTun::write_packet(std::span<std::uint8_t const> ip_packet) -> std::expected<void, WintunFailure> {
        if (!impl_ || !impl_->session) return std::unexpected(WintunFailure{WintunError::invalid_state});
        if (ip_packet.empty() || ip_packet.size() > 65535)
            return std::unexpected(WintunFailure{WintunError::invalid_state});
        BYTE* dst = impl_->alloc_send(impl_->session, static_cast<DWORD>(ip_packet.size()));
        if (!dst) {
            return std::unexpected(WintunFailure{std::error_code{static_cast<int>(::GetLastError()), std::system_category()}});
        }
        std::copy_n(ip_packet.data(), ip_packet.size(), reinterpret_cast<std::uint8_t*>(dst));
        impl_->send_packet(impl_->session, dst);
        return {};
    }

    auto WindowsTun::close() noexcept -> void { if (impl_) impl_->shutdown(); }
#else
    struct WindowsTun::Impl {};
    WindowsTun::WindowsTun(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
    WindowsTun::~WindowsTun() = default;
    WindowsTun::WindowsTun(WindowsTun&&) noexcept = default;
    auto WindowsTun::operator=(WindowsTun&&) noexcept -> WindowsTun& = default;
    auto WindowsTun::open(WintunConfig const&) -> std::expected<WindowsTun, WintunFailure> {
        return std::unexpected(WintunFailure{WintunError::unsupported});
    }
    auto WindowsTun::adapter_name() const noexcept -> std::string_view { return {}; }
    auto WindowsTun::read_packet(std::span<std::uint8_t>)
        -> std::expected<std::optional<std::size_t>, WintunFailure> {
        return std::unexpected(WintunFailure{WintunError::unsupported});
    }
    auto WindowsTun::write_packet(std::span<std::uint8_t const>) -> std::expected<void, WintunFailure> {
        return std::unexpected(WintunFailure{WintunError::unsupported});
    }
    auto WindowsTun::close() noexcept -> void {}
#endif
}
