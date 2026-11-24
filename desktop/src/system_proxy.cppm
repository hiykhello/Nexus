export module desktop.system_proxy;

import std;

export namespace desktop {
    struct SystemProxySnapshot {
        bool enabled = false;
        std::string mode;
        std::string server;
        std::string http_host;
        std::string http_port;
        std::string https_host;
        std::string https_port;
        std::string bypass_list;
        std::string pac_url;
    };

    // Snapshots and restores host desktop system proxy settings safely.
    // Explicitly exposes supported() so headless Linux desktops never treat
    // missing gsettings as a core startup failure, and honors diagnostic_mode()
    // so diagnostic runs never mutate host settings.
    class SystemProxyController {
        std::optional<SystemProxySnapshot> saved_;
        bool active_ = false;
        bool diagnostic_mode_ = false;
        std::string service_name_;
        std::string kde_read_, kde_write_;
    public:
        ~SystemProxyController() { (void)restore(); }

        [[nodiscard]] static auto supported() noexcept -> bool;
        [[nodiscard]] auto active(this SystemProxyController const& self) noexcept -> bool {
            return self.active_;
        }
        auto set_diagnostic_mode(this SystemProxyController& self, bool on) noexcept -> void {
            self.diagnostic_mode_ = on;
        }
        [[nodiscard]] auto diagnostic_mode(this SystemProxyController const& self) noexcept -> bool {
            return self.diagnostic_mode_;
        }

        [[nodiscard]] auto enable(this SystemProxyController& self, std::string const& host, std::uint16_t port)
            -> bool;
        [[nodiscard]] auto restore(this SystemProxyController& self) -> bool;
    };
}
