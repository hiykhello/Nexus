export module desktop.firewall_helper;

import std;

export namespace desktop {
    struct FirewallResult {
        bool ok = false;
        bool skipped = false;
        std::string message;
    };

    // Strips Windows extended-length path prefix (`\\?\` or `\\?\UNC\`) so firewall APIs
    // and netsh never reject canonicalized paths.
    [[nodiscard]] auto normalize_firewall_executable_path(std::string_view raw) -> std::string;

    // Ensures an idempotent inbound loopback allow rule for the Nexus binary on Windows.
    // Honors diagnostic_mode (never mutates host firewall) and safely no-ops on non-Windows hosts.
    [[nodiscard]] auto ensure_loopback_firewall_rule(std::string_view executable_path,
                                                     std::string_view rule_name = "Nexus Core Loopback",
                                                     bool diagnostic_mode = false) -> FirewallResult;
}
