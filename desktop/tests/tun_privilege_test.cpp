import std;
import desktop.tun_privilege;
import desktop.ui_prefs;

namespace {
    auto expect(bool cond, std::string_view msg) -> void {
        if (!cond) throw std::runtime_error(std::string(msg));
    }

    auto has_shell_metachar(std::string_view s) noexcept -> bool {
        return s.find_first_of(";&|`$<>\"'") != std::string_view::npos;
    }

    auto test_parse_linux_cap_eff() -> void {
        expect(!desktop::parse_linux_cap_eff_has_net_admin(""), "empty status has no CAP_NET_ADMIN");
        expect(!desktop::parse_linux_cap_eff_has_net_admin("Name:\tnexus\nCapEff:\t0000000000000000\n"),
            "zero CapEff has no CAP_NET_ADMIN");
        expect(desktop::parse_linux_cap_eff_has_net_admin("CapPrm:\t0000000000001000\nCapEff:\t0000000000001000\n"),
            "bit 12 (0x1000) sets CAP_NET_ADMIN");
        expect(desktop::parse_linux_cap_eff_has_net_admin("CapEff:\t000001ffffffffff\n"),
            "full root bitmask includes CAP_NET_ADMIN");
        expect(!desktop::parse_linux_cap_eff_has_net_admin("CapEff:\t0000000000000400\n"),
            "bit 10 (CAP_NET_BIND_SERVICE only) does not match CAP_NET_ADMIN");
        expect(!desktop::parse_linux_cap_eff_has_net_admin("CapEff:\t0000000000001000zzz\n"),
            "malformed trailing chars rejected");
        expect(!desktop::parse_linux_cap_eff_has_net_admin("CapEff:\tnot_hex\n"),
            "non-hex CapEff rejected");
    }

    auto test_parse_getcap() -> void {
        expect(desktop::parse_getcap_has_net_admin("/usr/bin/nexus cap_net_bind_service,cap_net_admin=ep\n"),
            "modern getcap =ep format detected");
        expect(desktop::parse_getcap_has_net_admin("/usr/bin/nexus = cap_net_admin,cap_net_bind_service+ep\n"),
            "legacy getcap +ep format detected");
        expect(desktop::parse_getcap_has_net_admin("/usr/bin/nexus cap_net_admin=eip"),
            "eip flags include e and p");
        expect(!desktop::parse_getcap_has_net_admin("/usr/bin/nexus cap_net_admin=p\n"),
            "permitted-only without effective bit rejected");
        expect(!desktop::parse_getcap_has_net_admin("/usr/bin/nexus cap_net_bind_service=ep\n"),
            "unrelated capability rejected");
        expect(desktop::parse_getcap_has_net_admin("/usr/bin/nexus CAP_NET_ADMIN=EP\n"),
            "uppercase getcap output matched zero-alloc");
        expect(!desktop::parse_getcap_has_net_admin(""), "empty getcap output rejected");
    }

    auto test_match_linux_cmdline() -> void {
        using namespace std::string_view_literals;
        auto const exact = "/usr/bin/nexus\0-D\0/home/alice/.config/nexus\0run\0--config\0/home/alice/.config/nexus/config.kdl\0"sv;
        expect(desktop::match_linux_cmdline_for_core(exact, "/usr/bin/nexus", "/home/alice/.config/nexus/config.kdl"),
            "exact NUL-separated cmdline matches");
        auto const no_trailing_nul = "/usr/bin/nexus\0run\0--config\0/etc/nexus/config.kdl"sv;
        expect(desktop::match_linux_cmdline_for_core(no_trailing_nul, "/usr/bin/nexus", "/etc/nexus/config.kdl"),
            "cmdline without trailing NUL matches");
        expect(!desktop::match_linux_cmdline_for_core(exact, "/usr/bin/other", "/home/alice/.config/nexus/config.kdl"),
            "wrong binary rejected");
        expect(!desktop::match_linux_cmdline_for_core(exact, "/usr/bin/nexus", "/tmp/other.kdl"),
            "wrong config path rejected");
        auto const missing_val = "/usr/bin/nexus\0run\0--config\0"sv;
        expect(!desktop::match_linux_cmdline_for_core(missing_val, "/usr/bin/nexus", "/tmp/a.kdl"),
            "trailing --config with empty value rejected");
        auto const no_config_flag = "/usr/bin/nexus\0run\0/home/alice/.config/nexus/config.kdl\0"sv;
        expect(!desktop::match_linux_cmdline_for_core(no_config_flag, "/usr/bin/nexus", "/home/alice/.config/nexus/config.kdl"),
            "missing --config flag rejected");
        expect(!desktop::match_linux_cmdline_for_core("", "/usr/bin/nexus", "/etc/nexus/config.kdl"),
            "empty cmdline rejected");
    }

    auto test_argv_builders() -> void {
        auto grant = desktop::build_linux_setcap_grant_argv("/usr/bin/nexus", "/usr/bin/pkexec", "/usr/sbin/setcap");
        expect(grant.size() == 4, "grant argv has 4 elements");
        expect(grant[0] == "/usr/bin/pkexec" && grant[1] == "/usr/sbin/setcap" &&
               grant[2] == "cap_net_admin,cap_net_bind_service=+ep" && grant[3].ends_with("nexus"),
            "grant argv matches exact pkexec setcap command");
        for (auto const& a : grant) expect(!has_shell_metachar(a), "grant argv contains zero shell metacharacters");

        auto revoke = desktop::build_linux_setcap_revoke_argv("/usr/bin/nexus", "/usr/bin/pkexec", "/usr/sbin/setcap");
        expect(revoke.size() == 4 && revoke[0] == "/usr/bin/pkexec" && revoke[1] == "/usr/sbin/setcap" &&
               revoke[2] == "-r" && revoke[3].ends_with("nexus"),
            "revoke argv matches exact pkexec setcap -r command");
        for (auto const& a : revoke) expect(!has_shell_metachar(a), "revoke argv contains zero shell metacharacters");

        auto sess = desktop::build_linux_session_elevated_argv(
            "/usr/bin/nexus", "/home/alice/.config/nexus/config.kdl", "/home/alice/.config/nexus",
            1000u, 1000u, "/usr/bin/pkexec", "/usr/bin/setpriv");
        expect(sess.size() == 14, "session elevated argv has 14 elements with workdir");
        expect(sess[0] == "/usr/bin/pkexec" && sess[1] == "/usr/bin/setpriv", "pkexec + setpriv prefix");
        expect(sess[2] == "--reuid=1000" && sess[3] == "--regid=1000" && sess[4] == "--init-groups",
            "uid/gid drop flags exact");
        expect(sess[5] == "--inh-caps=+net_admin,+net_bind_service" &&
               sess[6] == "--ambient-caps=+net_admin,+net_bind_service" && sess[7] == "--",
            "minimal ambient/inheritable caps flags exact");
        expect(sess[8].ends_with("nexus") && sess[9] == "-D" && sess[10] == "/home/alice/.config/nexus" &&
               sess[11] == "run" && sess[12] == "--config" && sess[13] == "/home/alice/.config/nexus/config.kdl",
            "core binary and config args exact");
        for (auto const& a : sess) expect(!has_shell_metachar(a), "session argv contains zero shell metacharacters");
    }

    auto test_ui_prefs_tun_persistent_roundtrip() -> void {
        desktop::UiPrefs def{};
        expect(def.tun_elevate_persistent, "tun_elevate_persistent defaults to true");

        auto tmp = std::filesystem::temp_directory_path() / "nexus-desktop-tun-prefs-test.conf";
        std::error_code ec;
        std::filesystem::remove(tmp, ec);

        desktop::UiPrefs custom{};
        custom.tun_elevate_persistent = false;
        expect(desktop::save_ui_prefs(tmp, custom), "save tun_elevate_persistent=false");
        auto loaded_false = desktop::load_ui_prefs(tmp);
        expect(!loaded_false.tun_elevate_persistent, "roundtrip tun_elevate_persistent=false");

        custom.tun_elevate_persistent = true;
        expect(desktop::save_ui_prefs(tmp, custom), "save tun_elevate_persistent=true");
        auto loaded_true = desktop::load_ui_prefs(tmp);
        expect(loaded_true.tun_elevate_persistent, "roundtrip tun_elevate_persistent=true");
        std::filesystem::remove(tmp, ec);
    }

    auto test_probe_host_binary(char const* argv0) -> void {
        auto probe = desktop::probe_tun_privilege(argv0 ? std::filesystem::path(argv0) : std::filesystem::path{});
        bool valid_status =
            probe.status == desktop::TunPrivilegeStatus::ready_root_or_admin ||
            probe.status == desktop::TunPrivilegeStatus::ready_persistent_cap ||
            probe.status == desktop::TunPrivilegeStatus::needs_elevation ||
            probe.status == desktop::TunPrivilegeStatus::unavailable;
        expect(valid_status, "probe_tun_privilege returns valid enum status");
        expect(!probe.detail.empty(), "probe_tun_privilege populates diagnostic detail");
        if (probe.status == desktop::TunPrivilegeStatus::ready_persistent_cap) {
            expect(probe.has_persistent_grant, "ready_persistent_cap implies has_persistent_grant");
        }
    }
}

auto main(int argc, char** argv) -> int {
    try {
        test_parse_linux_cap_eff();
        test_parse_getcap();
        test_match_linux_cmdline();
        test_argv_builders();
        test_ui_prefs_tun_persistent_roundtrip();
        test_probe_host_binary(argc > 0 ? argv[0] : nullptr);
        std::println("nexus-desktop-tun-privilege-tests: ALL PASSED");
        return 0;
    } catch (std::exception const& e) {
        std::println(std::cerr, "FAIL: {}", e.what());
        return 1;
    }
}
