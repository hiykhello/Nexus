import std;
import desktop.tun_helper_protocol;
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

    auto test_sha256_and_file() -> void {
        expect(desktop::sha256_bytes("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "SHA-256 empty string NIST vector");
        expect(desktop::sha256_bytes("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "SHA-256 'abc' NIST vector");
        expect(desktop::sha256_bytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
               "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            "SHA-256 448-bit multi-block NIST vector");
        expect(desktop::is_valid_sha256_hex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
            "valid 64-hex digest accepted");
        expect(!desktop::is_valid_sha256_hex("248d6a61"), "short digest rejected");
        expect(!desktop::is_valid_sha256_hex("z48d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
            "non-hex digest rejected");

        auto tmp = std::filesystem::temp_directory_path() / "nexus-desktop-sha256-test.bin";
        {
            std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
            out.write("abc", 3);
        }
        auto file_digest = desktop::sha256_file(tmp);
        std::error_code ec;
        std::filesystem::remove(tmp, ec);
        expect(file_digest.has_value() && *file_digest == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "sha256_file matches NIST vector");
        expect(!desktop::sha256_file(tmp).has_value(), "sha256_file fails on missing file");
    }

    auto test_helper_protocol_and_security_builders() -> void {
        expect(desktop::parse_tun_helper_request("PING") == desktop::TunHelperCommand::ping, "PING parsed");
        expect(desktop::parse_tun_helper_request("STATUS") == desktop::TunHelperCommand::status, "STATUS parsed");
        expect(desktop::parse_tun_helper_request("START") == desktop::TunHelperCommand::start, "START parsed");
        expect(desktop::parse_tun_helper_request("STOP") == desktop::TunHelperCommand::stop, "STOP parsed");
        expect(!desktop::parse_tun_helper_request("PING\n").has_value(), "newline rejected in request");
        expect(!desktop::parse_tun_helper_request("ping").has_value(), "lowercase rejected");
        expect(!desktop::parse_tun_helper_request("START;id").has_value(), "command injection rejected");
        expect(!desktop::parse_tun_helper_request(std::string(300, 'A')).has_value(), "oversized request rejected");

        auto r_run = desktop::parse_tun_helper_reply(desktop::format_tun_helper_reply({true, true, 4242, "RUNNING"}));
        expect(r_run.ok && r_run.running && r_run.pid == 4242, "RUNNING reply roundtrip");
        auto r_stop = desktop::parse_tun_helper_reply(desktop::format_tun_helper_reply({true, false, 0, ""}));
        expect(r_stop.ok && !r_stop.running, "STOPPED reply roundtrip");
        auto r_err = desktop::parse_tun_helper_reply(desktop::format_tun_helper_reply({false, false, 0, "digest mismatch"}));
        expect(!r_err.ok && r_err.detail == "digest mismatch", "ERR reply roundtrip");
        expect(!desktop::parse_tun_helper_reply(std::string(1100, 'X')).ok, "oversized reply rejected");

        expect(desktop::validate_windows_sid("S-1-5-21-3623811015-3361044348-30300820-1013"), "valid user SID accepted");
        expect(desktop::validate_windows_sid("S-1-5-18"), "valid SYSTEM SID accepted");
        expect(!desktop::validate_windows_sid("S-1-5-21-1-2)(A;;GA;;;WD"), "SDDL injection SID rejected");
        expect(!desktop::validate_windows_sid("S-1-5-"), "trailing dash SID rejected");
        expect(!desktop::validate_windows_sid(""), "empty SID rejected");
        auto sddl = desktop::build_win_helper_pipe_sddl("S-1-5-21-100-200-300-1001");
        expect(sddl.has_value() && *sddl == "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;S-1-5-21-100-200-300-1001)",
            "exact Windows Named Pipe SDDL built");
        expect(!desktop::build_win_helper_pipe_sddl("bad;sid").has_value(), "invalid SID fails SDDL builder");

        auto plist = desktop::render_macos_tun_helper_plist("/Applications/Nexus & Co <1>.app/Contents/MacOS/nexus-tun-helper");
        expect(plist.has_value(), "macOS LaunchDaemon plist rendered");
        expect(plist->contains("<string>io.nexus.tun-helper</string>"), "plist contains default label");
        expect(plist->contains("Nexus &amp; Co &lt;1&gt;.app/Contents/MacOS/nexus-tun-helper"), "plist XML-escapes binary path");
        expect(plist->contains("<string>--daemon</string>") && plist->contains("<key>RunAtLoad</key>"),
            "plist contains daemon arg and RunAtLoad");
        expect(!desktop::render_macos_tun_helper_plist("relative/path").has_value(), "relative helper binary rejected");
        expect(!desktop::render_macos_tun_helper_plist("/bin/ok\n/bad").has_value(), "newline in helper path rejected");

        auto q = desktop::quote_posix_sh_arg("a'b $(id) `uname`; rm -rf /");
        expect(q.has_value() && *q == "'a'\\''b $(id) `uname`; rm -rf /'", "POSIX sh single-quoting neutralizes metachars");
        auto esc = desktop::escape_applescript_string("path \"quoted\" \\ end");
        expect(esc.has_value() && *esc == "path \\\"quoted\\\" \\\\ end", "AppleScript string escaping exact");
        expect(!desktop::escape_applescript_string("bad\nline").has_value(), "AppleScript newline rejected");
        std::array<std::string_view, 3> mac_argv{"/usr/local/bin/nexus-tun-helper", "--install", "--config=/tmp/a'b \"c\""};
        auto osa = desktop::build_macos_osascript_admin_script(mac_argv);
        expect(osa.has_value() && osa->starts_with("do shell script \"") && osa->ends_with("\" with administrator privileges"),
            "osascript admin command built cleanly");

        desktop::TunHelperPinnedConfig cfg{
            "/usr/local/bin/nexus",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "/Users/alice/.config/nexus/config.kdl",
            "/Users/alice/.config/nexus",
            "501",
            "/Library/Application Support/Nexus/bin/nexus",
        };
        auto ser = desktop::serialize_tun_helper_config(cfg);
        expect(ser.has_value(), "pinned config serialized");
        auto parsed = desktop::parse_tun_helper_config(*ser);
        expect(parsed.has_value() && parsed->binary == cfg.binary && parsed->sha256 == cfg.sha256 &&
               parsed->config == cfg.config && parsed->workdir == cfg.workdir && parsed->owner == cfg.owner &&
               parsed->staged_binary == cfg.staged_binary,
            "pinned config roundtrip exact including staged_binary");
        expect(desktop::kWinTunHelperStageDirSddl == "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)",
            "Windows staging directory SDDL restricts access to SYSTEM and Administrators");
        expect(!desktop::parse_tun_helper_config("binary=/a\nsha256=bad\nconfig=/c\nowner=501\n").has_value(),
            "bad sha256 rejected in config parse");
        expect(!desktop::parse_tun_helper_config(*ser + "extra=1\n").has_value(), "unknown key rejected");
        expect(!desktop::parse_tun_helper_config(*ser + "owner=0\n").has_value(), "duplicate owner key rejected");
        expect(!desktop::parse_tun_helper_config(*ser + "staged_binary=/tmp/x\n").has_value(), "duplicate staged_binary rejected");
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
        test_sha256_and_file();
        test_helper_protocol_and_security_builders();
        std::println("nexus-desktop-tun-privilege-tests: ALL PASSED");
        return 0;
    } catch (std::exception const& e) {
        std::println(std::cerr, "FAIL: {}", e.what());
        return 1;
    }
}
