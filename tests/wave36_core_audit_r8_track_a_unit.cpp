#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
import std;
import capy;
import corosio;
import crypto;
import http2.client_types;
import logging.sink;
import ssh.session;
import xhttp.client;
#include "support/ssh_rekey_mock.hpp"

namespace {
    using namespace ssh_rekey_test;
    int failures = 0;

    auto expect(bool cond, std::string_view msg) -> void {
        if (!cond) {
            std::cerr << "FAIL: " << msg << '\n';
            ++failures;
        }
    }

    auto spawn(corosio::io_context& io, capy::task<> t) -> void {
        capy::run_async(io.get_executor(), []() noexcept {}, [](std::exception_ptr) noexcept {})(std::move(t));
    }

    // R8 P1-2A: Peer-initiated rekey switching cipher (ChaCha20 -> AES-256-GCM) with active channel
    auto test_ssh_peer_initiated_rekey() -> void {
        corosio::io_context io;
        Pipe c2s, s2c;
        MemStream c_stream(s2c, c2s), s_stream(c2s, s2c);
        auto host_key = make_ed25519_key(1);
        ssh::Session<MemStream> session(c_stream);
        MockSshServer server{s_stream};
        auto dl = Clock::now() + std::chrono::seconds(5);
        bool client_ok = false, server_ok = false;

        spawn(io, [&]() -> capy::task<> {
            auto cid = co_await server.handshake_and_open(host_key, dl);
            if (!cid) co_return;
            auto p1 = co_await server.recv_pkt(dl);
            if (!p1 || (*p1)[0] != ssh::kMsgChannelData) co_return;
            if (!co_await server.send_ch_data(*cid, "PONG1", dl)) co_return;
            if (!co_await server.do_kex(false, std::nullopt, std::nullopt, "aes256-gcm@openssh.com", host_key, dl, true)) co_return;
            if (server.inflight_before_kex != "AFTER-REKEY") {
                auto p2 = co_await server.recv_pkt(dl);
                if (!p2 || (*p2)[0] != ssh::kMsgChannelData) co_return;
                ssh::Reader r{std::span(*p2).subspan(1)}; (void)r.u32();
                auto d2 = r.text();
                if (!d2 || *d2 != "AFTER-REKEY") co_return;
            }
            if (!co_await server.send_ch_data(*cid, "PONG2", dl)) co_return;
            // Verify one more roundtrip guaranteed AFTER rekey completes on both sides
            auto p3 = co_await server.recv_pkt(dl);
            if (!p3 || (*p3)[0] != ssh::kMsgChannelData) co_return;
            ssh::Reader r3{std::span(*p3).subspan(1)}; (void)r3.u32();
            auto d3 = r3.text();
            if (!d3 || *d3 != "POST-NEWKEYS") co_return;
            if (!co_await server.send_ch_data(*cid, "PONG3", dl)) co_return;
            server_ok = true;
        }());
        spawn(io, [&]() -> capy::task<> {
            if (!co_await session.start_client(make_auth(host_key), dl)) { session.cancel(); co_return; }
            spawn(io, [&]() -> capy::task<> { (void)co_await session.run(); }());
            auto id = co_await session.open_direct_tcpip("127.0.0.1", 80, dl);
            if (!id) { session.cancel(); co_return; }
            {
                ssh::Channel<MemStream> ch(session, *id);
                if (!co_await send_str(ch, "PING1")) { session.cancel(); co_return; }
                if (co_await read_str(ch, 5) != "PONG1") { session.cancel(); co_return; }
                if (!co_await send_str(ch, "AFTER-REKEY")) { session.cancel(); co_return; }
                if (co_await read_str(ch, 5) != "PONG2") { session.cancel(); co_return; }
                if (!co_await send_str(ch, "POST-NEWKEYS")) { session.cancel(); co_return; }
                if (co_await read_str(ch, 5) != "PONG3") { session.cancel(); co_return; }
                client_ok = session.usable() && session.rekey_count() == 1;
            }
            session.cancel();
        }());
        io.run();
        expect(client_ok && server_ok && server.rekeys_done == 1 && !server.saw_proto_violation,
            "R8 P1-2A: peer-initiated SSH rekey preserves active forwarded channel across cipher change");
    }

    // R8 P1-2B: Local TX byte-threshold rekey (simulating 1 GiB) + in-flight server data before KEXINIT
    auto test_ssh_local_tx_threshold_rekey() -> void {
        corosio::io_context io;
        Pipe c2s, s2c;
        MemStream c_stream(s2c, c2s), s_stream(c2s, s2c);
        auto host_key = make_ed25519_key(1);
        ssh::Session<MemStream> session(c_stream);
        MockSshServer server{s_stream};
        auto dl = Clock::now() + std::chrono::seconds(5);
        std::string server_got, client_got;
        bool ok = false;

        spawn(io, [&]() -> capy::task<> {
            auto cid = co_await server.handshake_and_open(host_key, dl);
            if (!cid) co_return;
            while (server_got.size() < 900) {
                auto p = co_await server.recv_pkt(dl);
                if (!p || p->empty()) co_return;
                if ((*p)[0] == ssh::kMsgKexInit) {
                    if (!co_await server.send_ch_data(*cid, "INFLIGHT", dl)) co_return;
                    if (!co_await server.do_kex(false, std::move(*p), std::nullopt, "chacha20-poly1305@openssh.com", host_key, dl)) co_return;
                } else if ((*p)[0] == ssh::kMsgChannelData) {
                    ssh::Reader r{std::span(*p).subspan(1)}; (void)r.u32();
                    if (auto d = r.text()) {
                        server_got.append(*d);
                        if (!co_await server.send_ch_data(*cid, *d, dl)) co_return;
                    }
                }
            }
        }());
        spawn(io, [&]() -> capy::task<> {
            if (!co_await session.start_client(make_auth(host_key), dl)) { session.cancel(); co_return; }
            session.set_rekey_limits(256);
            spawn(io, [&]() -> capy::task<> { (void)co_await session.run(); }());
            auto id = co_await session.open_direct_tcpip("example.com", 443, dl);
            if (!id) { session.cancel(); co_return; }
            {
                ssh::Channel<MemStream> ch(session, *id);
                std::string chunk(150, 'X');
                for (int i = 0; i < 6; ++i) {
                    chunk[0] = static_cast<char>('A' + i);
                    if (!co_await send_str(ch, chunk)) { session.cancel(); co_return; }
                }
                std::array<std::uint8_t, 256> rbuf{};
                while (true) {
                    auto r = co_await ch.read(rbuf);
                    if (!r || *r == 0) break;
                    client_got.append(reinterpret_cast<char const*>(rbuf.data()), *r);
                    std::size_t expected = 900 + static_cast<std::size_t>(server.rekeys_done) * 8;
                    if (client_got.size() >= expected && server.rekeys_done >= 2) break;
                }
                ok = session.usable() && session.rekey_count() >= 2 && server_got.size() == 900 &&
                     client_got.contains("INFLIGHT");
            }
            session.cancel();
        }());
        io.run();
        expect(ok && !server.saw_proto_violation,
            "R8 P1-2B: local TX byte-threshold triggers multiple in-place rekeys without dropping channel");
    }

    // R8 P1-2C/D/E: Simultaneous rekey + GLOBAL_REQUEST deferral, RX-only threshold, high seqno & pin check
    auto test_ssh_simultaneous_rx_and_security() -> void {
        // 1) Simultaneous rekey + deferred GLOBAL_REQUEST failure
        {
            corosio::io_context io;
            Pipe c2s, s2c;
            MemStream c_stream(s2c, c2s), s_stream(c2s, s2c);
            auto host_key = make_ed25519_key(1);
            ssh::Session<MemStream> session(c_stream);
            MockSshServer server{s_stream};
            auto dl = Clock::now() + std::chrono::seconds(5);
            bool ok = false;

            spawn(io, [&]() -> capy::task<> {
                auto cid = co_await server.handshake_and_open(host_key, dl);
                if (!cid) co_return;
                auto p1 = co_await server.recv_pkt(dl);
                if (!p1 || (*p1)[0] != ssh::kMsgChannelData) co_return;
                ssh::Writer gr; gr.byte(ssh::kMsgGlobalRequest).string("keepalive@openssh.com").boolean(true);
                if (!co_await server.send_pkt(gr.buf, dl)) co_return;
                auto is_pkt = server.make_kexinit("aes128-gcm@openssh.com", false);
                if (!co_await server.send_pkt(is_pkt, dl)) co_return;
                auto ic_pkt = co_await server.recv_pkt(dl);
                if (!ic_pkt || (*ic_pkt)[0] != ssh::kMsgKexInit) co_return;
                if (!co_await server.do_kex(false, std::move(*ic_pkt), std::move(is_pkt), "aes128-gcm@openssh.com", host_key, dl)) co_return;
                bool got_data2 = false;
                while (!got_data2 || server.request_failures_seen == 0) {
                    auto p = co_await server.recv_pkt(dl);
                    if (!p || p->empty()) co_return;
                    if ((*p)[0] == ssh::kMsgRequestFailure) ++server.request_failures_seen;
                    else if ((*p)[0] == ssh::kMsgChannelData) {
                        got_data2 = true;
                        if (!co_await server.send_ch_data(*cid, "SIMUL-OK", dl)) co_return;
                    }
                }
            }());
            spawn(io, [&]() -> capy::task<> {
                if (!co_await session.start_client(make_auth(host_key), dl)) { session.cancel(); co_return; }
                session.set_rekey_limits(350);
                spawn(io, [&]() -> capy::task<> { (void)co_await session.run(); }());
                auto id = co_await session.open_direct_tcpip("127.0.0.1", 8080, dl);
                if (!id) { session.cancel(); co_return; }
                {
                    ssh::Channel<MemStream> ch(session, *id);
                    if (!co_await send_str(ch, std::string(180, 'S'))) { session.cancel(); co_return; }
                    if (!co_await send_str(ch, std::string(180, 'T'))) { session.cancel(); co_return; }
                    ok = (co_await read_str(ch, 8) == "SIMUL-OK") && session.usable() && session.rekey_count() == 1;
                }
                session.cancel();
            }());
            io.run();
            expect(ok && server.rekeys_done == 1 && server.request_failures_seen == 1 && !server.saw_proto_violation,
                "R8 P1-2C: simultaneous rekey + deferred GLOBAL_REQUEST failure without deadlock");
        }

        // 2) Local RX byte-threshold rekey (download-only)
        {
            corosio::io_context io;
            Pipe c2s, s2c;
            MemStream c_stream(s2c, c2s), s_stream(c2s, s2c);
            auto host_key = make_ed25519_key(1);
            ssh::Session<MemStream> session(c_stream);
            MockSshServer server{s_stream};
            auto dl = Clock::now() + std::chrono::seconds(5);
            bool ok = false;

            spawn(io, [&]() -> capy::task<> {
                auto cid = co_await server.handshake_and_open(host_key, dl);
                if (!cid) co_return;
                if (!co_await server.send_ch_data(*cid, std::string(300, 'D'), dl)) co_return;
                auto ic = co_await server.recv_pkt(dl);
                if (!ic || (*ic)[0] != ssh::kMsgKexInit) co_return;
                if (!co_await server.do_kex(false, std::move(*ic), std::nullopt, "chacha20-poly1305@openssh.com", host_key, dl)) co_return;
                (void)co_await server.send_ch_data(*cid, "AFTER-RX", dl);
            }());
            spawn(io, [&]() -> capy::task<> {
                if (!co_await session.start_client(make_auth(host_key), dl)) { session.cancel(); co_return; }
                session.set_rekey_limits(200);
                spawn(io, [&]() -> capy::task<> { (void)co_await session.run(); }());
                auto id = co_await session.open_direct_tcpip("127.0.0.1", 8081, dl);
                if (!id) { session.cancel(); co_return; }
                {
                    ssh::Channel<MemStream> ch(session, *id);
                    auto got = co_await read_str(ch, 308);
                    ok = (got == std::string(300, 'D') + "AFTER-RX") && session.usable() && session.rekey_count() >= 1;
                }
                session.cancel();
            }());
            io.run();
            expect(ok && server.rekeys_done >= 1, "R8 P1-2D: RX-only byte threshold triggers in-place rekey cleanly");
        }

        // 3) PacketCipher high seqno (>= 2^30) works after rekey + wrong host-key pin on rekey rejected
        {
            ssh::PacketCipher enc, dec;
            std::array<std::uint8_t, 64> key{}; key.fill(0x5a);
            expect(enc.activate(ssh::CipherKind::chacha20_poly1305, key, {}) &&
                   dec.activate(ssh::CipherKind::chacha20_poly1305, key, {}), "R8 P1-2E: activate cipher");
            std::array<std::uint8_t, 5> msg{1, 2, 3, 4, 5};
            constexpr std::uint32_t kHighSeq = (1u << 30) + 42u;
            auto wire = enc.encrypt(kHighSeq, msg);
            expect(wire.has_value(), "R8 P1-2E: monotonic seqno >= 2^30 succeeds after rekey");
            if (wire) {
                auto hdr = std::span<std::uint8_t const, 4>(wire->data(), 4);
                auto len = dec.decrypt_length(kHighSeq, hdr);
                auto plain = len ? dec.decrypt_body(kHighSeq, hdr, std::span(*wire).subspan(4)) : std::unexpected(std::string("len"));
                expect(plain && std::ranges::equal(*plain, msg), "R8 P1-2E: decrypt high seqno roundtrip");
            }

            corosio::io_context io;
            Pipe c2s, s2c;
            MemStream c_stream(s2c, c2s), s_stream(c2s, s2c);
            auto good_key = make_ed25519_key(1), bad_key = make_ed25519_key(2);
            ssh::Session<MemStream> session(c_stream);
            MockSshServer server{s_stream};
            auto dl = Clock::now() + std::chrono::seconds(5);
            bool rejected = false;
            spawn(io, [&]() -> capy::task<> {
                auto cid = co_await server.handshake_and_open(good_key, dl);
                if (!cid) co_return;
                (void)co_await server.do_kex(false, std::nullopt, std::nullopt, "chacha20-poly1305@openssh.com", bad_key, dl);
            }());
            spawn(io, [&]() -> capy::task<> {
                if (!co_await session.start_client(make_auth(good_key), dl)) { session.cancel(); co_return; }
                spawn(io, [&]() -> capy::task<> { (void)co_await session.run(); }());
                auto id = co_await session.open_direct_tcpip("127.0.0.1", 8082, dl);
                if (!id) { session.cancel(); co_return; }
                ssh::Channel<MemStream> ch(session, *id);
                std::array<std::uint8_t, 8> buf{};
                auto r = co_await ch.read(buf);
                rejected = !r.has_value() && !session.usable() && session.rekey_count() == 0;
                session.cancel();
            }());
            io.run();
            expect(rejected, "R8 P1-2E: unpinned host key during rekey is rejected and closes session");
        }
    }

    // R8 P2-1: XHTTP stream-up colliding upload/download stream IDs & tickets
    auto test_xhttp_stream_up_ticket_release() -> void {
        {
            xhttp::StreamTickets<std::int64_t> tickets;
            tickets.bind_download(0);
            tickets.bind_upload(0);
            int down_rel = 0, up_rel = 0;
            std::int64_t down_id = -1, up_id = -1;
            tickets.release_all([&](std::int64_t id) noexcept { ++down_rel; down_id = id; },
                                [&](std::int64_t id) noexcept { ++up_rel; up_id = id; });
            expect(down_rel == 1 && up_rel == 1 && down_id == 0 && up_id == 0,
                "R8 P2-1A: stream-up releases BOTH colliding HTTP/3 stream ID 0 tickets");
            tickets.release_all([&](std::int64_t) noexcept { ++down_rel; }, [&](std::int64_t) noexcept { ++up_rel; });
            expect(down_rel == 1 && up_rel == 1, "R8 P2-1A: second release_all is a no-op");
        }
        {
            xhttp::StreamTickets<http2::StreamTicket> tickets;
            http2::StreamTicket const colliding{.slot = 0, .generation = 1};
            tickets.bind_download(colliding);
            tickets.bind_upload(colliding);
            int down_rel = 0, up_rel = 0;
            tickets.release_all([&](http2::StreamTicket) noexcept { ++down_rel; },
                                [&](http2::StreamTicket) noexcept { ++up_rel; });
            expect(down_rel == 1 && up_rel == 1, "R8 P2-1B: stream-up releases BOTH colliding HTTP/2 StreamTickets");
        }
        {
            xhttp::StreamTickets<std::int64_t> tickets;
            tickets.bind_shared(0);
            int down_rel = 0, up_rel = 0;
            tickets.release_all([&](std::int64_t) noexcept { ++down_rel; }, [&](std::int64_t) noexcept { ++up_rel; });
            expect(down_rel == 1 && up_rel == 0, "R8 P2-1C: stream-one shared stream releases exactly once");
        }
        {
            xhttp::StreamTickets<std::int64_t> tickets;
            tickets.bind_download(4);
            int down_rel = 0, up_rel = 0;
            tickets.release_all([&](std::int64_t) noexcept { ++down_rel; }, [&](std::int64_t) noexcept { ++up_rel; });
            expect(down_rel == 1 && up_rel == 0, "R8 P2-1D: packet-up releases download ticket only");
        }
    }

    // R8 P2-2: Windows log rotation error path (keep==2 move cur->.1 failure preserves log + reopens)
    struct FdHandle {
        int fd = -1;
        explicit operator bool() const noexcept { return fd >= 0; }
    };

    struct FsRotateOps {
        std::filesystem::path fail_src, fail_dst;
        int fail_err = EACCES;

        static auto ok() noexcept -> int { return 0; }
        static auto invalid_arg() noexcept -> int { return EINVAL; }
        static auto is_not_found(int e) noexcept -> bool { return e == ENOENT; }
        static auto open_append(std::filesystem::path const& path, bool exclusive,
            std::uint64_t& size_out, int& err_out) noexcept -> FdHandle {
            int flags = O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | (exclusive ? O_EXCL : 0);
            int fd = ::open(path.c_str(), flags, 0600);
            if (fd < 0) { err_out = errno; return {}; }
            struct stat st{};
            if (::fstat(fd, &st) < 0) { err_out = errno; ::close(fd); return {}; }
            size_out = static_cast<std::uint64_t>(st.st_size);
            err_out = 0;
            return FdHandle{fd};
        }
        static auto close(FdHandle h) noexcept -> void { if (h.fd >= 0) ::close(h.fd); }
        static auto remove(std::filesystem::path const& p) noexcept -> void { ::unlink(p.c_str()); }
        auto move_replace(std::filesystem::path const& src, std::filesystem::path const& dst, int& err_out) const noexcept -> bool {
            if (!fail_src.empty() && src == fail_src && dst == fail_dst) { err_out = fail_err; return false; }
            if (::rename(src.c_str(), dst.c_str()) == 0) { err_out = 0; return true; }
            err_out = errno;
            return false;
        }
    };

    auto read_all(std::filesystem::path const& p) -> std::string {
        std::ifstream in(p, std::ios::binary);
        return std::string(std::istreambuf_iterator<char>(in), {});
    }

    auto test_windows_log_rotation_safety() -> void {
        auto dir = std::filesystem::temp_directory_path() /
            ("nexus-r8-winlog-" + std::to_string(static_cast<unsigned long long>(::getpid())));
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
        std::filesystem::create_directories(dir);
        auto cur = dir / "app.log", bak1 = dir / "app.log.1", bak2 = dir / "app.log.2", tmp = dir / "app.log.rotate";
        auto write_fd = [](int fd, std::string_view s) { return ::write(fd, s.data(), s.size()) == static_cast<ssize_t>(s.size()); };

        // 1) keep == 2: moving cur -> .1 fails (locked .1); must NOT overwrite cur with empty temp!
        {
            { std::ofstream f(cur); f << "important-active-log-data\n"; }
            { std::ofstream f(bak1); f << "old-backup-1\n"; }
            std::uint64_t sz = 0; int oerr = 0;
            auto active = FsRotateOps::open_append(cur, false, sz, oerr);
            std::array<std::string, 2> names{"app.log", "app.log.1"};
            FsRotateOps ops{cur, bak1, EACCES};
            int rerr = logging::rotate_file_ops<FdHandle, int>(dir, names, "app.log.rotate", active, sz, ops);
            expect(rerr == EACCES && !std::filesystem::exists(tmp), "R8 P2-2A: returns error and deletes temp on cur -> .1 failure");
            expect(read_all(cur) == "important-active-log-data\n" && read_all(bak1) == "old-backup-1\n",
                "R8 P2-2A: preserves active log and .1 backup intact");
            expect(static_cast<bool>(active) && sz == 26 && write_fd(active.fd, "appended-after-fail\n"),
                "R8 P2-2A: reopens active log in append mode with original size");
            expect(read_all(cur) == "important-active-log-data\nappended-after-fail\n",
                "R8 P2-2A: zero bytes lost after failed rotation");
            FsRotateOps::close(active);
        }

        // 2) keep == 3: shifting .1 -> .2 fails; aborts before closing active handle
        {
            { std::ofstream f(bak2); f << "old-backup-2\n"; }
            std::uint64_t sz = 0; int oerr = 0;
            auto active = FsRotateOps::open_append(cur, false, sz, oerr);
            int const orig_fd = active.fd;
            std::array<std::string, 3> names{"app.log", "app.log.1", "app.log.2"};
            FsRotateOps ops{bak1, bak2, EACCES};
            int rerr = logging::rotate_file_ops<FdHandle, int>(dir, names, "app.log.rotate", active, sz, ops);
            expect(rerr == EACCES && active.fd == orig_fd && !std::filesystem::exists(tmp),
                "R8 P2-2B: aborts before closing active handle when shifting .1 -> .2 fails");
            FsRotateOps::close(active);
        }

        // 3) keep == 3 happy-path multi-generation rotation + empty names guard
        {
            std::filesystem::remove(bak1, ec); std::filesystem::remove(bak2, ec);
            { std::ofstream f(cur); f << "gen1\n"; }
            std::uint64_t sz = 0; int oerr = 0;
            auto active = FsRotateOps::open_append(cur, false, sz, oerr);
            std::array<std::string, 3> names{"app.log", "app.log.1", "app.log.2"};
            FsRotateOps ops{};
            expect(logging::rotate_file_ops<FdHandle, int>(dir, names, "app.log.rotate", active, sz, ops) == 0 &&
                   sz == 0 && read_all(bak1) == "gen1\n" && read_all(cur).empty(),
                "R8 P2-2C: first rotation moves cur -> .1 cleanly");
            expect(write_fd(active.fd, "gen2\n") &&
                   logging::rotate_file_ops<FdHandle, int>(dir, names, "app.log.rotate", active, sz, ops) == 0 &&
                   read_all(bak2) == "gen1\n" && read_all(bak1) == "gen2\n" && read_all(cur).empty(),
                "R8 P2-2C: second rotation shifts .1 -> .2 and cur -> .1");
            std::span<std::string const> empty_names{};
            expect(logging::rotate_file_ops<FdHandle, int>(dir, empty_names, "app.log.rotate", active, sz, ops) == EINVAL,
                "R8 P2-2D: empty names returns invalid_arg without underflow");
            FsRotateOps::close(active);
        }
        std::filesystem::remove_all(dir, ec);
    }
}

auto main() -> int {
    test_ssh_peer_initiated_rekey();
    test_ssh_local_tx_threshold_rekey();
    test_ssh_simultaneous_rx_and_security();
    test_xhttp_stream_up_ticket_release();
    test_windows_log_rotation_safety();
    if (failures) {
        std::cerr << "wave36-core-audit-r8-track-a-unit FAILED (" << failures << " failures)\n";
        return 1;
    }
    std::cout << "ALL Wave 36 Round 8 Track A Core Audit regression tests PASSED (SSH rekey + XHTTP stream-up + Windows log rotation)\n";
    return 0;
}
