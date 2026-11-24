import std;
import platform.netlink_abi;
import platform.netlink_codec;
import platform.netlink_socket;
import packet.tun_linux;
import packet.tun_network_types;
import packet.tun_network_records;
import packet.tun_network_requests;
import packet.tun_network_view;
import packet.tun_network;
import test.lease_support;
namespace t = test::lease;
namespace n = ::platform::netlink;
namespace a = ::platform::netlink_abi;
namespace p = ::packet;
namespace d = ::packet::tun_network_detail;
namespace {
    struct Faults {
        static inline unsigned count = 0, dumps = 0, target = 0;
        static inline bool used = false, keep_up = false, dump_mode = false;
        static inline std::string_view effect;
        static auto before_send(std::span<std::uint8_t const> bytes, bool mutation) noexcept -> std::error_code {
            if (mutation) ++count;
            else ++dumps;
            if (!mutation && !dump_mode) return {};
            if (keep_up) {
                auto header = n::native<a::nlmsghdr>(bytes);
                if (header && header->nlmsg_type == a::RTM_NEWLINK) {
                    auto link = n::native<a::ifinfomsg>(bytes, sizeof(*header));
                    if (link && link->ifi_change == a::IFF_UP && !(link->ifi_flags & a::IFF_UP)) return std::make_error_code(std::errc::permission_denied);
                }
            }
            if (!used && mutation != dump_mode && (dump_mode ? dumps : count) == target && effect == "send") {
                used = true;
                return std::make_error_code(std::errc::permission_denied);
            }
            return {};
        }
        static auto after_receive(std::span<std::uint8_t>, bool mutation) noexcept -> n::ReceiveFault {
            // A dump has no advertised record count. Discard the complete
            // response (including DONE) to exercise its real receive timeout;
            // silently omitting an unrelated data chunk is not an ACK loss.
            if (dump_mode && !mutation && dumps==target && effect=="loss") { used=true; return n::ReceiveFault::lost_ack; }
            if (mutation == dump_mode || used || (dump_mode ? dumps : count) != target || effect == "send") return n::ReceiveFault::none;
            used = true;
            if (effect == "loss") return n::ReceiveFault::lost_ack;
            if (effect == "overflow") return n::ReceiveFault::overflow;
            if (effect == "truncated") return n::ReceiveFault::truncated;
            if (effect == "sequence") return n::ReceiveFault::wrong_sequence;
            if (effect == "sender") return n::ReceiveFault::wrong_sender;
            if (effect == "malformed") return n::ReceiveFault::malformed;
            return n::ReceiveFault::none;
        }
        static auto reset(std::string_view kind = {}, unsigned ordinal = 0, bool keep = false, bool dump = false) noexcept -> void {
            count = dumps = 0;
            target = ordinal;
            used = false;
            effect = kind;
            keep_up = keep;
            dump_mode = dump;
        }
    };
    using Lease = p::TunNetworkLease<Faults>;
    auto explain(p::TunNetworkFailure const &error) -> void {
        std::println("lease error code={} stage={} system={} nl={}", int(error.code), int(error.stage), error.system.message(), error.netlink ? int(error.netlink->code) : -1);
    }
    auto stopped(Lease &lease, p::LinuxTun &device, bool clean = true) -> p::TunCleanupReport {
        auto before = lease.native_handle();
        auto report = lease.stop(t::deadline());
        if (clean && report.total)
            for (std::size_t i = 0; i < report.recorded; ++i)
                std::println("cleanup code={} stage={} system={}", int(report.issues[i].code), int(report.issues[i].stage), report.issues[i].system.message());
        t::require(lease.drained() && device.native_handle() < 0 && report.device_closed && report.device_removed && report.socket_closed);
        t::require(!clean || !report.total);
        if (before >= 0) t::require(a::fcntl(before, a::F_GETFD) < 0 && *a::__errno_location() == std::to_underlying(std::errc::bad_file_descriptor));
        auto again = lease.stop(t::deadline());
        t::require(again.total == report.total && again.recorded == report.recorded);
        return report;
    }
    auto default_case(std::string_view mode, std::string_view effect, unsigned target) -> void {
        auto device = p::LinuxTun::create("nx-lease");
        t::require(device.has_value());
        auto settings = t::options();
        if (mode == "conflict" && effect.starts_with("specific")) {
            settings.routes[0] = {4, {10, 42, 0, 0}, 24};
            settings.routes[1] = {6, {0xfd, 0x42}, 64};
        }
        if (mode == "capacity") {
            settings.address_count = 16;
            settings.route_count = 64;
            for (unsigned i = 0; i < 16; ++i)
                settings.addresses[i] = {4, {10, 42, 0, static_cast<std::uint8_t>(i + 1)}, 24};
            for (unsigned i = 0; i < 64; ++i)
                settings.routes[i] = {4, {10, 43, 0, static_cast<std::uint8_t>(i + 1)}, 32};
        }
        if (mode == "ipv4-small") {
            settings.mtu = 100;
            settings.address_count = settings.route_count = 1;
        }
        auto lease = Lease::create(*device, settings);
        t::require(lease.has_value());
        auto fault=mode=="fault" || mode=="dump-fault";
        Faults::reset(fault ? effect : std::string_view{}, fault ? target : 0,false,mode=="dump-fault");
        auto start = lease->start(t::deadline());
        if (mode == "conflict" || mode=="dump-fault" || (mode == "fault" && effect == "send")) {
            if (start) {
                (void)stopped(*lease, *device);
                t::require(false);
            }
            t::require(!fault || Faults::used);
            t::require(mode != "conflict" || start.error().code == p::TunNetworkError::conflict);
            t::require(lease->drained() && !lease->cleanup().total && device->native_handle() < 0);
            std::println("{{\"mode\":\"{}\",\"effect\":\"{}\",\"target\":{},\"rollback\":true,\"mutations\":{}}}", mode, effect, target, Faults::count);
            return;
        }
        if (!start) explain(start.error());
        t::require(start.has_value());
        auto state = lease->status();
        t::require(state.started && state.addresses == settings.address_count && state.routes == settings.route_count);
        if (mode == "fault") t::require(Faults::used && state.reconciled == 1);
        auto startup_count = Faults::count;
        if (mode == "interactive" || mode == "foreign-alias" || mode == "foreign-route" || mode == "foreign-route6" || mode == "foreign-device") {
            std::println("{{\"ready\":true,\"ifindex\":{},\"mtu\":{},\"fd\":{},\"mutations\":{}}}", state.ifindex, settings.mtu, lease->native_handle(), startup_count);
            std::fflush(nullptr);
            std::string command;
            t::require(bool(std::getline(std::cin, command)) && command == "stop");
        }
        if (mode == "already-closed") device->close();
        if (mode == "namespace") {
            auto original = t::namespace_id("/proc/self/ns/net");
            t::require(a::unshare(a::CLONE_NEWNET) == 0 && t::namespace_id("/proc/self/ns/net") != original);
        }
        if (mode == "cleanup-fault") Faults::reset(effect, target);
        else if (mode == "cleanup-keepup") Faults::reset(effect, target, true);
        else Faults::reset();
        bool clean = mode != "cleanup-fault" && mode != "cleanup-keepup" && mode != "foreign-alias" && mode != "foreign-device" && mode != "namespace";
        auto report = stopped(*lease, *device, clean);
        if (mode == "cleanup-fault") t::require(Faults::used && report.total >= 1);
        if (mode == "cleanup-keepup") t::require(report.total >= 1 && (target == 0 || Faults::used) && Faults::count == 5);
        if (mode == "foreign-alias" || mode == "namespace") t::require(report.total >= 1);
        std::println(
            "{{\"mode\":\"{}\",\"effect\":\"{}\",\"target\":{},\"startup_mutations\":{},\"cleanup_mutations\":{},\"reconciled\":{},\"cleanup_issues\":{},\"drained\":true}}", mode,
            effect, target, startup_count, Faults::count, state.reconciled, report.total);
    }
    auto validation() -> void {
        auto device = p::LinuxTun::create("nx-lease");
        t::require(device.has_value());
        auto original = device->native_handle();
        for (unsigned fault = 0; fault < 10; ++fault) {
            auto settings = t::options();
            if (!fault) settings.mtu = 0;
            if (fault == 1) settings.mtu = 1279;
            if (fault == 2) settings.address_count = 0;
            if (fault == 3) settings.address_count = 17;
            if (fault == 4) settings.route_count = 65;
            if (fault == 5) settings.addresses[1] = settings.addresses[0];
            if (fault == 6) settings.routes[1] = settings.routes[0];
            if (fault == 7) settings.routes[0].prefix = 0;
            if (fault == 8) settings.routes[0].prefix = 24;
            if (fault == 9) settings.addresses[1].bytes[0] = 255;
            auto denied = Lease::create(*device, settings);
            t::require(!denied && denied.error().code == p::TunNetworkError::configuration && device->native_handle() == original);
        }
        auto lease = Lease::create(*device, t::options());
        t::require(lease.has_value());
        t::require(!Lease::create(*device, t::options()));
        t::require(lease->start(t::deadline()).has_value());
        t::require(!lease->start(t::deadline()));
        (void)stopped(*lease, *device);
        std::println("validation rejects bad MTU/address/route/capacity before token transfer, once-only claim and once-only start passed");
    }
    auto persistence() -> void {
        auto device = p::LinuxTun::create("nx-lease");
        t::require(device.has_value());
        t::require(a::ioctl(device->native_handle(), a::TUNSETPERSIST, 1) == 0);
        auto lease = Lease::create(*device, t::options());
        t::require(!lease && device->native_handle() >= 0);
        t::require(a::ioctl(device->native_handle(), a::TUNSETPERSIST, 0) == 0);
        device->close();
        std::println("persistent TUN refused before token claim; explicit fixture cleanup restored nonpersistent lifetime");
    }
    auto moved(bool after_start,bool roundtrip=false) -> void {
        auto device = p::LinuxTun::create("nx-lease");
        t::require(device.has_value());
        auto lease = Lease::create(*device, t::options());
        t::require(lease.has_value());
        if (after_start) t::require(lease->start(t::deadline()).has_value());
        auto original = device->native_handle();
        p::LinuxTun next(std::move(*device));
        if (roundtrip) *device=std::move(next);
        if (!after_start) t::require(!lease->start(t::deadline()));
        else (void)lease->stop(t::deadline());
        auto &current=roundtrip ? *device : next;
        t::require(!lease->drained() && lease->cleanup().total && current.native_handle() == original && a::fcntl(original, a::F_GETFD) >= 0 && !current.claim_network());
        current.close();
        std::println("moving a claimed TUN{} permanently invalidates the old lease without configuring or closing the current owner",roundtrip ? " out and back" : "");
    }
    auto expired() -> void {
        auto device = p::LinuxTun::create("nx-lease");
        t::require(device.has_value());
        auto lease = Lease::create(*device, t::options());
        t::require(lease.has_value());
        auto start = lease->start(n::Clock::now() - std::chrono::seconds(1));
        auto report=lease->cleanup();
        t::require(!start && !lease->drained() && device->native_handle() < 0 && report.device_closed && report.socket_closed && !report.device_removed && report.total &&
                   start.error().netlink && start.error().netlink->code == n::Error::timeout);
        std::println("expired shared startup/rollback budget closes descriptors and truthfully leaves kernel removal unverified");
    }
    auto reused() -> void {
        auto device=p::LinuxTun::create("nx-lease"); t::require(device.has_value());
        auto lease=Lease::create(*device,t::options()); t::require(lease.has_value());
        auto original=device->native_handle(); device->close();
        auto replacement=p::LinuxTun::create("nx-lease"); t::require(replacement && replacement->native_handle()==original);
        *device=std::move(*replacement);
        t::require(!lease->start(t::deadline()) && !lease->cleanup().device_closed && !lease->drained() && device->native_handle()==original);
        t::require(a::fcntl(original,a::F_GETFD)>=0 && device->claim_network().has_value()); device->close();
        std::println("reused owner address, device name and descriptor number cannot revive an old token or close the replacement");
    }
    auto abandoned() -> void {
        auto device=p::LinuxTun::create("nx-lease"); t::require(device.has_value());
        { auto token=device->claim_network(); t::require(token && token->inspect()); }
        t::require(!Lease::create(*device,t::options()) && device->native_handle()>=0); device->close();
        std::println("discarding a once-only token cannot create a second network manager");
    }
    auto closed_before_start() -> void {
        auto device=p::LinuxTun::create("nx-lease"); t::require(device.has_value());
        auto lease=Lease::create(*device,t::options()); t::require(lease.has_value()); device->close();
        t::require(!lease->start(t::deadline()) && lease->drained() && !lease->cleanup().total);
        std::println("a closed claimed owner remains recognized as closed without matching a later device");
    }
    auto persistence_after_claim() -> void {
        auto device=p::LinuxTun::create("nx-lease"); t::require(device.has_value());
        auto lease=Lease::create(*device,t::options()); t::require(lease.has_value());
        t::require(a::ioctl(device->native_handle(),a::TUNSETPERSIST,1)==0);
        auto start=lease->start(t::deadline()); auto report=lease->cleanup();
        t::require(!start && !lease->drained() && report.device_closed && !report.device_removed && report.total && report.socket_closed);
        std::println("external persistence change is rejected, descriptors close, and the retained device is reported instead of falsely verified removed");
    }
    auto deadline_case(bool separate,bool stopping=false) -> void {
        auto device=p::LinuxTun::create("nx-lease"); t::require(device.has_value());
        auto lease=Lease::create(*device,t::options()); t::require(lease.has_value());
        if (stopping) t::require(lease->start(t::deadline()).has_value());
        Faults::reset("loss",stopping ? 0 : 4);
        auto begin=n::Clock::now(),deadline=begin+std::chrono::milliseconds(100);
        if (stopping) (void)lease->stop(begin);
        else {
            auto start=lease->start(deadline,separate ? begin+std::chrono::seconds(2) : deadline);
            t::require(!start && Faults::used && start.error().netlink && start.error().netlink->code==n::Error::timeout);
        }
        auto elapsed=n::Clock::now()-begin; auto report=lease->cleanup();
        t::require(device->native_handle()<0 && report.device_closed && report.socket_closed && lease->status().stopped);
        t::require(separate ? lease->drained() && report.device_removed && !report.total : !lease->drained() && !report.device_removed && report.total);
        t::require(elapsed<std::chrono::seconds(1));
        if (!stopping) t::require(elapsed>=std::chrono::milliseconds(90));
        std::println("{} deadline: elapsed={}ms device_closed=true socket_closed=true removal_verified={} issues={}",stopping ? "expired stop" : separate ? "explicit rollback" : "shared rollback",
                    std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(),report.device_removed,report.total);
    }
    auto destruction(bool active) -> void {
        auto device=p::LinuxTun::create("nx-lease"); t::require(device.has_value()); auto original=device->native_handle();
        auto begin=n::Clock::now();
        { auto lease=Lease::create(*device,t::options()); t::require(lease.has_value()); if (active) t::require(lease->start(t::deadline()).has_value()); }
        t::require(device->native_handle()<0 && a::fcntl(original,a::F_GETFD)<0 && n::Clock::now()-begin<std::chrono::seconds(1));
        std::println("{} destruction performs bounded descriptor cleanup without inventing a new network cleanup budget",active ? "active" : "unstarted");
    }
    auto kernel_reject() -> void {
        auto device = p::LinuxTun::create("nx-lease");
        t::require(device.has_value());
        n::Socket control;
        t::require(control.open().has_value());
        d::View reader(control, 0, t::deadline());
        auto link = reader.link("nx-lease");
        t::require(link && *link);
        auto rejected = control.acknowledge(d::link_request((**link).index, std::numeric_limits<std::uint32_t>::max()), t::deadline());
        t::require(!rejected && rejected.error().rejected && rejected.error().code == n::Error::system);
        auto current = reader.link("nx-lease");
        t::require(current && *current && (**current).mtu == (**link).mtu);
        device->close();
        std::println("real kernel negative ACK binds exact request and preserves MTU on rejected operation");
    }
    auto replace_snapshot() -> void {
        auto device = p::LinuxTun::create("nx-lease");
        t::require(device.has_value());
        auto initial = t::options();
        auto lease = Lease::create(*device, initial);
        t::require(lease && lease->start(t::deadline()));
        auto index = lease->status().ifindex;
        n::Socket control;
        t::require(control.open().has_value());
        auto verify = [&](p::TunNetworkOptions const &current, p::TunNetworkOptions const &absent) {
            d::View reader(control, index, t::deadline());
            auto link = reader.link("nx-lease");
            t::require(link && *link && (**link).index == index);
            for (auto const &entry : std::span(current.addresses).first(current.address_count)) {
                auto address = reader.address(entry);
                t::require(address && *address && (**address).address == entry);
            }
            for (auto const &entry : std::span(current.routes).first(current.route_count)) {
                auto route = reader.route(entry);
                t::require(route && *route && (**route).destination == entry);
            }
            for (auto const &entry : std::span(absent.addresses).first(absent.address_count)) {
                auto address = reader.address(entry);
                t::require(address && !*address);
            }
            for (auto const &entry : std::span(absent.routes).first(absent.route_count)) {
                auto route = reader.route(entry);
                t::require(route && !*route);
            }
        };
        auto next = initial;
        next.addresses[0].bytes[3] = 10;
        next.routes[0].bytes[3] = 11;
        next.address_count = next.route_count = 1;
        for (unsigned failure : {2u, 6u}) {
            Faults::reset("send", failure);
            t::require(!lease->replace(next, t::deadline(), t::deadline()) && Faults::used && lease->status().started);
            verify(initial, next);
        }
        Faults::reset("loss", 5);
        t::require(lease->replace(next, t::deadline(), t::deadline()).has_value() && Faults::used);
        verify(next, initial);
        auto empty = next;
        empty.address_count = empty.route_count = 0;
        t::require(lease->replace(empty, t::deadline(), t::deadline()).has_value());
        verify(empty, next);
        t::require(lease->replace(initial, t::deadline(), t::deadline()).has_value());
        verify(initial, next);
        (void)stopped(*lease, *device);
        std::println("stable TUN snapshot replacement, withdrawal, lost ACK reconciliation and partial rollback passed");
    }
} // namespace
auto main(int argc, char **argv) -> int {
    try {
        t::isolation(argc, argv);
        t::require(argc >= 4);
        auto mode = std::string_view(argv[3]);
        auto effect = argc > 4 ? std::string_view(argv[4]) : std::string_view{};
        auto target = argc > 5 ? unsigned(t::number(argv[5])) : 0;
        if (mode == "validation") validation();
        else if (mode == "persistent") persistence();
        else if (mode == "moved") moved(false);
        else if (mode == "moved-active") moved(true);
        else if (mode == "moved-back") moved(false,true);
        else if (mode == "moved-back-active") moved(true,true);
        else if (mode == "reused") reused();
        else if (mode == "abandoned") abandoned();
        else if (mode == "closed-before-start") closed_before_start();
        else if (mode == "persistent-after-claim") persistence_after_claim();
        else if (mode == "shared-deadline") deadline_case(false);
        else if (mode == "rollback-deadline") deadline_case(true);
        else if (mode == "stop-deadline") deadline_case(false,true);
        else if (mode == "destructor") destruction(false);
        else if (mode == "destructor-active") destruction(true);
        else if (mode == "expired") expired();
        else if (mode == "kernel-reject") kernel_reject();
        else if (mode == "replace") replace_snapshot();
        else default_case(mode, effect, target);
    } catch (int value) { return value; }
}
