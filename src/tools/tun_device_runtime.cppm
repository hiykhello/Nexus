module;
#if defined(__linux__) && defined(NEXUS_ENABLE_IO_URING)
#include <cerrno>
#endif

export module cli.tun_device_runtime;
import std;
import config;
import packet;
import packet.tun_pump;
import packet.tun_device;
import packet.tun_network_plan;
import packet.tun_network_darwin;
import packet.tun_network_windows;
import platform.ip_address;
import platform.tun_bridge;
import packet.fd;
import packet.tun_network_types;
import packet.tun_network;
import packet.tun_default_policy;
import cli.tun_network_owner;
import platform.uring_buf_ring;

export namespace cli::tun_enabled {
    struct PumpStepSummary {
        bool input_delivered = false;
        bool output_delivered = false;
        bool fatal_error = false;
        std::string error_detail;
    };

    [[nodiscard]] inline auto build_tun_route_plan(config::TunInbound const& cfg)
        -> std::expected<packet::TunRoutePlan, std::string> {
        packet::TunRoutePlanInput in;
        in.mtu = cfg.mtu;
        in.auto_route = cfg.auto_route;
        in.route_exclude_private = cfg.route_exclude_private;
        if (cfg.inet4_address) {
            auto parsed = packet::parse_tun_cidr(*cfg.inet4_address);
            if (!parsed || parsed->family != 4) return std::unexpected("invalid inet4-address");
            in.inet4 = *parsed;
        }
        if (cfg.inet6_address) {
            auto parsed = packet::parse_tun_cidr(*cfg.inet6_address);
            if (!parsed || parsed->family != 6) return std::unexpected("invalid inet6-address");
            in.inet6 = *parsed;
        }
        for (auto const& text : cfg.route_includes) {
            auto parsed = packet::parse_tun_cidr(text);
            if (!parsed) return std::unexpected("invalid TUN route-include: " + text);
            in.includes.push_back(*parsed);
        }
        for (auto const& text : cfg.route_excludes) {
            auto parsed = packet::parse_tun_cidr(text);
            if (!parsed) return std::unexpected("invalid TUN route-exclude: " + text);
            in.excludes.push_back(*parsed);
        }
#if defined(__APPLE__)
        return packet::plan_darwin_tun_network(in, cfg.interface_name);
#elif defined(_WIN32)
        return packet::plan_windows_tun_network(in);
#else
        return packet::plan_cross_platform_tun_routes(in);
#endif
    }

    namespace detail {
        inline auto parse_cidr_addr(std::string_view text, bool ipv6) -> std::optional<packet::TunAddress> {
            auto slash = text.find('/');
            if (slash == std::string_view::npos) return std::nullopt;
            unsigned pfx = 0, max_pfx = ipv6 ? 128u : 32u;
            auto ps = text.substr(slash + 1);
            auto [end, ec] = std::from_chars(ps.data(), ps.data() + ps.size(), pfx);
            auto parsed = platform::parse_ip_address(text.substr(0, slash));
            if (ec != std::errc{} || end != ps.data() + ps.size() || pfx < 1u || pfx > max_pfx ||
                !parsed || (parsed->size == 16) != ipv6)
                return std::nullopt;
            packet::TunAddress out{.family = static_cast<std::uint8_t>(ipv6 ? 6 : 4), .prefix = static_cast<std::uint8_t>(pfx)};
            std::copy_n(parsed->bytes.begin(), parsed->size, out.bytes.begin());
            return out;
        }

        inline auto mask_network(packet::TunAddress addr) noexcept -> packet::TunAddress {
            std::size_t n = addr.family == 6 ? 16 : 4;
            std::size_t keep = addr.prefix / 8, rem = addr.prefix % 8;
            if (keep < n && rem) addr.bytes[keep] &= static_cast<std::uint8_t>(255u << (8 - rem));
            for (std::size_t i = keep + (rem != 0); i < n; ++i) addr.bytes[i] = 0;
            return addr;
        }

        inline auto is_fatal_io_error(std::error_code ec) noexcept -> bool {
            return ec == std::errc::bad_file_descriptor ||
                   ec == std::errc::no_such_device ||
                   ec == std::errc::no_such_device_or_address ||
                   ec == std::errc::broken_pipe ||
                   ec == std::errc::io_error ||
                   ec == std::errc::not_connected ||
                   ec == std::errc::network_down ||
                   ec == std::errc::permission_denied;
        }

        template<class T>
        inline auto classify_tun_failure(T const& val, std::string& detail) -> bool {
            if constexpr (std::same_as<T, std::error_code>) {
                if (!is_fatal_io_error(val)) return false;
                detail = "TUN device I/O error: " + val.message();
                return true;
            } else if constexpr (std::same_as<T, platform::TunBridgeError>) {
                if (val == platform::TunBridgeError::closed) { detail = "TUN bridge closed"; return true; }
                return false;
            } else if constexpr (std::same_as<T, packet::FdError>) {
                if (val == packet::FdError::end_of_file || val == packet::FdError::invalid_fd) {
                    detail = "TUN device closed"; return true;
                }
                return false;
            } else if constexpr (std::same_as<T, packet::TunPumpError>) {
                if (val == packet::TunPumpError::invalid_device) { detail = "TUN device invalid"; return true; }
                return false;
            } else if constexpr (requires { std::visit([](auto const&) {}, val); }) {
                return std::visit([&](auto const& inner) { return classify_tun_failure(inner, detail); }, val);
            } else {
                return false;
            }
        }

        template<class Step>
        inline auto summarize_step(Step const& s) -> PumpStepSummary {
            PumpStepSummary out{s.input_delivered, s.output_delivered, false, {}};
            if (s.input_error && classify_tun_failure(*s.input_error, out.error_detail)) out.fatal_error = true;
            else if (s.output_error && classify_tun_failure(*s.output_error, out.error_detail)) out.fatal_error = true;
            return out;
        }
    }

    struct TunDeviceRuntime {
        std::optional<packet::PlatformTun> platform_tun;
        std::shared_ptr<platform::ExternalTunBridge> bridge;
        std::optional<packet::TunDevicePump<platform::ExternalTunBridge>> bridge_pump;
#if defined(__linux__)
        std::optional<packet::FdPump> fd_pump;
        std::optional<packet::TunNetworkLease<>> lease;
        std::optional<packet::TunDefaultPolicy<>> default_policy;
        std::optional<StrictTunOwner> network_owner;
        std::optional<StrictTunRequest> pending_strict_request;
#if defined(__linux__) && defined(NEXUS_ENABLE_IO_URING)
        std::optional<platform::UringMultishotLoop> uring_rx;
        std::array<platform::MultishotEvent, 32> uring_pending{};
        std::size_t uring_head = 0, uring_tail = 0;
        packet::MemoryLink* uring_link = nullptr;
        std::uint16_t uring_mtu = 1500;
        auto disable_uring_rx() noexcept -> void {
            if (uring_rx) {
                for (std::size_t i = uring_head; i < uring_tail; ++i)
                    if (uring_pending[i].has_buffer) { (void)uring_rx->recycle(uring_pending[i].buffer_id); uring_pending[i].has_buffer = false; }
                if (platform_tun) (void)uring_rx->cancel_fd(platform_tun->native_handle());
                uring_rx.reset();
            }
            uring_head = uring_tail = 0; uring_link = nullptr;
        }
#endif
#else
        std::optional<packet::TunDevicePump<packet::PlatformTun>> dev_pump;
#if defined(__APPLE__)
        std::optional<packet::DarwinTunNetwork> darwin_network;
#elif defined(_WIN32)
        std::optional<packet::WindowsTunNetwork> windows_network;
#endif
#endif
        std::string active_name;

        [[nodiscard]] auto device_name() const noexcept -> std::string_view { return active_name; }
        [[nodiscard]] auto native_fd() const noexcept -> int {
#if !defined(_WIN32)
            return platform_tun ? platform_tun->native_handle() : -1;
#else
            return -1;
#endif
        }
        [[nodiscard]] auto uring_fd() const noexcept -> int {
#if defined(__linux__) && defined(NEXUS_ENABLE_IO_URING)
            return uring_rx ? uring_rx->ring_fd() : -1;
#else
            return -1;
#endif
        }
        [[nodiscard]] auto has_uring_rx() const noexcept -> bool { return uring_fd() >= 0; }
        [[nodiscard]] auto has_policy_health() const noexcept -> bool {
#if defined(__linux__)
            return default_policy.has_value() || network_owner.has_value();
#else
            return false;
#endif
        }

        [[nodiscard]] auto start_bridge(std::shared_ptr<platform::ExternalTunBridge> b,
            packet::MemoryLink& link, std::uint16_t mtu) -> std::expected<std::string, std::string> {
            if (!b) return std::unexpected("TUN bridge handle is null");
            auto p = packet::TunDevicePump<platform::ExternalTunBridge>::create(*b, link, mtu);
            if (!p) return std::unexpected("failed initializing TUN bridge pump");
            bridge = std::move(b);
            bridge_pump.emplace(std::move(*p));
            active_name = std::string(bridge->device_name());
            return active_name;
        }

#if defined(__linux__)
        [[nodiscard]] auto prepare_linux_request(config::TunInbound const& cfg, packet::TunRedirectOptions redirect,
            std::optional<std::uint16_t> redirect_port) -> std::expected<StrictTunRequest, std::string> {
            StrictTunRequest request;
            if (redirect_port) {
                request.redirect = redirect;
                request.redirect.port = *redirect_port;
                request.redirect.exclude_mptcp = cfg.exclude_mptcp;
            }
            if (cfg.host_dns_resolved) {
#ifndef NEXUS_TUN_HOST_DNS
                return std::unexpected("TUN host-dns backend is not enabled in this build");
#else
                if (cfg.host_dns_server.empty() || cfg.host_dns_server.size() >= request.dns_stub.size())
                    return std::unexpected("TUN host-dns requires a supervised strict-route and a DNS stub");
                std::ranges::copy(cfg.host_dns_server, request.dns_stub.begin());
#endif
            }
            auto& nopts = request.network;
            nopts.mtu = cfg.mtu;
            if (cfg.inet4_address) {
                auto address = detail::parse_cidr_addr(*cfg.inet4_address, false);
                if (!address) return std::unexpected("invalid inet4-address");
                nopts.addresses[nopts.address_count++] = *address;
                if (!cfg.strict_route && address->prefix < 32) nopts.routes[nopts.route_count++] = detail::mask_network(*address);
                if (cfg.auto_route && !cfg.strict_route && cfg.route_includes.empty()) {
                    nopts.routes[nopts.route_count++] = {4, {0}, 1};
                    nopts.routes[nopts.route_count++] = {4, {128}, 1};
                }
            }
            if (cfg.inet6_address) {
                auto address = detail::parse_cidr_addr(*cfg.inet6_address, true);
                if (!address) return std::unexpected("invalid inet6-address");
                nopts.addresses[nopts.address_count++] = *address;
                if (!cfg.strict_route && address->prefix < 128) nopts.routes[nopts.route_count++] = detail::mask_network(*address);
                if (cfg.auto_route && !cfg.strict_route && cfg.route_includes.empty()) {
                    nopts.routes[nopts.route_count++] = {6, {0}, 1};
                    nopts.routes[nopts.route_count++] = {6, {128}, 1};
                }
            }
            for (auto const& text : cfg.route_includes) {
                if (auto pfx = detail::parse_cidr_addr(text, text.contains(':')); pfx && nopts.route_count < nopts.routes.size())
                    nopts.routes[nopts.route_count++] = detail::mask_network(*pfx);
            }
            if (cfg.strict_route) {
                if (cfg.interface_name.size() >= request.name.size()) return std::unexpected("invalid TUN interface-name");
                std::ranges::copy(cfg.interface_name, request.name.begin());
                if (cfg.socket_mark) request.policy.mark = *cfg.socket_mark;
                request.policy.include_mark = cfg.include_routing_mark;
                request.policy.exclude_mark = cfg.exclude_routing_mark;
                for (auto const& text : cfg.route_excludes) {
                    auto prefix = detail::parse_cidr_addr(text, text.contains(':'));
                    if (!prefix || request.exclude_count == request.excludes.size())
                        return std::unexpected("invalid TUN route-exclude");
                    auto normalized = detail::mask_network(*prefix);
                    if (std::ranges::contains(std::span(request.excludes).first(request.exclude_count), normalized))
                        return std::unexpected("duplicate TUN route-exclude");
                    request.excludes[request.exclude_count++] = normalized;
                }
                if (cfg.route_exclude_private) {
                    constexpr std::array private_routes{
                        packet::TunAddress{4, {10}, 8}, packet::TunAddress{4, {172, 16}, 12},
                        packet::TunAddress{4, {192, 168}, 16}, packet::TunAddress{4, {100, 64}, 10},
                        packet::TunAddress{4, {169, 254}, 16}, packet::TunAddress{6, {0xfc}, 7},
                        packet::TunAddress{6, {0xfe, 0x80}, 10}
                    };
                    for (auto const& prefix : private_routes) {
                        if (!(prefix.family == 4 ? cfg.inet4_address : cfg.inet6_address)) continue;
                        if (std::ranges::contains(std::span(request.excludes).first(request.exclude_count), prefix)) continue;
                        if (request.exclude_count >= request.excludes.size())
                            return std::unexpected("TUN route-exclude limit exceeded");
                        request.excludes[request.exclude_count++] = prefix;
                    }
                }
            }
            request.multi_queue = cfg.multi_queue;
            return request;
        }

        [[nodiscard]] auto start_linux_device(config::TunInbound const& cfg, packet::MemoryLink& link,
            bool supervise_strict_network, StrictTunRequest const& request,
            std::optional<packet::PlatformTun> supplied) -> std::expected<std::string, std::string> {
            using Clock = std::chrono::steady_clock;
            if (supplied) platform_tun.emplace(std::move(*supplied));
            else if (cfg.strict_route && supervise_strict_network) {
                network_owner.emplace();
                auto started = network_owner->start(request);
                if (!started) return std::unexpected(std::move(started.error()));
                platform_tun.emplace(std::move(*started));
            } else {
                auto t = packet::LinuxTun::create(cfg.interface_name, {.multi_queue = cfg.multi_queue});
                if (!t) return std::unexpected("failed creating TUN device " + cfg.interface_name);
                platform_tun.emplace(std::move(*t));
            }
            if (request.network.address_count && !network_owner) {
                auto tok = platform_tun->claim_network();
                if (!tok) return std::unexpected("failed claiming TUN network");
                if (auto st = packet::TunNetworkLease<>::emplace_into(lease, std::move(*tok), request.network); !st)
                    return std::unexpected(std::format("failed configuring TUN netlink (code={} stage={} sys={})",
                        static_cast<int>(st.error().code), static_cast<int>(st.error().stage), st.error().system.message()));
                if (auto st = lease->start(Clock::now() + std::chrono::seconds(5)); !st) {
                    auto err = std::format("failed starting TUN interface (code={} stage={} sys={})",
                        static_cast<int>(st.error().code), static_cast<int>(st.error().stage), st.error().system.message());
                    lease.reset();
                    return std::unexpected(std::move(err));
                }
            }
            auto p = packet::FdPump::create(platform_tun->native_handle(), link, cfg.mtu);
            if (!p) return std::unexpected("failed initializing TUN packet pump");
            fd_pump.emplace(std::move(*p));
#if defined(__linux__) && defined(NEXUS_ENABLE_IO_URING)
            auto bsz = std::max<std::uint32_t>(cfg.mtu + 64u, 4096u);
            if (auto r = platform::UringMultishotLoop::create({.ring_entries = 32, .buffer_size = bsz, .buffer_group_id = 1, .sq_entries = 64}))
                if (r->arm_read_multishot(platform_tun->native_handle(), 1) && r->submit()) {
                    uring_rx.emplace(std::move(*r)); uring_link = &link; uring_mtu = cfg.mtu;
                }
#endif
            active_name = std::string(platform_tun->name());
            if (cfg.strict_route && !network_owner) pending_strict_request = request;
            return active_name;
        }

        [[nodiscard]] auto activate_strict_policy() -> std::expected<void, std::string> {
            if (!pending_strict_request) return {};
            auto req = std::move(*pending_strict_request);
            pending_strict_request.reset();
            if (!lease) return std::unexpected("TUN strict-route requires an address");
            using Clock = std::chrono::steady_clock;
            default_policy.emplace();
            auto deadline = Clock::now() + std::chrono::seconds(3);
            auto excludes = std::span(req.excludes).first(req.exclude_count);
            auto installed = default_policy->start(*lease, req.policy, deadline, deadline + std::chrono::seconds(2), excludes);
            if (!installed) return std::unexpected(std::format("TUN strict-route installation failed (code={})",
                static_cast<int>(installed.error().code)));
            return {};
        }
#else
        [[nodiscard]] auto start_other_device(config::TunInbound const& cfg, packet::MemoryLink& link,
            std::optional<packet::PlatformTun> supplied) -> std::expected<std::string, std::string> {
            if (supplied) platform_tun.emplace(std::move(*supplied));
            else {
                auto t = packet::open_platform_tun(cfg.interface_name, cfg.mtu);
                if (!t) return std::unexpected("failed creating platform TUN device " + cfg.interface_name);
                platform_tun.emplace(std::move(*t));
            }
            active_name = packet::platform_tun_info(*platform_tun, cfg.mtu).name;
            if (cfg.auto_route || cfg.inet4_address || cfg.inet6_address) {
                auto plan = build_tun_route_plan(cfg);
                if (!plan) return std::unexpected(plan.error());
#if defined(__APPLE__)
                darwin_network.emplace();
                if (auto st = darwin_network->start(active_name, *plan); !st)
                    return std::unexpected("failed configuring Darwin utun routes: " + st.error().message());
#elif defined(_WIN32)
                windows_network.emplace();
                if (auto st = windows_network->start(platform_tun->luid(), *plan); !st)
                    return std::unexpected("failed configuring Wintun network: " + st.error().message());
#endif
            }
            auto p = packet::TunDevicePump<packet::PlatformTun>::create(*platform_tun, link, cfg.mtu);
            if (!p) return std::unexpected("failed initializing platform TUN pump");
            dev_pump.emplace(std::move(*p));
            return active_name;
        }
#endif

        template<class Validator>
        [[nodiscard]] auto step(Validator validator, void* ctx) -> PumpStepSummary {
            if (bridge_pump) return detail::summarize_step(bridge_pump->step(validator, ctx));
#if defined(__linux__)
#if defined(__linux__) && defined(NEXUS_ENABLE_IO_URING)
            bool prev_rx = false, prev_tx = false;
            if (uring_rx && fd_pump && uring_link) {
                auto tx = detail::summarize_step(fd_pump->step_output(validator, ctx));
                if (tx.fatal_error) return tx;
                prev_tx = tx.output_delivered;
                std::string fatal_detail;
                auto recycle_ev = [&](platform::MultishotEvent& ev) noexcept {
                    if (ev.has_buffer) { (void)uring_rx->recycle(ev.buffer_id); ev.has_buffer = false; }
                };
                auto rearm_or_disable = [&]() noexcept {
                    if (uring_rx && (!uring_rx->arm_read_multishot(platform_tun->native_handle(), 1) || !uring_rx->submit()))
                        disable_uring_rx();
                };
                auto handle_ev = [&](platform::MultishotEvent& ev) -> int {
                    if (ev.result == 0) {
                        recycle_ev(ev); fatal_detail = "TUN device closed"; disable_uring_rx(); return -2;
                    }
                    if (ev.result < 0) {
                        recycle_ev(ev);
                        int e = -ev.result;
                        if (e == EINVAL || e == EOPNOTSUPP) { disable_uring_rx(); return 0; }
                        if (e == ENOBUFS) { rearm_or_disable(); return 0; }
                        if (auto ec = std::error_code(e, std::generic_category()); detail::is_fatal_io_error(ec)) {
                            fatal_detail = "TUN device I/O error: " + ec.message(); disable_uring_rx(); return -2;
                        }
                        if (ev.needs_rearm) rearm_or_disable();
                        return 0;
                    }
                    if (!ev.has_buffer) { if (ev.needs_rearm) rearm_or_disable(); return 0; }
                    if (static_cast<std::size_t>(ev.result) > uring_mtu) {
                        recycle_ev(ev); if (ev.needs_rearm) rearm_or_disable(); return 0;
                    }
                    auto view = uring_rx->buffer_view(ev.buffer_id, static_cast<std::size_t>(ev.result));
                    auto ok = uring_link->send(packet::Side::first, view);
                    if (!ok && ok.error() == packet::DeviceError::queue_full) return -1;
                    recycle_ev(ev);
                    if (ok) prev_rx = true;
                    if (ev.needs_rearm) rearm_or_disable();
                    return ok ? 1 : 0;
                };
                auto drain_pending = [&]() -> int {
                    while (uring_rx && uring_head < uring_tail) {
                        int rc = handle_ev(uring_pending[uring_head]);
                        if (rc < 0) return rc;
                        if (uring_rx) ++uring_head;
                    }
                    if (uring_head == uring_tail) uring_head = uring_tail = 0;
                    return 0;
                };
                int drc = drain_pending();
                if (drc == -2) return {prev_rx, prev_tx, true, std::move(fatal_detail)};
                if (drc == -1) return {prev_rx, prev_tx, false, {}};
                if (uring_rx) {
                    auto n = uring_rx->poll_events(uring_pending, 0, 0);
                    if (!n) disable_uring_rx();
                    else {
                        uring_head = 0; uring_tail = *n;
                        if (drain_pending() == -2) return {prev_rx, prev_tx, true, std::move(fatal_detail)};
                    }
                }
                if (uring_rx) return {prev_rx, prev_tx, false, {}};
            }
#endif
            if (fd_pump) {
                auto out = detail::summarize_step(fd_pump->step(validator, ctx));
#if defined(__linux__) && defined(NEXUS_ENABLE_IO_URING)
                out.input_delivered = out.input_delivered || prev_rx;
                out.output_delivered = out.output_delivered || prev_tx;
#endif
                return out;
            }
#else
            if (dev_pump) return detail::summarize_step(dev_pump->step(validator, ctx));
#endif
            return {};
        }

        [[nodiscard]] auto check_policy_health() -> bool {
#if defined(__linux__)
            if (default_policy && !default_policy->check()) return false;
            if (network_owner && !network_owner->healthy()) return false;
#endif
            return true;
        }

        auto release(std::string& error_out, bool& had_error) noexcept -> void {
            bridge_pump.reset();
            bridge.reset();
#if defined(__linux__)
            using Clock = std::chrono::steady_clock;
#if defined(__linux__) && defined(NEXUS_ENABLE_IO_URING)
            disable_uring_rx();
#endif
            fd_pump.reset();
            if (default_policy) {
                (void)default_policy->stop(Clock::now() + std::chrono::seconds(3));
                if (!default_policy->drained()) { error_out = "TUN strict-route cleanup could not be verified"; had_error = true; }
                default_policy.reset();
            }
            if (lease) { (void)lease->stop(Clock::now() + std::chrono::seconds(3)); lease.reset(); }
            if (platform_tun) { platform_tun->close(); platform_tun.reset(); }
            if (network_owner) {
                if (!network_owner->stop() && !had_error) { error_out = "TUN strict-route cleanup could not be verified"; had_error = true; }
                network_owner.reset();
            }
#else
            dev_pump.reset();
#if defined(__APPLE__)
            if (darwin_network) { darwin_network->stop(); darwin_network.reset(); }
#elif defined(_WIN32)
            if (windows_network) { windows_network->stop(); windows_network.reset(); }
#endif
            if (platform_tun) { platform_tun->close(); platform_tun.reset(); }
#endif
        }
    };
}
