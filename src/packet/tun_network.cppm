export module packet.tun_network;
import std;
import platform.linux_random;
import platform.netlink_abi;
import platform.netlink_codec;
import platform.netlink_socket;
import packet.tun_linux;
import packet.tun_network_types;
import packet.tun_network_records;
import packet.tun_network_requests;
import packet.tun_network_view;

export namespace packet {
    template <class Hooks = platform::netlink::NoHooks> class TunNetworkLease {
        using Clock = platform::netlink::Clock;
        using Socket = platform::netlink::Socket<Hooks>;
        using Link = tun_network_detail::LinkRecord;
        using Address = tun_network_detail::AddressRecord;
        using Route = tun_network_detail::RouteRecord;
        using View = tun_network_detail::View<Socket>;
        LinuxTun::NetworkToken token_;
        TunNetworkOptions options_;
        Socket socket_;
        std::array<char, 48> marker_{};
        std::array<std::optional<Address>, 16> addresses_{};
        std::array<std::optional<Route>, 64> routes_{};
        std::array<bool, 16> address_attempted_{};
        std::array<bool, 64> route_attempted_{};
        TunNetworkStatus status_;
        TunCleanupReport cleanup_;
        bool claimed_ = false, starting_ = false;
        auto view(Clock::time_point deadline) noexcept -> View { return View(socket_, status_.ifindex, deadline); }
        static auto netlink_failure(platform::netlink::Failure value, TunNetworkStage stage) -> std::unexpected<TunNetworkFailure> {
            return std::unexpected(TunNetworkFailure{.code = TunNetworkError::netlink, .stage = stage, .system = value.system, .netlink = value});
        }
        auto marker() const noexcept -> std::string_view { return {marker_.data(), std::char_traits<char>::length(marker_.data())}; }
        auto name() const noexcept -> std::string_view {
            auto const &value = token_.identity().name;
            return {value.data(), std::char_traits<char>::length(value.data())};
        }
        auto same_device(Link const &link, bool claimed) const noexcept -> bool {
            bool alias = claimed ? std::string_view(link.alias.data()) == marker() : !link.alias[0];
            return link.index == status_.ifindex && link.name == token_.identity().name && link.type == platform::netlink_abi::ARPHRD_NONE && alias;
        }
        auto identity(Clock::time_point deadline, bool claimed = true) -> std::expected<Link, TunNetworkFailure> {
            auto device = token_.inspect();
            if (!device) return std::unexpected(TunNetworkFailure{.code = TunNetworkError::device, .stage = TunNetworkStage::identify, .device = device.error()});
            auto found = view(deadline).link();
            if (!found) return netlink_failure(found.error(), TunNetworkStage::identify);
            if (!*found || !same_device(**found, claimed)) return tun_network_detail::fail(TunNetworkError::ownership, TunNetworkStage::identify);
            return **found;
        }
        auto source(std::uint8_t family) const noexcept -> std::array<std::uint8_t, 16> {
            for (std::size_t i = 0; i < options_.address_count; ++i)
                if (options_.addresses[i].family == family) return options_.addresses[i].bytes;
            return {};
        }
        auto desired(Address const &value, TunAddress const &address) const noexcept -> bool {
            using namespace platform::netlink_abi;
            auto required = std::uint32_t(IFA_F_PERMANENT | IFA_F_NOPREFIXROUTE | (address.family == 6 ? IFA_F_NODAD : 0));
            return !value.complex && value.address == address && value.index == std::uint32_t(status_.ifindex) && value.peer == address.bytes &&
                   (!value.label[0] || value.label == token_.identity().name) && value.scope == RT_SCOPE_UNIVERSE && (value.flags & required) == required &&
                   !(value.flags & (IFA_F_TENTATIVE | IFA_F_DADFAILED));
        }
        auto desired(Route const &value, TunAddress const &route) const noexcept -> bool {
            using namespace platform::netlink_abi;
            return !value.complex && value.destination == route && value.index == std::uint32_t(status_.ifindex) && value.table == RT_TABLE_MAIN && value.priority == 1024 &&
                   value.protocol == RTPROT_STATIC && value.scope == (route.family == 6 ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK) && value.type == RTN_UNICAST && !value.flags && !value.preference &&
                   value.source == source(route.family);
        }
        auto preflight(Clock::time_point deadline) -> std::expected<void, TunNetworkFailure> {
            using namespace platform::netlink_abi;
            auto token = token_.inspect();
            if (!token) return std::unexpected(TunNetworkFailure{.code = TunNetworkError::device, .stage = TunNetworkStage::identify, .device = token.error()});
            auto link = view(deadline).link(name());
            if (!link) return netlink_failure(link.error(), TunNetworkStage::identify);
            if (!*link) return tun_network_detail::fail(TunNetworkError::ownership, TunNetworkStage::identify);
            status_.ifindex = (**link).index;
            if (!same_device(**link, false) || ((**link).flags & IFF_UP) || !((**link).flags & IFF_POINTOPOINT))
                return tun_network_detail::fail(TunNetworkError::ownership, TunNetworkStage::identify);
            bool conflict = false;
            for (auto family : {std::uint8_t{4}, std::uint8_t{6}}) {
                auto addresses = view(deadline).addresses(family, [&](Address const &address) -> std::expected<void, platform::netlink::Failure> {
                    if (address.index == std::uint32_t(status_.ifindex)) conflict = true;
                    for (std::size_t i = 0; i < options_.address_count; ++i)
                        if (address.address.family == options_.addresses[i].family && address.address.bytes == options_.addresses[i].bytes) conflict = true;
                    return {};
                });
                if (!addresses) return netlink_failure(addresses.error(), TunNetworkStage::validate);
                auto routes = view(deadline).routes(family, [&](Route const &route) -> std::expected<void, platform::netlink::Failure> {
                    if (route.index == std::uint32_t(status_.ifindex)) conflict = true;
                    if (route.table == RT_TABLE_MAIN)
                        for (std::size_t i = 0; i < options_.route_count; ++i)
                            if (tun_network_detail::contains(options_.routes[i], route.destination)) conflict = true;
                    return {};
                });
                if (!routes) return netlink_failure(routes.error(), TunNetworkStage::validate);
            }
            if (conflict) return tun_network_detail::fail(TunNetworkError::conflict, TunNetworkStage::validate);
            return {};
        }
        template <class Verify>
        auto apply(platform::netlink::Request request, TunNetworkStage stage, Clock::time_point deadline,
                   Verify &&verify, bool *attempted = nullptr) -> std::expected<void, TunNetworkFailure> {
            auto acknowledged = socket_.acknowledge(std::move(request), deadline);
            if (attempted) *attempted = acknowledged || (acknowledged.error().may_have_changed && !acknowledged.error().rejected);
            if (!acknowledged && !acknowledged.error().may_have_changed) return netlink_failure(acknowledged.error(), stage);
            auto checked = verify();
            if (!checked) return std::unexpected(checked.error());
            if (!acknowledged && acknowledged.error().rejected) return netlink_failure(acknowledged.error(), stage);
            if (!*checked) return tun_network_detail::fail(TunNetworkError::readback, stage);
            if (!acknowledged) ++status_.reconciled;
            return {};
        }
        auto complete(Clock::time_point deadline) -> std::expected<void, TunNetworkFailure> {
            using namespace platform::netlink_abi;
            auto owner = identity(deadline);
            if (!owner) return std::unexpected(owner.error());
            if (owner->mtu != options_.mtu || !(owner->flags & IFF_UP)) return tun_network_detail::fail(TunNetworkError::readback, TunNetworkStage::verify);
            std::array<bool, 16> address_seen{};
            std::array<bool, 64> route_seen{};
            bool correct = true;
            for (auto family : {std::uint8_t{4}, std::uint8_t{6}}) {
                auto scanned = view(deadline).addresses(family, [&](Address const &value) -> std::expected<void, platform::netlink::Failure> {
                    if (value.index != std::uint32_t(status_.ifindex)) return {};
                    bool matched = false;
                    for (std::size_t i = 0; i < options_.address_count; ++i)
                        if (addresses_[i] && value == *addresses_[i]) {
                            address_seen[i] = true;
                            matched = true;
                        }
                    correct &= matched;
                    return {};
                });
                if (!scanned) return netlink_failure(scanned.error(), TunNetworkStage::verify);
                scanned = view(deadline).routes(family, [&](Route const &value) -> std::expected<void, platform::netlink::Failure> {
                    if (value.index != std::uint32_t(status_.ifindex) || value.table != RT_TABLE_MAIN) return {};
                    bool matched = false;
                    for (std::size_t i = 0; i < options_.route_count; ++i)
                        if (routes_[i] && value == *routes_[i]) {
                            route_seen[i] = true;
                            matched = true;
                        }
                    correct &= matched;
                    return {};
                });
                if (!scanned) return netlink_failure(scanned.error(), TunNetworkStage::verify);
            }
            if (!correct || !std::ranges::all_of(std::span(address_seen).first(options_.address_count), [](bool value) { return value; }) ||
                !std::ranges::all_of(std::span(route_seen).first(options_.route_count), [](bool value) { return value; }))
                return tun_network_detail::fail(TunNetworkError::readback, TunNetworkStage::verify);
            return {};
        }
        auto install_addresses(Clock::time_point deadline) -> std::expected<void, TunNetworkFailure> {
            for (std::size_t i = 0; i < options_.address_count; ++i) {
                auto owner = identity(deadline);
                if (!owner) return std::unexpected(owner.error());
                auto checked = apply(tun_network_detail::address_request(status_.ifindex, options_.addresses[i], true), TunNetworkStage::address, deadline,
                                [&]() -> std::expected<bool, TunNetworkFailure> {
                                    auto found = view(deadline).address(options_.addresses[i]);
                                    if (!found) return netlink_failure(found.error(), TunNetworkStage::address);
                                    if (!*found || !desired(**found, options_.addresses[i])) return false;
                                    addresses_[i] = **found;
                                    return true;
                                }, &address_attempted_[i]);
                if (!checked) return checked;
                ++status_.addresses;
            }
            return {};
        }
        auto install_routes(Clock::time_point deadline) -> std::expected<void, TunNetworkFailure> {
            for (std::size_t i = 0; i < options_.route_count; ++i) {
                auto owner = identity(deadline);
                if (!owner) return std::unexpected(owner.error());
                auto conflict = view(deadline).route_conflict(options_.routes[i]);
                if (!conflict) return netlink_failure(conflict.error(), TunNetworkStage::route);
                if (*conflict) return tun_network_detail::fail(TunNetworkError::conflict, TunNetworkStage::route);
                auto checked = apply(tun_network_detail::route_request(status_.ifindex, options_.routes[i], true, source(options_.routes[i].family)), TunNetworkStage::route, deadline,
                                [&]() -> std::expected<bool, TunNetworkFailure> {
                                    auto found = view(deadline).route(options_.routes[i]);
                                    if (!found) return netlink_failure(found.error(), TunNetworkStage::route);
                                    if (!*found || !desired(**found, options_.routes[i])) return false;
                                    routes_[i] = **found;
                                    return true;
                                }, &route_attempted_[i]);
                if (!checked) return checked;
                ++status_.routes;
            }
            return {};
        }
        auto remove_snapshot(Clock::time_point deadline, bool keep_addresses) -> std::expected<void, TunNetworkFailure> {
            auto erase = [&]<bool RouteEntry>(std::size_t i) -> std::expected<void, TunNetworkFailure> {
                constexpr auto stage = RouteEntry ? TunNetworkStage::remove_route : TunNetworkStage::remove_address;
                auto const &entry = RouteEntry ? options_.routes[i] : options_.addresses[i];
                auto read = [&] {
                    if constexpr (RouteEntry) return view(deadline).route(entry);
                    else return view(deadline).address(entry);
                };
                auto owner = identity(deadline);
                if (!owner) return std::unexpected(owner.error());
                auto found = read();
                if (!found) return netlink_failure(found.error(), stage);
                if (!*found) return {};
                auto const &saved = [&]() -> auto const & {
                    if constexpr (RouteEntry) return routes_[i];
                    else return addresses_[i];
                }();
                if (!desired(**found, entry) || (saved && **found != *saved))
                    return tun_network_detail::fail(TunNetworkError::ownership, stage);
                auto request = RouteEntry
                    ? tun_network_detail::route_request(status_.ifindex, entry, false, source(entry.family))
                    : tun_network_detail::address_request(status_.ifindex, entry, false);
                return apply(std::move(request), stage, deadline, [&]() -> std::expected<bool, TunNetworkFailure> {
                    auto remaining = read();
                    if (!remaining) return netlink_failure(remaining.error(), stage);
                    return !*remaining;
                });
            };
            for (auto count = options_.route_count; count; --count) if (route_attempted_[count - 1]) {
                auto result = erase.template operator()<true>(count - 1);
                if (!result) return result;
            }
            if (keep_addresses) return {};
            for (auto count = options_.address_count; count; --count) if (address_attempted_[count - 1]) {
                auto result = erase.template operator()<false>(count - 1);
                if (!result) return result;
            }
            return {};
        }
        auto install_snapshot(TunNetworkOptions const &options, Clock::time_point deadline,
                              bool keep_addresses) -> std::expected<void, TunNetworkFailure> {
            options_ = options;
            routes_ = {};
            route_attempted_ = {};
            status_.routes = 0;
            std::expected<void, TunNetworkFailure> result;
            if (!keep_addresses) {
                addresses_ = {};
                address_attempted_ = {};
                status_.addresses = 0;
                result = install_addresses(deadline);
            }
            if (result) result = install_routes(deadline);
            if (result) result = complete(deadline);
            return result;
        }
        auto start_impl(Clock::time_point deadline) -> std::expected<void, TunNetworkFailure> {
            using namespace platform::netlink_abi;
            auto opened = socket_.open();
            if (!opened) return netlink_failure(opened.error(), TunNetworkStage::identify);
            auto checked = preflight(deadline);
            if (!checked) return checked;
            std::array<std::uint8_t, 16> random{};
            auto entropy = platform::secure_random(std::as_writable_bytes(std::span(random)));
            if (!entropy) return tun_network_detail::fail(TunNetworkError::entropy, TunNetworkStage::claim, entropy.error());
            constexpr std::string_view prefix = "nexus-", hex = "0123456789abcdef";
            std::ranges::copy(prefix, marker_.begin());
            for (std::size_t i = 0; i < random.size(); ++i) {
                marker_[prefix.size() + 2 * i] = hex[random[i] >> 4];
                marker_[prefix.size() + 2 * i + 1] = hex[random[i] & 15];
            }
            checked =
                apply(tun_network_detail::link_request(status_.ifindex, {}, marker(), {}, true), TunNetworkStage::claim, deadline, [&]() -> std::expected<bool, TunNetworkFailure> {
                    auto link = identity(deadline);
                    if (!link) return std::unexpected(link.error());
                    return link->ipv6_generation == IN6_ADDR_GEN_MODE_NONE && !(link->flags & IFF_UP);
                });
            if (!checked) return checked;
            claimed_ = true;
            checked = apply(tun_network_detail::link_request(status_.ifindex, options_.mtu), TunNetworkStage::mtu, deadline, [&]() -> std::expected<bool, TunNetworkFailure> {
                auto link = identity(deadline);
                if (!link) return std::unexpected(link.error());
                return link->mtu == options_.mtu && !(link->flags & IFF_UP);
            });
            if (!checked) return checked;
            checked = install_addresses(deadline);
            if (!checked) return checked;
            auto owner = identity(deadline);
            if (!owner) return std::unexpected(owner.error());
            checked = apply(tun_network_detail::link_request(status_.ifindex, {}, {}, true), TunNetworkStage::enable, deadline, [&]() -> std::expected<bool, TunNetworkFailure> {
                auto link = identity(deadline);
                if (!link) return std::unexpected(link.error());
                return link->mtu == options_.mtu && (link->flags & IFF_UP) && (options_.mtu < 1280 || link->ipv6_generation == IN6_ADDR_GEN_MODE_NONE);
            });
            if (!checked) return checked;
            checked = install_routes(deadline);
            if (!checked) return checked;
            checked = complete(deadline);
            if (!checked) return checked;
            status_.started = true;
            return {};
        }
        auto issue(TunNetworkError code, TunNetworkStage stage, std::error_code system = {}) noexcept -> void { cleanup_.add({code, stage, system}); }
        static auto validate_claim(LinuxTun::NetworkToken const& token,TunNetworkOptions const& options) -> std::expected<void,TunNetworkFailure> {
            if (!tun_network_detail::validate(options)) return tun_network_detail::fail(TunNetworkError::configuration,TunNetworkStage::validate);
            auto checked=token.inspect();
            if (!checked) return std::unexpected(TunNetworkFailure{.code=TunNetworkError::device,.stage=TunNetworkStage::identify,.device=checked.error()});
            return {};
        }

      public:
        class ConstructionKey {
            friend class TunNetworkLease;
            ConstructionKey() = default;

          public:
            ConstructionKey(ConstructionKey &&) = default;
        };
        TunNetworkLease(ConstructionKey, LinuxTun::NetworkToken token, TunNetworkOptions options) noexcept : token_(std::move(token)), options_(options) {}
        ~TunNetworkLease() {
            // Destruction always closes descriptors; checked cleanup belongs to
            // the caller's explicit deadline and must precede destruction.
            if (!status_.stopped) (void)stop(Clock::now());
        }
        TunNetworkLease(TunNetworkLease const &) = delete;
        auto operator=(TunNetworkLease const &) -> TunNetworkLease & = delete;
        TunNetworkLease(TunNetworkLease &&) = delete;
        auto operator=(TunNetworkLease &&) -> TunNetworkLease & = delete;
        [[nodiscard]] static auto create(LinuxTun &device, TunNetworkOptions options) -> std::expected<TunNetworkLease, TunNetworkFailure> {
            if (!tun_network_detail::validate(options)) return tun_network_detail::fail(TunNetworkError::configuration, TunNetworkStage::validate);
            auto token = device.claim_network();
            if (!token) return std::unexpected(TunNetworkFailure{.code = TunNetworkError::device, .stage = TunNetworkStage::identify, .device = token.error()});
            return std::expected<TunNetworkLease, TunNetworkFailure>(std::in_place, ConstructionKey{}, std::move(*token), options);
        }
        [[nodiscard]] static auto create(LinuxTun::NetworkToken token,TunNetworkOptions options) -> std::expected<TunNetworkLease,TunNetworkFailure> {
            auto checked=validate_claim(token,options); if (!checked) return std::unexpected(checked.error());
            return std::expected<TunNetworkLease,TunNetworkFailure>(std::in_place,ConstructionKey{},std::move(token),options);
        }
        [[nodiscard]] static auto emplace_into(std::optional<TunNetworkLease>& target,LinuxTun::NetworkToken token,TunNetworkOptions options)
            -> std::expected<void,TunNetworkFailure> {
            if (target) return tun_network_detail::fail(TunNetworkError::state,TunNetworkStage::validate);
            auto checked=validate_claim(token,options); if (!checked) return std::unexpected(checked.error());
            target.emplace(ConstructionKey{},std::move(token),options); return {};
        }
        [[nodiscard]] auto start(Clock::time_point deadline, Clock::time_point rollback_deadline) -> std::expected<void, TunNetworkFailure> {
            if (starting_ || status_.stopped) return tun_network_detail::fail(TunNetworkError::state, TunNetworkStage::validate);
            starting_ = true;
            auto result = start_impl(deadline);
            if (!result) (void)stop(rollback_deadline);
            return result;
        }
        // The single deadline is shared with rollback. Expiry can leave removal
        // unverified in cleanup(), while device/socket descriptors still close.
        [[nodiscard]] auto start(Clock::time_point deadline) -> std::expected<void, TunNetworkFailure> { return start(deadline,deadline); }
        // The caller keeps forwarding quiescent throughout replacement.
        // Recoverable failures restore the old snapshot on the same device.
        [[nodiscard]] auto replace(TunNetworkOptions const &next, Clock::time_point deadline,
                                   Clock::time_point rollback_deadline) -> std::expected<void, TunNetworkFailure> {
            if (!status_.started || status_.stopped) return tun_network_detail::fail(TunNetworkError::state, TunNetworkStage::validate);
            if (next.mtu != options_.mtu || !tun_network_detail::validate(next, true))
                return tun_network_detail::fail(TunNetworkError::configuration, TunNetworkStage::validate);
            auto intact = complete(deadline);
            if (!intact) return intact;
            auto previous = options_;
            if (next == previous) return {};
            bool keep_addresses = std::ranges::equal(std::span(previous.addresses).first(previous.address_count),
                std::span(next.addresses).first(next.address_count));
            auto result = remove_snapshot(deadline, keep_addresses);
            if (result) result = install_snapshot(next, deadline, keep_addresses);
            if (result) return {};

            bool cancellation_disabled = false;
            if constexpr (Socket::cancellable) cancellation_disabled = socket_.exchange_cancellation_disabled(true);
            auto restored = remove_snapshot(rollback_deadline, keep_addresses);
            if (restored) restored = install_snapshot(previous, rollback_deadline, keep_addresses);
            if (!restored) (void)stop(rollback_deadline);
            else if constexpr (Socket::cancellable) (void)socket_.exchange_cancellation_disabled(cancellation_disabled);
            return result;
        }
        // The data-plane borrower must be quiescent before this terminal call.
        // Always closes the owned nonpersistent device, including rollback.
        [[nodiscard]] auto stop(Clock::time_point deadline) noexcept -> TunCleanupReport {
            using namespace platform::netlink_abi;
            if (status_.stopped) return cleanup_;
            if constexpr(Socket::cancellable) socket_.disable_cancellation();
            status_.started = false;
            if (socket_.native_handle() >= 0 && claimed_) {
                auto visible = view(deadline).link();
                auto owner = identity(deadline);
                if (visible && !*visible) {
                } // The sole nonpersistent device was already closed or removed.
                else if (!owner)
                    issue(TunNetworkError::ownership, TunNetworkStage::disable, owner.error().system);
                else {
                    auto down = socket_.acknowledge(tun_network_detail::link_request(status_.ifindex, {}, {}, false), deadline);
                    if (!down) issue(TunNetworkError::netlink, TunNetworkStage::disable, down.error().system);
                    for (std::size_t count = options_.route_count; count; --count) {
                        auto i = count - 1;
                        if (!route_attempted_[i]) continue;
                        auto still = identity(deadline);
                        if (!still) {
                            issue(TunNetworkError::ownership, TunNetworkStage::remove_route, still.error().system);
                            break;
                        }
                        auto found = view(deadline).route(options_.routes[i]);
                        if (!found) {
                            issue(TunNetworkError::netlink, TunNetworkStage::remove_route, found.error().system);
                            continue;
                        }
                        if (!*found) continue;
                        if (!desired(**found, options_.routes[i]) || (routes_[i] && **found != *routes_[i])) {
                            issue(TunNetworkError::ownership, TunNetworkStage::remove_route);
                            continue;
                        }
                        auto removed =
                            socket_.acknowledge(tun_network_detail::route_request(status_.ifindex, options_.routes[i], false, source(options_.routes[i].family)), deadline);
                        auto remaining = view(deadline).route(options_.routes[i]);
                        if (!remaining || *remaining) issue(TunNetworkError::readback, TunNetworkStage::remove_route, removed ? std::error_code{} : removed.error().system);
                    }
                    for (std::size_t count = options_.address_count; count; --count) {
                        auto i = count - 1;
                        if (!address_attempted_[i]) continue;
                        auto still = identity(deadline);
                        if (!still) {
                            issue(TunNetworkError::ownership, TunNetworkStage::remove_address, still.error().system);
                            break;
                        }
                        auto found = view(deadline).address(options_.addresses[i]);
                        if (!found) {
                            issue(TunNetworkError::netlink, TunNetworkStage::remove_address, found.error().system);
                            continue;
                        }
                        if (!*found) continue;
                        if (!desired(**found, options_.addresses[i]) || (addresses_[i] && **found != *addresses_[i])) {
                            issue(TunNetworkError::ownership, TunNetworkStage::remove_address);
                            continue;
                        }
                        auto removed = socket_.acknowledge(tun_network_detail::address_request(status_.ifindex, options_.addresses[i], false), deadline);
                        auto remaining = view(deadline).address(options_.addresses[i]);
                        if (!remaining || *remaining) issue(TunNetworkError::readback, TunNetworkStage::remove_address, removed ? std::error_code{} : removed.error().system);
                    }
                }
            }
            cleanup_.device_closed = token_.close_device();
            if (!cleanup_.device_closed) issue(TunNetworkError::ownership, TunNetworkStage::close);
            if (socket_.native_handle() >= 0) {
                auto remaining = view(deadline).link(status_.ifindex>0 ? std::nullopt : std::optional{name()});
                cleanup_.device_removed = remaining && !*remaining;
                if (!cleanup_.device_removed) issue(TunNetworkError::readback, TunNetworkStage::close, remaining ? std::error_code{} : remaining.error().system);
            } else cleanup_.device_removed = cleanup_.device_closed;
            socket_.close();
            cleanup_.socket_closed = socket_.native_handle() < 0;
            status_.stopped = true;
            status_.addresses = status_.routes = 0;
            return cleanup_;
        }
        // Read-only identity proof for composed policy owners; no second device claim.
        [[nodiscard]] auto verified_device(Clock::time_point deadline) -> std::expected<Link,TunNetworkFailure> {
            if (!status_.started || status_.stopped) return tun_network_detail::fail(TunNetworkError::state,TunNetworkStage::identify);
            return identity(deadline);
        }
        // A composed policy enters terminal checked cleanup before the TUN
        // is removed. Signal cancellation no longer suppresses identity proof;
        // the original absolute rollback deadline still bounds every exchange.
        [[nodiscard]] auto verified_device_for_cleanup(Clock::time_point deadline) -> std::expected<Link,TunNetworkFailure> {
            if constexpr(Socket::cancellable) {
                auto previous=socket_.exchange_cancellation_disabled(true);
                struct Restore {Socket& socket;bool previous;~Restore(){(void)socket.exchange_cancellation_disabled(previous);}} restore{socket_,previous};
                return verified_device(deadline);
            } else return verified_device(deadline);
        }
        [[nodiscard]] auto network_options() const noexcept -> TunNetworkOptions const& {return options_;}
        [[nodiscard]] auto status() const noexcept -> TunNetworkStatus { return status_; }
        [[nodiscard]] auto cleanup() const noexcept -> TunCleanupReport { return cleanup_; }
        [[nodiscard]] auto drained() const noexcept -> bool { return status_.stopped && cleanup_.device_closed && cleanup_.device_removed && cleanup_.socket_closed; }
        [[nodiscard]] auto native_handle() const noexcept -> int { return token_.native_handle(); }
    };
} // namespace packet
