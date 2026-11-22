module;
#include <cerrno>
#include <unistd.h>
module cli.masque_ip_server;
import std;
import config;
import masque.ip_control;
import masque.ip_server;
import packet.tun_linux;
import packet.tun_network;
import packet.tun_network_types;
import platform.ip_address;

namespace cli::masque_enabled {
    namespace {
        auto address(std::string_view text, bool route) noexcept -> std::optional<packet::TunAddress> {
            auto slash = text.find('/');
            if (route != (slash != text.npos)) return {};
            auto ip = platform::parse_ip_address(text.substr(0, slash));
            if (!ip) return {};
            unsigned bits = ip->size * 8;
            if (route) {
                auto [end, error] = std::from_chars(text.data() + slash + 1, text.data() + text.size(), bits);
                if (error != std::errc{} || end != text.data() + text.size() || bits > ip->size * 8) return {};
            }
            packet::TunAddress result{static_cast<std::uint8_t>(ip->size == 4 ? 4 : 6), ip->bytes,
                                      static_cast<std::uint8_t>(bits)};
            if (!packet::tun_network_detail::valid(result, route)) return {};
            return result;
        }

        class LinuxIpServerPort final : public masque::IpServerPort {
            using Clock = std::chrono::steady_clock;
            std::string name_;
            packet::TunNetworkOptions network_;
            std::vector<masque::AddressEntry> assigned_;
            std::vector<masque::RouteEntry> routes_;
            std::optional<packet::LinuxTun> tun_;
            std::optional<packet::TunNetworkLease<>> lease_;
            bool cleanup_failed_ = false;
        public:
            LinuxIpServerPort(std::string name, packet::TunNetworkOptions network,
                              std::vector<masque::AddressEntry> assigned, std::vector<masque::RouteEntry> routes)
                : name_(std::move(name)), network_(network), assigned_(std::move(assigned)), routes_(std::move(routes)) {}
            ~LinuxIpServerPort() override { close(); }

            auto open() noexcept -> bool override {
                if (tun_ || cleanup_failed_) return false;
                try {
                    auto device = packet::LinuxTun::create(name_);
                    if (!device) return false;
                    tun_.emplace(std::move(*device));
                    auto token = tun_->claim_network();
                    if (token && packet::TunNetworkLease<>::emplace_into(lease_, std::move(*token), network_)) {
                        auto deadline = Clock::now() + std::chrono::milliseconds(750);
                        if (lease_->start(deadline, deadline + std::chrono::seconds(1))) return true;
                    }
                } catch (...) {
                    close();
                    return false;
                }
                close();
                return false;
            }
            auto close() noexcept -> void override {
                if (lease_) {
                    auto result = lease_->stop(Clock::now() + std::chrono::seconds(2));
                    cleanup_failed_ |= result.total || !lease_->drained();
                    lease_.reset();
                }
                tun_.reset();
            }
            auto healthy() const noexcept -> bool override {return !cleanup_failed_;}
            auto read(std::span<std::uint8_t> bytes) noexcept -> std::optional<std::size_t> override {
                auto count = ::read(tun_->native_handle(), bytes.data(), bytes.size());
                if (count > 0) return static_cast<std::size_t>(count);
                if (count < 0 && (errno == EAGAIN || errno == EINTR)) return 0;
                return {};
            }
            auto write(std::span<std::uint8_t const> bytes) noexcept -> Write override {
                auto count = ::write(tun_->native_handle(), bytes.data(), bytes.size());
                if (count < 0 && (errno == EAGAIN || errno == EINTR)) return Write::blocked;
                return count == static_cast<std::ptrdiff_t>(bytes.size()) ? Write::sent : Write::failed;
            }
            auto addresses() const noexcept -> std::span<masque::AddressEntry const> override { return assigned_; }
            auto routes() const noexcept -> std::span<masque::RouteEntry const> override { return routes_; }
        };
    }

    auto make_ip_server_port(config::MasqueIpInbound const& options, config::MasqueInbound const& server) ->
        std::expected<std::unique_ptr<masque::IpServerPort>, std::string> {
        if (options.interface.size() > 15 || options.interface == "." || options.interface == ".." ||
            !std::ranges::all_of(options.interface, [](unsigned char c) {
                return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                       (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
            })) return std::unexpected("invalid CONNECT-IP server interface-name");
        packet::TunNetworkOptions network{.mtu = masque::IpServerPort::mtu};
        std::vector<masque::AddressEntry> assigned;
        std::vector<masque::RouteEntry> routes;
        for (auto const& text : options.local_addresses) {
            auto local = address(text, false);
            if (!local || (local->family == (server.listen_host.contains(':') ? 6 : 4) &&
                local->bytes == server.listen_address)) return std::unexpected("invalid CONNECT-IP local-address");
            network.addresses[network.address_count++] = *local;
        }
        auto local = std::span(network.addresses).first(network.address_count);
        for (auto const& text : options.client_addresses) {
            auto client = address(text, false);
            if (!client || std::ranges::find(assigned, client->family, &masque::AddressEntry::version) != assigned.end() ||
                std::ranges::count(local, client->family, &packet::TunAddress::family) != 1 ||
                std::ranges::find(local, *client) != local.end() ||
                (client->family == (server.listen_host.contains(':') ? 6 : 4) && client->bytes == server.listen_address))
                return std::unexpected("invalid or unpaired CONNECT-IP client-address");
            network.routes[network.route_count++] = *client;
            assigned.push_back({0, client->family, client->prefix, client->bytes});
        }
        std::array<bool, 2> route_family{};
        for (auto const& text : options.allowed_routes) {
            auto prefix = address(text, true);
            if (!prefix || std::ranges::find(assigned, prefix->family, &masque::AddressEntry::version) == assigned.end())
                return std::unexpected("CONNECT-IP allow-ip requires a numeric network with an assigned client address family");
            auto size = masque::ip_address_bytes(prefix->family);
            auto last = prefix->bytes;
            for (unsigned bit = prefix->prefix; bit < size * 8; ++bit)
                last[bit / 8] |= static_cast<std::uint8_t>(128 >> (bit % 8));
            routes.push_back({prefix->family, 0, prefix->bytes, last});
            route_family[prefix->family == 6] = true;
        }
        if (!packet::tun_network_detail::validate(network) ||
            std::ranges::any_of(assigned, [&](auto const& entry) { return !route_family[entry.version == 6]; }))
            return std::unexpected("invalid CONNECT-IP server network");
        return std::make_unique<LinuxIpServerPort>(options.interface, network, std::move(assigned), std::move(routes));
    }
}
