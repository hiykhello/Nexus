module masque.ip_server;
import std;
import containers.inplace_vector;
import masque.capsule;
import masque.connect_ip;
import masque.ip_control;
import masque.ip_packet;
import masque.ip_receiver;

namespace masque {
    struct IpServerStream::Impl {
        using Packet = containers::inplace_vector<std::uint8_t, ip_server_mtu>;
        IpServerPort& port_;
        ConnectIpScope scope_;
        IpReceiver<Impl, ip_server_mtu + 16, 2, 16, 8> incoming_{*this};
        static constexpr std::size_t max_configured_addresses = 2;
        std::array<AddressEntry, 8> assignments_{};
        std::size_t assignment_count_ = 0;
        std::array<RouteEntry, 16> routes_{};
        std::size_t route_count_ = 0;
        containers::inplace_vector<Packet, 8> ingress_;
        bool open_ = false, failed_ = false, assignments_pending_ = false, routes_pending_ = false, withdrawing_ = false;

        auto permits(std::span<std::uint8_t const> bytes, bool client_to_tun) const noexcept -> bool {
            auto packet = inspect_ip_packet(bytes);
            if (!packet || packet->fragmented || packet->routed || packet->source_override || !packet->hop_limit)
                return false;
            if (!client_to_tun) std::swap(packet->source, packet->destination);
            auto assigned = std::span(assignments_).first(assignment_count_);
            return std::ranges::any_of(assigned, [&](auto const& address) {
                return !address_rejection(address) && ip_prefix_contains(address, packet->version, packet->source);
            }) && ip_destination_advertised(*packet, std::span(routes_).first(route_count_));
        }

        template<class Entry, class Encode>
        auto control(std::span<std::uint8_t> output, std::uint64_t kind, std::span<Entry const> entries, Encode encode)
            -> std::size_t {
            std::array<std::uint8_t, 576> body;
            std::size_t size = 0;
            for (auto const& entry : entries) {
                auto count = encode(std::span(body).subspan(size), entry);
                if (!count) return 0;
                size += *count;
            }
            auto prefix = write_capsule_prefix(output, kind, size);
            if (!prefix || output.size() < *prefix + size) return 0;
            std::ranges::copy(std::span(body).first(size), output.begin() + *prefix);
            return *prefix + size;
        }

    public:
        Impl(IpServerPort& port, ConnectIpScope scope) : port_(port), scope_(std::move(scope)) {}
        ~Impl() { stop(); }

        auto start() noexcept -> bool {
            if (!port_ || scope_.kind == IpTargetKind::hostname || port_->addresses().size() > max_configured_addresses ||
                port_->routes().size() > routes_.size()) return false;
            route_count_ = 0;
            auto addresses = port_->addresses();
            for (auto const& configured : port_->routes()) {
                if (scope_.protocol && configured.protocol && configured.protocol != *scope_.protocol) continue;
                auto candidate = configured;
                if (scope_.protocol) candidate.protocol = *scope_.protocol;
                if (scope_.kind == IpTargetKind::prefix) {
                    if (scope_.prefix.version != candidate.version) continue;
                    auto last = scope_.prefix.address;
                    for (unsigned bit = scope_.prefix.prefix_length; bit < ip_address_bytes(candidate.version) * 8; ++bit)
                        last[bit / 8] |= static_cast<std::uint8_t>(128 >> (bit % 8));
                    candidate.first = std::max(candidate.first, scope_.prefix.address);
                    candidate.last = std::min(candidate.last, last);
                    if (candidate.last < candidate.first) continue;
                }
                routes_[route_count_++] = candidate;
            }
            std::ranges::sort(std::span(routes_).first(route_count_), [](RouteEntry const& a, RouteEntry const& b) noexcept {
                if (a.version != b.version) return a.version < b.version;
                if (a.protocol != b.protocol) return a.protocol < b.protocol;
                auto size = ip_address_bytes(a.version);
                auto af = std::span(a.first).first(size), bf = std::span(b.first).first(size);
                if (!std::ranges::equal(af, bf)) return std::lexicographical_compare(af.begin(), af.end(), bf.begin(), bf.end());
                auto al = std::span(a.last).first(size), bl = std::span(b.last).first(size);
                return std::lexicographical_compare(al.begin(), al.end(), bl.begin(), bl.end());
            });
            std::size_t merged = 0;
            for (std::size_t i = 0; i < route_count_; ++i) {
                auto const& next = routes_[i];
                auto size = ip_address_bytes(next.version);
                if (!size) { route_count_ = 0; return false; }
                auto nf = std::span(next.first).first(size), nl = std::span(next.last).first(size);
                if (merged && routes_[merged - 1].version == next.version && routes_[merged - 1].protocol == next.protocol) {
                    auto& prev = routes_[merged - 1];
                    auto pl = std::span(prev.last).first(size);
                    if (!std::lexicographical_compare(pl.begin(), pl.end(), nf.begin(), nf.end())) {
                        if (std::lexicographical_compare(pl.begin(), pl.end(), nl.begin(), nl.end()))
                            std::ranges::copy(nl, prev.last.begin());
                        continue;
                    }
                }
                routes_[merged++] = next;
            }
            route_count_ = merged;
            if (!route_count_ || addresses.empty() || !port_->open()) { route_count_ = 0; return false; }
            open_ = true;
            std::ranges::copy(addresses, assignments_.begin());
            assignment_count_ = addresses.size();
            assignments_pending_ = routes_pending_ = true;
            return true;
        }
        auto stop() noexcept -> void {
            if (std::exchange(open_, false)) port_->close();
            incoming_.stop();
            ingress_.clear();
        }
        auto active() const noexcept -> bool { return open_ && !failed_; }
        auto withdraw() noexcept -> void {
            if (!open_ || withdrawing_) return;
            withdrawing_ = true;
            ingress_.clear();
            route_count_ = assignment_count_ = 0;
            routes_pending_ = assignments_pending_ = true;
        }
        auto failed() const noexcept -> bool { return failed_; }
        auto permits_datagram(std::span<std::uint8_t const> bytes) const noexcept -> bool {
            return bytes.size() <= ip_server_mtu && permits(bytes, true);
        }
        auto feed(std::span<std::uint8_t const> bytes) noexcept -> bool {
            return withdrawing_ || (active() && incoming_.feed(bytes).status == IpReceiveStatus::active && !failed_);
        }
        auto datagram(std::span<std::uint8_t const> body) noexcept -> bool {
            return withdrawing_ || (active() && incoming_.datagram(body) == IpReceiveStatus::active && !failed_);
        }
        auto assigned(std::span<AddressEntry const> entries) noexcept -> bool { return entries.empty(); }
        auto routes(std::span<RouteEntry const> entries) noexcept -> bool { return entries.empty(); }
        auto requested(std::span<AddressEntry const> entries) noexcept -> bool {
            if (!port_ || withdrawing_) return false;
            auto const configured_addresses = port_->addresses();
            if (configured_addresses.size() > max_configured_addresses || assignment_count_ < configured_addresses.size())
                return false;
            std::array<AddressEntry, 8> next{};
            auto next_count = assignments_pending_ ? assignment_count_ : configured_addresses.size();
            std::ranges::copy(std::span(assignments_).first(next_count), next.begin());
            std::array<bool, max_configured_addresses> answered{};
            for (auto const& request : entries) {
                auto size = ip_address_bytes(request.version);
                if (!size) return false;
                auto configured = std::ranges::find(configured_addresses, request.version, &AddressEntry::version);
                if (configured == configured_addresses.end()) {
                    if (next_count >= next.size()) return false;
                    next[next_count++] = AddressEntry{request.request_id, request.version, static_cast<std::uint8_t>(size * 8), {}};
                    continue;
                }
                auto index = static_cast<std::size_t>(configured - configured_addresses.begin());
                if (index >= answered.size()) return false;
                auto& assignment = next[index];
                if (answered[index] || assignment.request_id ||
                    request.prefix_length > assignment.prefix_length ||
                    !ip_prefix_contains(request, assignment.version, assignment.address)) {
                    if (next_count >= next.size()) return false;
                    next[next_count++] = AddressEntry{request.request_id, request.version, static_cast<std::uint8_t>(size * 8), {}};
                    continue;
                }
                answered[index] = true;
                assignment.request_id = request.request_id;
            }
            assignments_ = next;
            assignment_count_ = next_count;
            assignments_pending_ = true;
            return true;
        }
        std::size_t uploaded_=0;
        auto take_uploaded() noexcept -> std::size_t {return std::exchange(uploaded_,0);}
        auto packet(std::span<std::uint8_t const> bytes) noexcept -> void {
            if (!active() || !permits_datagram(bytes)) return;
            if (ingress_.empty()) {
                auto result = port_->write(bytes);
                if (result == IpServerWrite::sent) {uploaded_+=bytes.size();return;}
                if (result == IpServerWrite::failed) { failed_ = true; return; }
            }
            if (ingress_.size() < ingress_.capacity()) ingress_.emplace_back(bytes.begin(), bytes.end());
        }
        auto poll() noexcept -> bool {
            while (!ingress_.empty()) {
                switch (port_->write(ingress_.front())) {
                case IpServerWrite::sent: uploaded_+=ingress_.front().size();ingress_.erase(ingress_.begin());break;
                case IpServerWrite::blocked: return true;
                case IpServerWrite::failed: failed_ = true; return false;
                }
            }
            return active();
        }
        auto output(std::span<std::uint8_t> output,std::size_t* payload_size) -> std::size_t {
            if (payload_size) *payload_size=0;
            if (!active()) return 0;
            if (std::exchange(assignments_pending_, false)) {
                auto written = control(output, address_assign_capsule, std::span<AddressEntry const>(assignments_).first(assignment_count_),
                    [](auto buffer, auto const& entry) { return write_address_entry(buffer, entry, false); });
                if (!written) failed_ = true;
                return written;
            }
            if (std::exchange(routes_pending_, false)) {
                auto written = control(output, route_advertisement_capsule, std::span<RouteEntry const>(routes_).first(route_count_),
                    write_route_entry);
                if (!written) failed_ = true;
                return written;
            }
            if (withdrawing_) return 0;
            std::array<std::uint8_t, ip_server_mtu + 1> bytes;
            for (unsigned i = 0; i < 8; ++i) {
                auto size = port_->read(bytes);
                if (!size) { failed_ = true; return 0; }
                if (!*size) return 0;
                if (*size > ip_server_mtu || !permits(std::span(bytes).first(*size), false)) continue;
                auto prefix = write_capsule_prefix(output, datagram_capsule_type, *size + 1);
                if (!prefix || output.size() < *prefix + 1 + *size) { failed_ = true; return 0; }
                output[*prefix] = 0;
                std::ranges::copy(std::span(bytes).first(*size), output.begin() + *prefix + 1);
                if (payload_size) *payload_size=*size;
                return *prefix + 1 + *size;
            }
            return 0;
        }
    };
    IpServerStream::IpServerStream(IpServerPort& port, ConnectIpScope scope) : impl_(new Impl(port, std::move(scope))) {}
    IpServerStream::~IpServerStream() = default;
    auto IpServerStream::start() noexcept -> bool { return impl_->start(); }
    auto IpServerStream::stop() noexcept -> void { impl_->stop(); }
    auto IpServerStream::withdraw() noexcept -> void { impl_->withdraw(); }
    auto IpServerStream::failed() const noexcept -> bool { return impl_->failed(); }
    auto IpServerStream::feed(std::span<std::uint8_t const> bytes) noexcept -> bool { return impl_->feed(bytes); }
    auto IpServerStream::datagram(std::span<std::uint8_t const> bytes) noexcept -> bool { return impl_->datagram(bytes); }
    auto IpServerStream::poll() noexcept -> bool { return impl_->poll(); }
    auto IpServerStream::take_uploaded() noexcept -> std::size_t {return impl_->take_uploaded();}
    auto IpServerStream::output(std::span<std::uint8_t> out,std::size_t* payload_size) -> std::size_t {
        return impl_->output(out,payload_size);
    }
}
