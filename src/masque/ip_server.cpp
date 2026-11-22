module masque.ip_server;
import std;
import masque.capsule;
import masque.connect_ip;
import masque.ip_control;
import masque.ip_packet;
import masque.ip_receiver;

namespace masque {
    struct IpServerStream::Impl {
        using Packet = std::inplace_vector<std::uint8_t, IpServerPort::mtu>;
        IpServerPort& port_;
        ConnectIpScope scope_;
        IpReceiver<Impl, IpServerPort::mtu + 16, 2, 16, 8> incoming_{*this};
        std::array<AddressEntry, 2> assignments_{};
        std::size_t assignment_count_ = 0;
        std::array<RouteEntry, 16> routes_{};
        std::size_t route_count_ = 0;
        std::inplace_vector<Packet, 8> ingress_;
        bool open_ = false, failed_ = false, assignments_pending_ = false, routes_pending_ = false, withdrawing_ = false;

        auto permits(std::span<std::uint8_t const> bytes, bool client_to_tun) const noexcept -> bool {
            auto packet = inspect_ip_packet(bytes);
            if (!packet || packet->fragmented || packet->routed || packet->source_override || !packet->hop_limit)
                return false;
            if (!client_to_tun) std::swap(packet->source, packet->destination);
            auto assigned = std::span(assignments_).first(assignment_count_);
            return std::ranges::any_of(assigned, [&](auto const& address) {
                return !address_rejection(address) && address.version == packet->version && address.address == packet->source;
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
            if (scope_.kind == IpTargetKind::hostname || port_.addresses().size() > assignments_.size() ||
                port_.routes().size() > routes_.size()) return false;
            auto addresses = port_.addresses();
            for (auto const& configured : port_.routes()) {
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
            if (!route_count_ || addresses.empty() || !port_.open()) return false;
            open_ = true;
            std::ranges::copy(addresses, assignments_.begin());
            assignment_count_ = addresses.size();
            assignments_pending_ = routes_pending_ = true;
            return true;
        }
        auto stop() noexcept -> void {
            if (std::exchange(open_, false)) port_.close();
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
            return bytes.size() <= IpServerPort::mtu && permits(bytes, true);
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
            std::array<bool, 2> answered{};
            for (auto const& request : entries) {
                auto configured = std::ranges::find(port_.addresses(), request.version, &AddressEntry::version);
                if (configured == port_.addresses().end()) return false;
                auto index = static_cast<std::size_t>(configured - port_.addresses().begin());
                auto& assignment = assignments_[index];
                if (std::exchange(answered[index], true) || assignment.request_id ||
                    request.prefix_length > assignment.prefix_length ||
                    !ip_prefix_contains(request, assignment.version, assignment.address)) return false;
                assignment.request_id = request.request_id;
            }
            assignments_pending_ = true;
            return true;
        }
        std::size_t uploaded_=0;
        auto take_uploaded() noexcept -> std::size_t {return std::exchange(uploaded_,0);}
        auto packet(std::span<std::uint8_t const> bytes) noexcept -> void {
            if (!active() || !permits_datagram(bytes)) return;
            if (ingress_.empty()) {
                auto result = port_.write(bytes);
                if (result == IpServerPort::Write::sent) {uploaded_+=bytes.size();return;}
                if (result == IpServerPort::Write::failed) { failed_ = true; return; }
            }
            if (ingress_.size() < ingress_.capacity()) ingress_.emplace_back(bytes.begin(), bytes.end());
        }
        auto poll() noexcept -> bool {
            while (!ingress_.empty()) {
                switch (port_.write(ingress_.front())) {
                case IpServerPort::Write::sent: uploaded_+=ingress_.front().size();ingress_.erase(ingress_.begin());break;
                case IpServerPort::Write::blocked: return true;
                case IpServerPort::Write::failed: failed_ = true; return false;
                }
            }
            return active();
        }
        auto output(std::span<std::uint8_t> output,std::size_t* payload_size) -> std::size_t {
            if (payload_size) *payload_size=0;
            if (!active()) return 0;
            if (std::exchange(assignments_pending_, false))
                return control(output, address_assign_capsule, std::span<AddressEntry const>(assignments_).first(assignment_count_),
                    [](auto buffer, auto const& entry) { return write_address_entry(buffer, entry, false); });
            if (std::exchange(routes_pending_, false))
                return control(output, route_advertisement_capsule, std::span<RouteEntry const>(routes_).first(route_count_),
                    write_route_entry);
            if (withdrawing_) return 0;
            std::array<std::uint8_t, IpServerPort::mtu + 1> bytes;
            for (unsigned i = 0; i < 8; ++i) {
                auto size = port_.read(bytes);
                if (!size) { failed_ = true; return 0; }
                if (!*size) return 0;
                if (*size > IpServerPort::mtu || !permits(std::span(bytes).first(*size), false)) continue;
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
