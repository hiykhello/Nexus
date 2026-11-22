// Included after the Tailscale device and proxy module imports.
class UserspaceLink final : public proxy::MeshLink {
    using Device = tailscale::wireguard_tun::Device;
    static constexpr std::size_t capacity = 64;
    mutable std::mutex mutex_;
    std::optional<Network> network_;
    std::optional<std::uint64_t> device_generation_;
    std::deque<std::vector<std::uint8_t>> outbound_, inbound_;
    std::uint64_t generation_ = 0;
    std::atomic_bool failed_{false};
public:
    auto network() const -> std::optional<Network> override {
        std::lock_guard lock(mutex_);
        return network_;
    }
    auto failed() const noexcept -> bool override { return failed_.load(std::memory_order_acquire); }
    auto failure() noexcept -> void { failed_.store(true,std::memory_order_release); }
    auto withdraw() noexcept -> void {
        std::lock_guard lock(mutex_);
        network_.reset();
        device_generation_.reset();
        outbound_.clear();
        inbound_.clear();
    }

    auto synchronize(Device& device) -> void {
        auto next=device.userspace_network();
        std::lock_guard lock(mutex_);
        if(!next || device_generation_!=next->revision) {
            inbound_.clear();
            outbound_.clear();
            network_.reset();
            device_generation_.reset();
            if(next) {
                device_generation_=next->revision;
                network_.emplace(Network{next->ipv4,next->ipv6,++generation_});
            }
        }
        if(!network_)return;
        for(unsigned count=0;count<16 && !outbound_.empty();++count) {
            (void)device.send_ip(outbound_.front());
            outbound_.pop_front();
        }
        for(unsigned count=0;count<16 && inbound_.size()<capacity;++count) {
            auto packet=device.receive_ip();
            if(!packet)break;
            inbound_.push_back(std::move(*packet));
        }
    }
    auto send(std::uint64_t revision,std::span<const std::uint8_t> packet) -> bool override {
        std::lock_guard lock(mutex_);
        if(!network_ || network_->revision!=revision || outbound_.size()==capacity)return false;
        outbound_.emplace_back(packet.begin(),packet.end());
        return true;
    }
    auto receive(std::uint64_t revision) -> std::optional<std::vector<std::uint8_t>> override {
        std::lock_guard lock(mutex_);
        if(!network_ || network_->revision!=revision || inbound_.empty()) return {};
        auto packet=std::move(inbound_.front());
        inbound_.pop_front();
        return packet;
    }
};

class OutboundLink final : public proxy::MeshLink {
    UserspaceLink link_;
    std::jthread thread_;
public:
    explicit OutboundLink(auto run) : thread_([this,run=std::move(run)](std::stop_token stop) mutable {
        try { if(run(stop,link_)!=0)link_.failure(); }
        catch(...) { link_.failure(); }
    }) {}
    auto network() const -> std::optional<Network> override {return link_.network();}
    auto failed() const noexcept -> bool override {return link_.failed();}
    auto send(std::uint64_t generation,std::span<const std::uint8_t> packet) -> bool override {
        return link_.send(generation,packet);
    }
    auto receive(std::uint64_t generation) -> std::optional<std::vector<std::uint8_t>> override {
        return link_.receive(generation);
    }
};
