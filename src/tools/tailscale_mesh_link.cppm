// Userspace WireGuard-over-DERP multi-worker mesh link adapters for Tailscale endpoints.
export module cli.tailscale_mesh_link;
import std;
import relay;
import tailscale.multi_worker;
import tailscale.wireguard_tun;

export namespace cli::tailscale_endpoint {
    class UserspaceLink {
        using Network = relay::MeshNetwork;
        using Device = tailscale::wireguard_tun::Device;
        using Hub = tailscale::MultiWorkerMeshHub;
        static constexpr std::size_t max_workers = 16;

        Hub hub_{max_workers};
        std::mutex slot_mutex_;
        std::array<bool, max_workers> slot_used_{};
    public:
        auto set_wake(void (*fn)(void*) noexcept, void* ctx) noexcept -> void {
            hub_.set_tx_wake(fn, ctx);
        }
        auto network() const -> std::optional<Network> {
            auto n = hub_.network();
            if (!n) return std::nullopt;
            return Network{n->ipv4, n->ipv6, n->revision};
        }
        auto failed() const noexcept -> bool { return hub_.failed(); }
        auto failure() noexcept -> void { hub_.mark_failed(); }
        auto withdraw() noexcept -> void { hub_.withdraw(); }

        auto bind_worker() -> std::optional<relay::MeshWorkerBinding> {
            std::size_t chosen = max_workers;
            {
                std::lock_guard lock(slot_mutex_);
                for (std::size_t i = 0; i < max_workers; ++i) {
                    if (!slot_used_[i]) {
                        slot_used_[i] = true;
                        chosen = i;
                        break;
                    }
                }
            }
            if (chosen == max_workers) return std::nullopt;
            if (!hub_.register_worker(chosen)) {
                std::lock_guard lock(slot_mutex_);
                slot_used_[chosen] = false;
                return std::nullopt;
            }
            auto range = Hub::port_range_for(chosen, max_workers);
            return relay::MeshWorkerBinding{chosen, range.begin, range.end};
        }

        auto unbind_worker(std::size_t worker_id) noexcept -> void {
            if (worker_id >= max_workers) return;
            hub_.unregister_worker(worker_id);
            std::lock_guard lock(slot_mutex_);
            slot_used_[worker_id] = false;
        }

        auto synchronize(Device& device) -> void {
            if (auto next = device.userspace_network()) {
                hub_.update_network(Hub::Network{next->ipv4, next->ipv6, next->revision});
            } else {
                hub_.update_network(std::nullopt);
            }
            if (!hub_.network()) return;
            for (unsigned count = 0; count < 32; ++count) {
                auto pkt = hub_.pop_outbound();
                if (!pkt) break;
                (void)device.send_ip(*pkt);
            }
            for (unsigned count = 0; count < 32; ++count) {
                auto packet = device.receive_ip();
                if (!packet) break;
                (void)hub_.dispatch_inbound(*packet);
            }
        }
        auto send(std::size_t worker_id, std::uint64_t revision, std::span<std::uint8_t const> packet) -> bool {
            return hub_.send_from_worker(worker_id, revision, packet);
        }
        auto receive(std::size_t worker_id, std::uint64_t revision) -> std::optional<std::vector<std::uint8_t>> {
            return hub_.receive_for_worker(worker_id, revision);
        }
    };

    class OutboundLink {
        using Network = relay::MeshNetwork;
        UserspaceLink link_;
        std::jthread thread_;
    public:
        explicit OutboundLink(auto run) : thread_([this, run = std::move(run)](std::stop_token stop) mutable {
            try { if (run(stop, link_) != 0) link_.failure(); }
            catch (...) { link_.failure(); }
        }) {}
        auto network() const -> std::optional<Network> { return link_.network(); }
        auto failed() const noexcept -> bool { return link_.failed(); }
        auto bind_worker() -> std::optional<relay::MeshWorkerBinding> { return link_.bind_worker(); }
        auto unbind_worker(std::size_t worker_id) noexcept -> void { link_.unbind_worker(worker_id); }
        auto send(std::size_t worker_id, std::uint64_t generation, std::span<std::uint8_t const> packet) -> bool {
            return link_.send(worker_id, generation, packet);
        }
        auto receive(std::size_t worker_id, std::uint64_t generation) -> std::optional<std::vector<std::uint8_t>> {
            return link_.receive(worker_id, generation);
        }
    };
}
