export module tailscale.multi_worker;
import std;
import tailscale.magic_dns;

export namespace tailscale {
    // Thread-safe multi-worker L3 packet router and MagicDNS holder for userspace
    // Tailscale outbounds. Eliminates single-worker contention by partitioning
    // ephemeral source-port ownership and tracking reverse 5-tuples per worker so
    // inbound replies always land in the exact originating worker's queue.
    struct MultiWorkerMeshHubOptions {
        static constexpr std::size_t default_outbound_cap = 2048;
        static constexpr std::size_t default_worker_rx_cap = 1024;
        static constexpr std::size_t default_max_tracked_flows = 65536;
        std::size_t outbound_cap = default_outbound_cap;
        std::size_t worker_rx_cap = default_worker_rx_cap;
        std::size_t max_flows = default_max_tracked_flows;
    };

    class MultiWorkerMeshHub {
    public:
        using Options = MultiWorkerMeshHubOptions;
        struct Network {
            std::optional<std::array<std::uint8_t, 4>> ipv4;
            std::optional<std::array<std::uint8_t, 16>> ipv6;
            std::uint64_t revision = 0;
        };

        struct PortRange {
            std::uint16_t begin = 1024;
            std::uint16_t end = 65535;
        };

        struct FlowKey {
            std::uint8_t family = 0;
            std::uint8_t protocol = 0;
            std::array<std::uint8_t, 16> remote_ip{};
            std::uint16_t local_port = 0;
            std::uint16_t remote_port = 0;
            auto operator==(FlowKey const&) const -> bool = default;
        };

        struct FlowKeyHash {
            auto operator()(FlowKey const& k) const noexcept -> std::size_t {
                std::size_t h = (std::size_t(k.family) << 24) ^ (std::size_t(k.protocol) << 16) ^
                                (std::size_t(k.local_port) << 1) ^ std::size_t(k.remote_port);
                for (std::size_t i = 0; i < (k.family == 4 ? 4u : 16u); ++i)
                    h = (h * 1315423911u) ^ k.remote_ip[i];
                return h;
            }
        };

        static constexpr std::size_t default_outbound_cap = Options::default_outbound_cap;
        static constexpr std::size_t default_worker_rx_cap = Options::default_worker_rx_cap;
        static constexpr std::size_t default_max_tracked_flows = Options::default_max_tracked_flows;
        static constexpr std::size_t max_queue_cap = 1u << 16;

        class PacketRing {
            std::vector<std::vector<std::uint8_t>> slots_;
            std::size_t limit_ = 0, mask_ = 0, head_ = 0, count_ = 0;
        public:
            explicit PacketRing(std::size_t cap = 0) noexcept : limit_(cap) {}
            auto set_limit(std::size_t cap) noexcept -> void { slots_.clear(); limit_ = cap; mask_ = head_ = count_ = 0; }
            [[nodiscard]] auto limit() const noexcept -> std::size_t { return limit_; }
            [[nodiscard]] auto ring_capacity() const noexcept -> std::size_t { return slots_.size(); }
            [[nodiscard]] auto size() const noexcept -> std::size_t { return count_; }
            [[nodiscard]] auto empty() const noexcept -> bool { return count_ == 0; }
            auto clear() noexcept -> void {
                for (std::size_t i = 0; i < count_; ++i) slots_[(head_ + i) & mask_].clear();
                head_ = count_ = 0;
            }
            auto push(std::span<std::uint8_t const> pkt) -> bool {
                if (count_ >= limit_) return false;
                if (slots_.empty()) {
                    auto sz = std::bit_ceil(std::max<std::size_t>(limit_, 2));
                    slots_.resize(sz);
                    mask_ = sz - 1;
                }
                auto& dst = slots_[(head_ + count_) & mask_];
                dst.assign(pkt.begin(), pkt.end());
                ++count_;
                return true;
            }
            auto pop() -> std::optional<std::vector<std::uint8_t>> {
                if (!count_) return std::nullopt;
                auto pkt = std::move(slots_[head_]);
                head_ = (head_ + 1) & mask_;
                --count_;
                return pkt;
            }
        };

        struct WorkerQueue {
            PacketRing inbound;
            void (*wake_fn)(void*) noexcept = nullptr;
            void* wake_ctx = nullptr;
            bool registered = false;
        };

    private:
        mutable std::mutex mutex_;
        std::size_t worker_count_ = 1;
        std::size_t outbound_cap_ = default_outbound_cap;
        std::size_t worker_rx_cap_ = default_worker_rx_cap;
        std::size_t max_tracked_flows_ = default_max_tracked_flows;
        std::vector<WorkerQueue> workers_;
        std::optional<Network> network_;
        std::optional<std::uint64_t> device_generation_;
        std::uint64_t revision_ = 0;
        PacketRing outbound_;
        std::unordered_map<FlowKey, std::size_t, FlowKeyHash> flow_owner_;
        std::deque<FlowKey> flow_order_;
        std::shared_ptr<magic_dns::Resolver> magic_dns_;
        std::atomic_bool failed_{false};
        void (*tx_wake_fn_)(void*) noexcept = nullptr;
        void* tx_wake_ctx_ = nullptr;

        static auto parse_flow(std::span<std::uint8_t const> packet, bool outbound) noexcept
            -> std::optional<FlowKey> {
            if (packet.size() < 20) return std::nullopt;
            std::uint8_t ver = packet[0] >> 4;
            FlowKey key{};
            std::size_t l4_off = 0;
            if (ver == 4) {
                std::size_t ihl = static_cast<std::size_t>(packet[0] & 0x0f) * 4u;
                if (ihl < 20 || packet.size() < ihl + 8) return std::nullopt;
                if ((packet[6] & 0x1fu) != 0 || packet[7] != 0) return std::nullopt;
                key.family = 4;
                key.protocol = packet[9];
                auto ip_off = outbound ? 16u : 12u;
                std::copy_n(packet.begin() + ip_off, 4, key.remote_ip.begin());
                l4_off = ihl;
            } else if (ver == 6) {
                if (packet.size() < 48) return std::nullopt;
                key.family = 6;
                key.protocol = packet[6];
                auto ip_off = outbound ? 24u : 8u;
                std::copy_n(packet.begin() + ip_off, 16, key.remote_ip.begin());
                l4_off = 40;
            } else {
                return std::nullopt;
            }
            if (key.protocol != 6 && key.protocol != 17) return std::nullopt;
            auto sport = static_cast<std::uint16_t>((std::uint16_t(packet[l4_off]) << 8) | packet[l4_off + 1]);
            auto dport = static_cast<std::uint16_t>((std::uint16_t(packet[l4_off + 2]) << 8) | packet[l4_off + 3]);
            if (!sport || !dport) return std::nullopt;
            key.local_port = outbound ? sport : dport;
            key.remote_port = outbound ? dport : sport;
            return key;
        }

        auto record_flow_locked(FlowKey const& key, std::size_t worker_id) -> void {
            auto [it, inserted] = flow_owner_.insert_or_assign(key, worker_id);
            if (!inserted) return;
            flow_order_.push_back(key);
            while (flow_order_.size() > max_tracked_flows_) {
                flow_owner_.erase(flow_order_.front());
                flow_order_.pop_front();
            }
        }

    public:
        explicit MultiWorkerMeshHub(std::size_t worker_count = 1,
                                    std::shared_ptr<magic_dns::Resolver> resolver = {},
                                    Options options = {})
            : worker_count_(std::max<std::size_t>(1, worker_count)),
              outbound_cap_(std::clamp<std::size_t>(options.outbound_cap, 1, max_queue_cap)),
              worker_rx_cap_(std::clamp<std::size_t>(options.worker_rx_cap, 1, max_queue_cap)),
              max_tracked_flows_(std::clamp<std::size_t>(options.max_flows, 1, 1u << 20)),
              workers_(worker_count_),
              outbound_(outbound_cap_),
              magic_dns_(resolver ? std::move(resolver) : std::make_shared<magic_dns::Resolver>()) {
            for (auto& w : workers_) w.inbound.set_limit(worker_rx_cap_);
        }

        [[nodiscard]] auto worker_count() const noexcept -> std::size_t { return worker_count_; }
        [[nodiscard]] auto outbound_cap() const noexcept -> std::size_t { return outbound_cap_; }
        [[nodiscard]] auto worker_rx_cap() const noexcept -> std::size_t { return worker_rx_cap_; }
        [[nodiscard]] auto max_tracked_flows() const noexcept -> std::size_t { return max_tracked_flows_; }

        [[nodiscard]] auto magic_dns() const noexcept -> std::shared_ptr<magic_dns::Resolver> {
            return magic_dns_;
        }

        // Disjoint ephemeral source-port partition per worker so concurrent workers
        // never collide on local ports when multiplexing over one tailnet IP.
        [[nodiscard]] static auto port_range_for(std::size_t worker_id, std::size_t worker_count) noexcept
            -> PortRange {
            constexpr std::uint32_t base = 10000;
            constexpr std::uint32_t span = 50000; // [10000, 60000)
            auto n = std::max<std::size_t>(1, worker_count);
            auto idx = worker_id % n;
            auto stride = std::max<std::uint32_t>(1, span / static_cast<std::uint32_t>(n));
            auto start = base + static_cast<std::uint32_t>(idx) * stride;
            auto stop = (idx + 1 == n) ? (base + span - 1) : (start + stride - 1);
            return {static_cast<std::uint16_t>(start), static_cast<std::uint16_t>(stop)};
        }

        [[nodiscard]] auto owner_of_local_port(std::uint16_t local_port) const noexcept
            -> std::optional<std::size_t> {
            constexpr std::uint32_t base = 10000;
            constexpr std::uint32_t span = 50000;
            if (local_port < base || local_port >= base + span) return std::nullopt;
            auto stride = std::max<std::uint32_t>(1, span / static_cast<std::uint32_t>(worker_count_));
            auto idx = static_cast<std::size_t>((local_port - base) / stride);
            return std::min(idx, worker_count_ - 1);
        }

        auto register_worker(std::size_t worker_id, void (*wake_fn)(void*) noexcept = nullptr,
                             void* wake_ctx = nullptr) -> bool {
            std::lock_guard lock(mutex_);
            if (worker_id >= workers_.size()) return false;
            workers_[worker_id].registered = true;
            workers_[worker_id].wake_fn = wake_fn;
            workers_[worker_id].wake_ctx = wake_ctx;
            return true;
        }

        auto unregister_worker(std::size_t worker_id) noexcept -> void {
            std::lock_guard lock(mutex_);
            if (worker_id >= workers_.size()) return;
            workers_[worker_id].registered = false;
            workers_[worker_id].wake_fn = nullptr;
            workers_[worker_id].wake_ctx = nullptr;
            workers_[worker_id].inbound.clear();
        }

        auto set_tx_wake(void (*fn)(void*) noexcept, void* ctx) noexcept -> void {
            std::lock_guard lock(mutex_);
            tx_wake_fn_ = fn;
            tx_wake_ctx_ = ctx;
        }

        auto mark_failed() noexcept -> void { failed_.store(true, std::memory_order_release); }
        [[nodiscard]] auto failed() const noexcept -> bool { return failed_.load(std::memory_order_acquire); }

        auto update_network(std::optional<Network> const& device_net) -> void {
            std::lock_guard lock(mutex_);
            if (!device_net || device_generation_ != device_net->revision) {
                outbound_.clear();
                flow_owner_.clear();
                flow_order_.clear();
                for (auto& w : workers_) w.inbound.clear();
                network_.reset();
                device_generation_.reset();
                if (device_net) {
                    device_generation_ = device_net->revision;
                    network_.emplace(Network{device_net->ipv4, device_net->ipv6, ++revision_});
                }
            }
        }

        auto withdraw() noexcept -> void {
            std::lock_guard lock(mutex_);
            network_.reset();
            device_generation_.reset();
            outbound_.clear();
            flow_owner_.clear();
            flow_order_.clear();
            for (auto& w : workers_) w.inbound.clear();
        }

        [[nodiscard]] auto network() const -> std::optional<Network> {
            std::lock_guard lock(mutex_);
            return network_;
        }

        // Called concurrently by worker threads to submit an inner IP packet.
        [[nodiscard]] auto send_from_worker(std::size_t worker_id, std::uint64_t revision,
                                            std::span<std::uint8_t const> packet) -> bool {
            std::lock_guard lock(mutex_);
            if (worker_id >= workers_.size() || !network_ || network_->revision != revision)
                return false;
            if (!outbound_.push(packet)) return false;
            if (auto flow = parse_flow(packet, true)) record_flow_locked(*flow, worker_id);
            if (tx_wake_fn_) tx_wake_fn_(tx_wake_ctx_);
            return true;
        }

        // Called by the Tailscale device I/O thread to drain outbound packets.
        [[nodiscard]] auto pop_outbound() -> std::optional<std::vector<std::uint8_t>> {
            std::lock_guard lock(mutex_);
            return outbound_.pop();
        }

        // Called by the Tailscale device I/O thread to route an inbound decrypted IP packet
        // to the exact owning worker's RX queue.
        auto dispatch_inbound(std::span<std::uint8_t const> packet) -> bool {
            std::lock_guard lock(mutex_);
            if (!network_) return false;
            std::optional<std::size_t> target;
            if (auto flow = parse_flow(packet, false)) {
                if (auto it = flow_owner_.find(*flow); it != flow_owner_.end()) {
                    target = it->second;
                } else {
                    target = owner_of_local_port(flow->local_port);
                }
            }
            if (!target && worker_count_ == 1) target = 0;
            if (!target || *target >= workers_.size()) return false;
            auto& q = workers_[*target];
            if (!q.inbound.push(packet)) return false;
            if (q.wake_fn) q.wake_fn(q.wake_ctx);
            return true;
        }

        // Called concurrently by each worker thread to consume ONLY its own packets.
        [[nodiscard]] auto receive_for_worker(std::size_t worker_id, std::uint64_t revision)
            -> std::optional<std::vector<std::uint8_t>> {
            std::lock_guard lock(mutex_);
            if (worker_id >= workers_.size() || !network_ || network_->revision != revision)
                return std::nullopt;
            return workers_[worker_id].inbound.pop();
        }
    };
}
