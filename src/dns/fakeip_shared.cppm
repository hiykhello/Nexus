export module nexus.dns.fakeip_shared;
import std;
import nexus.dns.fakeip;
import nexus.dns.fakeip_response;
import nexus.dns.fakeip_target;
import nexus.dns.fakeip_registry;
export namespace nexus::dns {
    // A single mutex serializes registry and pool operations across workers.
    // Handles retain the state; each individual handle still has one owner.
    class FakeIpShared {
        struct State {
            // Destroyed after the registry, including while handles retain State.
            std::shared_ptr<void> lifetime;
            std::mutex mutex;
            FakeIpRegistry registry;
            std::size_t ranges=0;
            bool sealed=false;
            explicit State(std::size_t limit,std::shared_ptr<void> owner) : lifetime(std::move(owner)),registry(limit) {}
        };
        std::shared_ptr<State> state_;
    public:
        class Response {
            std::shared_ptr<State> state_;
            std::unique_ptr<FakeIpResponse> response_;
            Response(std::shared_ptr<State> state,std::unique_ptr<FakeIpResponse> response)
                : state_(std::move(state)),response_(std::move(response)) {}
            friend class FakeIpShared;
        public:
            // Do not access the same handle concurrently. The bytes must stay
            // alive and unmodified until transport has completed.
            [[nodiscard]] auto wire() const noexcept -> std::span<std::uint8_t const> { return response_->wire(); }
            [[nodiscard]] auto finish(bool possibly_sent,std::chrono::steady_clock::time_point now)
                -> std::expected<void,FakeIpError> {
                std::lock_guard guard(state_->mutex);
                return response_->finish(possibly_sent,now);
            }
            [[nodiscard]] auto finish(bool possibly_sent) -> std::expected<void,FakeIpError> {
                std::lock_guard guard(state_->mutex);
                return response_->finish(possibly_sent,std::chrono::steady_clock::now());
            }
        };
        class Target {
            std::shared_ptr<State> state_;
            std::unique_ptr<FakeIpTarget> target_;
            Target(std::shared_ptr<State> state,std::unique_ptr<FakeIpTarget> target)
                : state_(std::move(state)),target_(std::move(target)) {}
            friend class FakeIpShared;
        public:
            [[nodiscard]] auto mapping() const noexcept -> FakeIpMapping const& { return target_->mapping(); }
            [[nodiscard]] auto release(std::chrono::steady_clock::time_point now)
                -> std::expected<void,FakeIpTargetError> {
                std::lock_guard guard(state_->mutex);
                return target_->release(now);
            }
            [[nodiscard]] auto release() -> std::expected<void,FakeIpTargetError> {
                std::lock_guard guard(state_->mutex);
                return target_->release(std::chrono::steady_clock::now());
            }
        };
        explicit FakeIpShared(std::size_t limit,std::shared_ptr<void> lifetime={})
            : state_(std::make_shared<State>(limit,std::move(lifetime))) {}
        FakeIpShared(FakeIpShared const&)=delete;
        auto operator=(FakeIpShared const&) -> FakeIpShared& = delete;
        // Reserve an entire historical or otherwise unusable range without
        // allocating a pool. It remains blocked for this state's lifetime.
        [[nodiscard]] auto reserve(std::uint32_t first,std::uint32_t last)
            -> std::expected<void,FakeIpRegistryError> {
            std::lock_guard guard(state_->mutex);
            if (state_->sealed) return std::unexpected(FakeIpRegistryError::sealed);
            auto result=state_->registry.add(first,last,nullptr);
            if (result) ++state_->ranges;
            return result;
        }
        [[nodiscard]] auto add(std::uint32_t first,std::uint32_t last,std::uint32_t alloc_first,
            std::uint32_t alloc_last,std::chrono::seconds ttl,std::chrono::seconds grace)
            -> std::expected<void,FakeIpRegistryError> {
            auto pool=FakeIpPool::create(alloc_first,alloc_last,ttl,grace);
            if (!pool) return std::unexpected(FakeIpRegistryError::invalid);
            std::lock_guard guard(state_->mutex);
            if (state_->sealed) return std::unexpected(FakeIpRegistryError::sealed);
            auto result=state_->registry.add(first,last,std::move(*pool));
            if (result) ++state_->ranges;
            return result;
        }
        [[nodiscard]] auto add_quarantined(std::uint32_t first,std::uint32_t last,
            std::uint32_t alloc_first,std::uint32_t alloc_last,std::chrono::seconds ttl,std::chrono::seconds grace,
            std::chrono::steady_clock::time_point start,std::chrono::steady_clock::duration interval)
            -> std::expected<void,FakeIpRegistryError> {
            std::lock_guard guard(state_->mutex);
            if (state_->sealed) return std::unexpected(FakeIpRegistryError::sealed);
            auto result=state_->registry.add_quarantined(first,last,alloc_first,alloc_last,ttl,grace,start,interval);
            if (result) ++state_->ranges;
            return result;
        }
        [[nodiscard]] auto add_quarantined(std::uint32_t first,std::uint32_t last,
            std::uint32_t alloc_first,std::uint32_t alloc_last,std::chrono::seconds ttl,std::chrono::seconds grace,
            std::chrono::steady_clock::duration interval) -> std::expected<void,FakeIpRegistryError> {
            std::lock_guard guard(state_->mutex);
            if (state_->sealed) return std::unexpected(FakeIpRegistryError::sealed);
            auto result=state_->registry.add_quarantined(first,last,alloc_first,alloc_last,ttl,grace,
                                                         std::chrono::steady_clock::now(),interval);
            if (result) ++state_->ranges;
            return result;
        }
        // Irreversible for this state. Register all protected ranges first.
        [[nodiscard]] auto seal() -> std::expected<void,FakeIpRegistryError> {
            std::lock_guard guard(state_->mutex);
            if (!state_->ranges) return std::unexpected(FakeIpRegistryError::invalid);
            state_->sealed=true;
            return {};
        }
        [[nodiscard]] auto sealed() const -> bool {
            std::lock_guard guard(state_->mutex); return state_->sealed;
        }
        [[nodiscard]] auto retire(std::uint32_t first) -> std::expected<void,FakeIpRegistryError> {
            std::lock_guard guard(state_->mutex); return state_->registry.retire(first);
        }
        [[nodiscard]] auto contains(std::uint32_t address) const -> std::expected<bool,FakeIpRegistryError> {
            std::lock_guard guard(state_->mutex);
            if (!state_->sealed) return std::unexpected(FakeIpRegistryError::unsealed);
            return state_->registry.contains(address);
        }
        [[nodiscard]] auto respond(std::uint32_t first,std::span<std::uint8_t const> query,std::uint64_t view,
            std::chrono::steady_clock::time_point now)
            -> std::expected<std::unique_ptr<Response>,std::variant<FakeIpRegistryError,FakeIpDnsError>> {
            std::lock_guard guard(state_->mutex);
            if (!state_->sealed) return std::unexpected(std::variant<FakeIpRegistryError,FakeIpDnsError>{FakeIpRegistryError::unsealed});
            auto response=state_->registry.respond(first,query,view,now);
            if (!response) return std::unexpected(response.error());
            return std::unique_ptr<Response>(new Response(state_,std::move(*response)));
        }
        // Clock sampling under the lock avoids reversing samples between workers.
        [[nodiscard]] auto respond(std::uint32_t first,std::span<std::uint8_t const> query,std::uint64_t view)
            -> std::expected<std::unique_ptr<Response>,std::variant<FakeIpRegistryError,FakeIpDnsError>> {
            std::lock_guard guard(state_->mutex);
            if (!state_->sealed) return std::unexpected(std::variant<FakeIpRegistryError,FakeIpDnsError>{FakeIpRegistryError::unsealed});
            auto response=state_->registry.respond(first,query,view,std::chrono::steady_clock::now());
            if (!response) return std::unexpected(response.error());
            return std::unique_ptr<Response>(new Response(state_,std::move(*response)));
        }
        [[nodiscard]] auto acquire(std::uint32_t address,std::uint64_t view,std::chrono::steady_clock::time_point now)
            -> std::expected<std::unique_ptr<Target>,FakeIpRegistryError> {
            std::lock_guard guard(state_->mutex);
            if (!state_->sealed) return std::unexpected(FakeIpRegistryError::unsealed);
            auto target=state_->registry.acquire(address,view,now);
            if (!target) return std::unexpected(target.error());
            if (!*target) return std::unique_ptr<Target>{};
            return std::unique_ptr<Target>(new Target(state_,std::move(*target)));
        }
        [[nodiscard]] auto acquire(std::uint32_t address,std::uint64_t view)
            -> std::expected<std::unique_ptr<Target>,FakeIpRegistryError> {
            std::lock_guard guard(state_->mutex);
            if (!state_->sealed) return std::unexpected(FakeIpRegistryError::unsealed);
            auto target=state_->registry.acquire(address,view,std::chrono::steady_clock::now());
            if (!target) return std::unexpected(target.error());
            if (!*target) return std::unique_ptr<Target>{};
            return std::unique_ptr<Target>(new Target(state_,std::move(*target)));
        }
    };
}
