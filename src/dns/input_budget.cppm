export module dns.input_budget;
import std;

export namespace dns {
    // Atomic byte reservations; each instance covers a specified class of
    // DNS objects. It must outlive all leases borrowed from it.
    class InputBudget {
        std::atomic<std::size_t> used_{0};
        std::size_t limit_;
    public:
        class Lease {
            InputBudget* budget_;
            std::size_t bytes_;
            friend class InputBudget;
            Lease(InputBudget& budget,std::size_t bytes) noexcept :budget_(&budget),bytes_(bytes) {}
        public:
            Lease(Lease const&)=delete;
            auto operator=(Lease const&) -> Lease& = delete;
            Lease(Lease&& other) noexcept :budget_(std::exchange(other.budget_,nullptr)),bytes_(other.bytes_) {}
            auto operator=(Lease&& other) noexcept -> Lease& {
                if(this!=&other) {
                    if(budget_)budget_->used_.fetch_sub(bytes_,std::memory_order_release);
                    budget_=std::exchange(other.budget_,nullptr);bytes_=other.bytes_;
                }
                return *this;
            }
            ~Lease(){if(budget_)budget_->used_.fetch_sub(bytes_,std::memory_order_release);}
        };
        explicit InputBudget(std::size_t limit) noexcept :limit_(limit) {}
        InputBudget(InputBudget const&)=delete;
        auto operator=(InputBudget const&) -> InputBudget& = delete;
        [[nodiscard]] auto acquire(std::size_t bytes) noexcept -> std::optional<Lease> {
            auto used=used_.load(std::memory_order_relaxed);
            for(;;) {
                if(bytes>limit_ || used>limit_-bytes)return {};
                if(used_.compare_exchange_weak(used,used+bytes,std::memory_order_acquire,std::memory_order_relaxed))
                    return Lease(*this,bytes);
            }
        }
        [[nodiscard]] auto used() const noexcept -> std::size_t {return used_.load(std::memory_order_acquire);}
        [[nodiscard]] auto limit() const noexcept -> std::size_t {return limit_;}
    };
    // One budget shared by all DNS UDP and TCP listeners and workers.
    inline auto default_input_budget() noexcept -> InputBudget& {
        static InputBudget budget(32*1024*1024);
        return budget;
    }
    // Separate from the raw input buffers and from in-flight query copies.
    inline auto default_listener_query_budget() noexcept -> InputBudget& {
        static InputBudget budget(32*1024*1024);
        return budget;
    }
    // Reservations for copies made to override the upstream ECS view.
    inline auto default_message_override_budget() noexcept -> InputBudget& {
        static InputBudget budget(32*1024*1024);
        return budget;
    }
    // Raw upstream UDP/TCP response buffers, shared across all workers.
    inline auto default_upstream_receive_budget() noexcept -> InputBudget& {
        static InputBudget budget(32*1024*1024);
        return budget;
    }
    // Parsed responses retained by serial DNS rule walks across async queries.
    inline auto default_serial_response_budget() noexcept -> InputBudget& {
        static InputBudget budget(32*1024*1024);
        return budget;
    }
    // Completed message race results waiting for publication or selection.
    inline auto default_message_race_result_budget() noexcept -> InputBudget& {
        static InputBudget budget(32*1024*1024);
        return budget;
    }
    // Address race results until the rule program and selected result finish.
    inline auto default_address_race_result_budget() noexcept -> InputBudget& {
        static InputBudget budget(32*1024*1024);
        return budget;
    }
}
