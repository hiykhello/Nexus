// Per-worker direct TCP buffer pool, splice pipe pool, and zero-timer yield.
#pragma once

    class DirectBufferPool {
    public:
        static constexpr std::size_t kBufferSize = 128 * 1024;
        static constexpr std::size_t kMaxBuffers = 32;
        static constexpr auto kIdleTtl = std::chrono::seconds(5);

        class Lease {
            DirectBufferPool* pool_ = nullptr;
            std::unique_ptr<std::uint8_t[]> data_;
        public:
            Lease() noexcept = default;
            Lease(DirectBufferPool* pool, std::unique_ptr<std::uint8_t[]> data) noexcept
                : pool_(pool), data_(std::move(data)) {}
            Lease(Lease const&) = delete;
            auto operator=(Lease const&) -> Lease& = delete;
            Lease(Lease&& other) noexcept
                : pool_(std::exchange(other.pool_, nullptr)), data_(std::move(other.data_)) {}
            auto operator=(Lease&& other) noexcept -> Lease& {
                if (this != &other) {
                    reset();
                    pool_ = std::exchange(other.pool_, nullptr);
                    data_ = std::move(other.data_);
                }
                return *this;
            }
            ~Lease() { reset(); }
            auto reset() noexcept -> void {
                if (data_) {
                    if (pool_) pool_->release(std::move(data_));
                    else data_.reset();
                }
                pool_ = nullptr;
            }
            explicit operator bool() const noexcept { return static_cast<bool>(data_); }
            auto data() noexcept -> std::uint8_t* { return data_.get(); }
            static constexpr auto size() noexcept -> std::size_t { return kBufferSize; }
        };

    private:
        struct Entry {
            std::unique_ptr<std::uint8_t[]> data;
            Clock::time_point idle_since{};
        };
        std::vector<Entry> free_;
        std::size_t in_use_ = 0;

        auto release(std::unique_ptr<std::uint8_t[]> data) noexcept -> void {
            if (in_use_) --in_use_;
            if (free_.size() < kMaxBuffers) {
                try {
                    free_.push_back({std::move(data), Clock::now()});
                    return;
                } catch (...) {}
            }
        }

    public:
        DirectBufferPool() = default;
        DirectBufferPool(DirectBufferPool const&) = delete;
        auto operator=(DirectBufferPool const&) -> DirectBufferPool& = delete;

        auto try_acquire() noexcept -> Lease {
            if (!free_.empty()) {
                auto data = std::move(free_.back().data);
                free_.pop_back();
                ++in_use_;
                return Lease(this, std::move(data));
            }
            if (in_use_ >= kMaxBuffers) return {};
            auto data = std::unique_ptr<std::uint8_t[]>(new (std::nothrow) std::uint8_t[kBufferSize]);
            if (!data) return {};
            ++in_use_;
            return Lease(this, std::move(data));
        }

        auto reap(Clock::time_point now) noexcept -> void {
            if (free_.empty()) return;
            std::erase_if(free_, [now](Entry const& entry) {
                return now - entry.idle_since >= kIdleTtl;
            });
        }

        auto clear() noexcept -> void {
            free_.clear();
        }
    };

    class SplicePipePool {
    public:
        static constexpr std::size_t kTargetPipeSize = 256 * 1024;
        static constexpr auto kIdleTtl = std::chrono::seconds(2);

        struct Pipe {
            int fd[2]{-1, -1};
            std::size_t capacity = 64 * 1024;
            [[nodiscard]] auto valid() const noexcept -> bool { return fd[0] >= 0 && fd[1] >= 0; }
        };

    private:
        struct Entry {
            Pipe pipe;
            Clock::time_point idle_since{};
        };
        std::vector<Entry> free_;

    public:
        SplicePipePool() = default;
        SplicePipePool(SplicePipePool const&) = delete;
        auto operator=(SplicePipePool const&) -> SplicePipePool& = delete;
        ~SplicePipePool() { clear(); }

        auto acquire() noexcept -> Pipe;
        auto release(Pipe pipe, bool clean, std::size_t max_cached, Clock::time_point now) noexcept -> void;
        auto reap(Clock::time_point now) noexcept -> void;
        auto clear() noexcept -> void;
    };

    struct YieldToExecutor {
        capy::continuation cont{};
        auto await_ready() const noexcept -> bool { return false; }
        template<class Context>
        auto await_suspend(std::coroutine_handle<> handle, Context const* context) noexcept
            -> std::coroutine_handle<> {
            cont.h = handle;
            context->executor.post(cont);
            return std::noop_coroutine();
        }
        auto await_resume() const noexcept -> void {}
    };
