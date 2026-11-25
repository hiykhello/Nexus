export module net.connection_pool;
import std;

export namespace net {
    using PoolClock=std::chrono::steady_clock;
    enum class PoolError { closed,full,exhausted,invalid };
    struct PoolOptions {
        std::size_t max_sessions=64,min_idle=0;
        std::chrono::milliseconds idle_timeout{30000},check_interval{30000};
        auto valid() const noexcept -> bool {
            return max_sessions && max_sessions<=256 && min_idle<=max_sessions &&
                idle_timeout>=std::chrono::milliseconds(1) && idle_timeout<=std::chrono::hours(24) &&
                check_interval>=std::chrono::milliseconds(1) && check_interval<=std::chrono::hours(24);
        }
    };
    // A worker owns this pool and all its connections. Leases only borrow;
    // they cannot outlive the pool. Connection supplies usable(), cancel()
    // and drained(). A retired connection is destroyed only after its I/O
    // root has drained. The host stops and drains before destroying the pool.
    struct EmptyLeaseCount {};
    template<class Connection,bool Shared=false>
    class ConnectionPool {
        struct Entry {
            std::unique_ptr<Connection> connection;
            std::uint64_t sequence;
            PoolClock::time_point idle_since;
            std::conditional_t<Shared,std::uint16_t,bool> leased=0;
            bool retiring=false;
        };
        PoolOptions options_;
        std::vector<std::unique_ptr<Entry>> entries_;
        std::size_t creating_=0;
        std::uint64_t next_sequence_=1;
        bool closed_=false;
        [[no_unique_address]] std::conditional_t<Shared,std::size_t,EmptyLeaseCount> leases_{};
        auto retire(Entry& entry) noexcept -> void {
            if (entry.retiring) return;
            entry.retiring=true; entry.connection->cancel();
        }
        auto release(Entry& entry,PoolClock::time_point now) noexcept -> void {
            if constexpr(Shared){--entry.leased;--leases_;if(!entry.leased)entry.idle_since=now;}
            else{entry.leased=false;entry.idle_since=now;}
            if (closed_ || !entry.connection->usable()) retire(entry);
            if constexpr (requires(Connection& value) { { value.released() } noexcept; }) entry.connection->released();
        }
    public:
        class Lease {
            friend class ConnectionPool;
            ConnectionPool* pool_=nullptr;
            Entry* entry_=nullptr;
            Lease(ConnectionPool& pool,Entry& entry) noexcept : pool_(&pool),entry_(&entry) {
                if constexpr(Shared){++entry.leased;++pool.leases_;}else entry.leased=true;
                if constexpr (requires(Connection& value) { { value.acquired() } noexcept; }) entry.connection->acquired();
            }
        public:
            Lease(Lease const&)=delete;
            auto operator=(Lease const&) -> Lease& = delete;
            Lease(Lease&& other) noexcept : pool_(std::exchange(other.pool_,nullptr)),entry_(other.entry_) {}
            auto operator=(Lease&& other) noexcept -> Lease& {
                if (this!=&other) { reset(); pool_=std::exchange(other.pool_,nullptr); entry_=other.entry_; } return *this;
            }
            ~Lease() { reset(); }
            auto connection() const noexcept -> Connection& { return *entry_->connection; }
            auto sequence() const noexcept -> std::uint64_t { return entry_->sequence; }
            auto reset(PoolClock::time_point now=PoolClock::now()) noexcept -> void {
                if (pool_) { pool_->release(*entry_,now); pool_=nullptr; }
            }
        };
        class Creation {
            friend class ConnectionPool;
            ConnectionPool* pool_=nullptr;
            explicit Creation(ConnectionPool& pool) noexcept : pool_(&pool) { ++pool.creating_; }
        public:
            Creation(Creation const&)=delete;
            auto operator=(Creation const&) -> Creation& = delete;
            Creation(Creation&& other) noexcept : pool_(std::exchange(other.pool_,nullptr)) {}
            auto operator=(Creation&& other) noexcept -> Creation& {
                if (this!=&other) { reset(); pool_=std::exchange(other.pool_,nullptr); } return *this;
            }
            ~Creation() { reset(); }
            auto reset() noexcept -> void { if (pool_) { --pool_->creating_; pool_=nullptr; } }
            // Commit only a fully authenticated, usable connection. Startup
            // owns cancellation/drain when authentication fails instead.
            auto commit(std::unique_ptr<Connection>&& connection,PoolClock::time_point now=PoolClock::now())
                -> std::expected<Lease,PoolError> {
                if (!pool_ || !connection || !connection->usable()) return std::unexpected(PoolError::invalid);
                auto& pool=*pool_;
                if (pool.closed_) return std::unexpected(PoolError::closed);
                if (!pool.next_sequence_) return std::unexpected(PoolError::exhausted);
                auto entry=std::make_unique<Entry>(nullptr,pool.next_sequence_,now);
                auto* accepted=entry.get();
                pool.entries_.push_back(std::move(entry));
                accepted->connection=std::move(connection);
                ++pool.next_sequence_; reset();
                return Lease(pool,*accepted);
            }
        };
        explicit ConnectionPool(PoolOptions options) : options_(options) {
            if (!options.valid()) throw std::invalid_argument("invalid connection pool limits");
            entries_.reserve(options.max_sessions);
        }
        ConnectionPool(ConnectionPool const&)=delete;
        auto operator=(ConnectionPool const&) -> ConnectionPool& = delete;
        auto acquire() noexcept -> std::optional<Lease> {
            if (closed_) return {};
            if constexpr(Shared)if(leases_+creating_>=options_.max_sessions)return {};
            Entry* selected=nullptr;
            for (auto& owned:entries_) {
                auto& entry=*owned;
                if (!entry.connection->usable()) { retire(entry); continue; }
                bool available;
                if constexpr(Shared)available=entry.connection->available();else available=!entry.leased;
                if (available && !entry.retiring && (!selected || selected->sequence<entry.sequence)) selected=&entry;
            }
            if (!selected) return {};
            return Lease(*this,*selected);
        }
        auto active_count() const noexcept -> std::size_t {
            return static_cast<std::size_t>(std::ranges::count_if(entries_,[](auto const& entry) {
                return !entry->retiring;
            }));
        }
        auto reserve() noexcept -> std::expected<Creation,PoolError> {
            if (closed_) return std::unexpected(PoolError::closed);
            if (!next_sequence_) return std::unexpected(PoolError::exhausted);
            if constexpr(Shared)if(leases_+creating_>=options_.max_sessions)return std::unexpected(PoolError::full);
            if (active_count()+creating_>=options_.max_sessions) return std::unexpected(PoolError::full);
            return Creation(*this);
        }
        auto idle_count() const noexcept -> std::size_t {
            return std::ranges::count_if(entries_,[](auto const& entry) {
                return !entry->leased && !entry->retiring && entry->connection->usable();
            });
        }
        auto prewarm_needed() const noexcept -> std::size_t {
            if (closed_) return 0;
            auto available=idle_count()+creating_;
            auto deficit=available<options_.min_idle ? options_.min_idle-available : 0;
            auto active=active_count();
            if constexpr(Shared)return std::min({deficit,options_.max_sessions-std::min(options_.max_sessions,active+creating_),
                options_.max_sessions-std::min(options_.max_sessions,leases_+creating_)});
            return std::min(deficit,options_.max_sessions-std::min(options_.max_sessions,active+creating_));
        }
        auto reap(PoolClock::time_point now,bool maintain_min_idle=true) noexcept -> void {
            auto idle=idle_count();
            auto minimum=maintain_min_idle ? options_.min_idle : 0;
            for (auto& owned:entries_) {
                auto& entry=*owned;
                if (!entry.connection->usable()) retire(entry);
                if (!entry.leased && !entry.retiring && idle>minimum && now>=entry.idle_since && now-entry.idle_since>=options_.idle_timeout) {
                    retire(entry); --idle;
                }
            }
            std::erase_if(entries_,[](auto const& entry) { return !entry->leased && entry->retiring && entry->connection->drained(); });
        }
        auto stop() noexcept -> void {
            closed_=true;
            for (auto& entry:entries_) {
                if constexpr (requires(Connection& connection) {{connection.stop()} noexcept;}) entry->connection->stop();
                retire(*entry);
            }
        }
        auto drained() const noexcept -> bool {
            return !creating_ && std::ranges::all_of(entries_,[](auto const& entry) { return !entry->leased && entry->connection->drained(); });
        }
        auto size() const noexcept -> std::size_t { return entries_.size(); }
        auto options() const noexcept -> PoolOptions const& { return options_; }
    };
}
