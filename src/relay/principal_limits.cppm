export module relay.principal_limits;
import std;
import relay.session_quota;
import net.principal_bytes;

export namespace relay {
    using net::PrincipalBytes;
    enum class PrincipalResource { connection, stream };
    struct PrincipalLimits {
        std::string name;
        std::size_t connections=std::numeric_limits<std::size_t>::max();
        std::size_t streams=std::numeric_limits<std::size_t>::max();
        PrincipalBytes::Limits bytes;
    };
    struct PrincipalUsage {
        std::size_t connections, streams;
        std::uint64_t rejected_connections, rejected_streams;
    };

    class PrincipalBudget {
        struct Counters {
            SessionQuota connections{0}, streams{0};
            PrincipalBytes bytes;
            std::atomic<std::uint64_t> rejected_connections{0}, rejected_streams{0};
        };
        friend class PrincipalRegistry;
        PrincipalLimits limits_;
        std::shared_ptr<Counters> counters_;
        SessionQuota connections_, streams_;

        PrincipalBudget(PrincipalLimits limits,std::shared_ptr<Counters> counters) noexcept;
    public:
        [[nodiscard]] auto limits() const noexcept -> PrincipalLimits const& {return limits_;}
        [[nodiscard]] auto acquire(PrincipalResource resource) const noexcept -> std::optional<SessionQuota::Lease>;
        [[nodiscard]] auto usage() const noexcept -> PrincipalUsage;
        [[nodiscard]] auto bytes() const noexcept -> PrincipalBytes const& {return counters_->bytes;}
        auto publish_bytes(std::chrono::steady_clock::time_point now) const noexcept -> void {
            counters_->bytes.publish(limits_.bytes,now);
        }
    };

    class PrincipalPolicy {
        friend class PrincipalRegistry;
        std::vector<PrincipalBudget> entries_;
    public:
        [[nodiscard]] auto entries() const noexcept -> std::span<PrincipalBudget const> {return entries_;}
        [[nodiscard]] auto find(std::string_view user) const noexcept -> PrincipalBudget const*;
    };

    // Only the listener coordinator stages policy. Active and retired policies
    // retain counters for principals still represented by a listener.
    class PrincipalRegistry {
        struct Entry {
            std::string inbound, user;
            std::weak_ptr<PrincipalBudget::Counters> counters;
        };
        std::vector<Entry> entries_;
    public:
        [[nodiscard]] auto prepare(std::string_view inbound,std::span<PrincipalLimits const> policy)
            -> std::shared_ptr<PrincipalPolicy const>;
    };
}

module :private;

namespace relay {
    PrincipalBudget::PrincipalBudget(PrincipalLimits limits,std::shared_ptr<Counters> counters) noexcept
        : limits_(std::move(limits)),counters_(std::move(counters)),
          connections_(counters_->connections.with_limit(limits_.connections)),
          streams_(counters_->streams.with_limit(limits_.streams)) {}

    auto PrincipalBudget::acquire(PrincipalResource resource) const noexcept -> std::optional<SessionQuota::Lease> {
        bool connection=resource==PrincipalResource::connection;
        auto const& quota=connection ? connections_ : streams_;
        auto lease=quota.try_acquire();
        if (!lease) {
            auto& rejected=connection ? counters_->rejected_connections : counters_->rejected_streams;
            rejected.fetch_add(1,std::memory_order_relaxed);
        }
        return lease;
    }

    auto PrincipalBudget::usage() const noexcept -> PrincipalUsage {
        return {connections_.used(),streams_.used(),counters_->rejected_connections.load(std::memory_order_relaxed),
            counters_->rejected_streams.load(std::memory_order_relaxed)};
    }

    auto PrincipalPolicy::find(std::string_view user) const noexcept -> PrincipalBudget const* {
        auto name=[](PrincipalBudget const& entry) -> std::string_view {return entry.limits().name;};
        auto found=std::ranges::lower_bound(entries_,user,{},name);
        if (found==entries_.end() || name(*found)!=user) return nullptr;
        return &*found;
    }

    auto PrincipalRegistry::prepare(std::string_view inbound,std::span<PrincipalLimits const> policy)
        -> std::shared_ptr<PrincipalPolicy const> {
        if (policy.empty()) return {};
        std::erase_if(entries_,[](Entry const& entry) {return entry.counters.expired();});
        auto snapshot=std::make_shared<PrincipalPolicy>();
        snapshot->entries_.reserve(policy.size());
        for (auto const& limits : policy) {
            auto existing=std::ranges::find_if(entries_,[&](Entry const& entry) {
                return entry.inbound==inbound && entry.user==limits.name;
            });
            auto counters=existing==entries_.end() ? nullptr : existing->counters.lock();
            if (!counters) {
                counters=std::make_shared<PrincipalBudget::Counters>();
                if (existing==entries_.end()) entries_.push_back({std::string(inbound),limits.name,counters});
                else existing->counters=counters;
            }
            snapshot->entries_.push_back(PrincipalBudget(limits,std::move(counters)));
        }
        std::ranges::sort(snapshot->entries_,{},[](PrincipalBudget const& item) -> std::string_view {
            return item.limits().name;
        });
        return snapshot;
    }
}
