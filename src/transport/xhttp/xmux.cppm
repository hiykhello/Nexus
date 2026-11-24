export module xhttp.xmux;
import std;
import xhttp.config;

export namespace xhttp {
    class Mux {
    public:
        using Clock=std::chrono::steady_clock;
        struct Ticket {
            std::size_t slot;
            std::uint64_t generation;
            auto operator==(Ticket const&) const -> bool = default;
        };
        struct Selection {Ticket ticket;bool create;};

    private:
        struct Connection {
            Clock::time_point born={};
            std::uint64_t generation=0;
            std::uint32_t sessions=0,requests=0;
            std::uint16_t active=0;
            bool live=false,draining=false;
        };
        MuxLimits limits_;
        std::vector<Connection> slots_;

        [[nodiscard]] auto lookup(Ticket ticket) noexcept -> Connection* {
            if (ticket.slot>=slots_.size()) return nullptr;
            auto& item=slots_[ticket.slot];
            return item.live && item.generation==ticket.generation ? &item : nullptr;
        }
        [[nodiscard]] auto aged(Connection const& item,Clock::time_point now) const noexcept -> bool {
            auto lifetime=now-item.born;
            return (limits_.lifetime_ms && lifetime>=std::chrono::milliseconds(limits_.lifetime_ms)) ||
                (limits_.reusable_seconds && lifetime>=std::chrono::seconds(limits_.reusable_seconds));
        }
        auto refresh(Connection& item,Clock::time_point now) const noexcept -> void {
            if (aged(item,now) || (limits_.requests && item.requests>=limits_.requests)) item.draining=true;
        }
        auto admit(std::size_t index,bool create) noexcept -> Selection {
            auto& item=slots_[index];
            ++item.active;
            if (item.sessions<std::numeric_limits<std::uint32_t>::max()) ++item.sessions;
            return {{index,item.generation},create};
        }

    public:
        explicit Mux(MuxLimits limits):limits_(limits),slots_(limits.valid() ? limits.connections : 0) {}
        template<class Match>
        auto acquire(Clock::time_point now,Match const& matches) noexcept -> std::optional<Selection> {
            std::optional<std::size_t> best,empty;
            for (std::size_t i=0;i<slots_.size();++i) {
                auto& item=slots_[i];
                if (!item.live) {
                    if (!empty && item.generation!=std::numeric_limits<std::uint64_t>::max()) empty=i;
                    continue;
                }
                refresh(item,now);
                if (!item.draining && matches(i) && item.active<limits_.concurrency &&
                    (!limits_.reuse_times || item.sessions<=limits_.reuse_times) &&
                    (!best || item.active<slots_[*best].active)) best=i;
            }
            if (best) return admit(*best,false);
            if (!empty) return {};
            auto& item=slots_[*empty];
            item=Connection{.born=now,.generation=item.generation+1,.live=true};
            return admit(*empty,true);
        }
        auto acquire(Clock::time_point now) noexcept -> std::optional<Selection> {
            return acquire(now,[](std::size_t) noexcept {return true;});
        }
        auto idle(Ticket ticket) noexcept -> bool {
            auto* item=lookup(ticket);
            return item && !item->active;
        }
        auto request(Ticket ticket,Clock::time_point now) noexcept -> bool {
            auto* item=lookup(ticket);
            if (!item || !item->active) return false;
            refresh(*item,now);
            if (item->draining) return false;
            if (item->requests<std::numeric_limits<std::uint32_t>::max()) ++item->requests;
            return true;
        }
        auto release(Ticket ticket) noexcept -> bool {
            auto* item=lookup(ticket);
            if (!item || !item->active) return false;
            --item->active;
            return true;
        }
        auto retire(Ticket ticket) noexcept -> bool {
            auto* item=lookup(ticket);
            if (!item) return false;
            item->draining=true;
            return true;
        }
        [[nodiscard]] auto reclaimable(Ticket ticket,Clock::time_point now) noexcept -> bool {
            auto* item=lookup(ticket);
            if (!item) return false;
            refresh(*item,now);
            return !item->active && (item->draining || (limits_.reuse_times && item->sessions>limits_.reuse_times));
        }
        auto remove(Ticket ticket) noexcept -> bool {
            auto* item=lookup(ticket);
            if (!item || item->active) return false;
            item->live=false;
            return true;
        }
    };
}
