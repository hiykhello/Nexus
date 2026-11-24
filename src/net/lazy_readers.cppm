export module net.lazy_readers;
import std;
import capy;

export namespace net {
    // Fixed-target stream slots live with the association. Their indices are
    // stable for readers, and the slot is allocated only on first use.
    template<class Slot,class Peer,std::size_t Capacity>
    class FixedDatagramSlots {
        struct Entry {
            std::size_t route;
            Peer peer;
            Slot slot{};
            Entry(std::size_t index,Peer const& endpoint) : route(index),peer(endpoint) {}
        };
        std::array<std::unique_ptr<Entry>,Capacity> entries_{};
    public:
        auto select(std::size_t route,Peer const& peer) -> std::optional<std::size_t> {
            auto found=std::ranges::find_if(entries_,[&](auto const& entry) {
                return entry && entry->route==route && entry->peer==peer;
            });
            if (found==entries_.end()) {
                found=std::ranges::find_if(entries_,[](auto const& entry) {return !entry;});
                if (found==entries_.end()) return {};
                *found=std::make_unique<Entry>(route,peer);
            }
            return static_cast<std::size_t>(found-entries_.begin());
        }
        auto slot(std::size_t index) noexcept -> Slot& {return entries_[index]->slot;}
        auto peer(std::size_t index) const noexcept -> Peer const& {return entries_[index]->peer;}
        template<class Visit>
        auto for_each(Visit visit) noexcept -> void {
            for (auto const& entry:entries_) if (entry) visit(entry->slot);
        }
    };
    // One association/executor, at most one reader per physical slot. Each
    // request adds a structured when_all branch only when that slot is used.
    // Factory is copied into each manager frame, never borrowed from tasks().
    template<std::size_t Capacity>
    class LazyReaders {
        std::array<bool,Capacity> requested_{};
        std::array<bool,Capacity> started_{};
        capy::async_event changed_;
        bool stopped_=false;
    public:
        LazyReaders()=default;
        LazyReaders(LazyReaders const&)=delete;
        auto operator=(LazyReaders const&) -> LazyReaders& = delete;
        // A request can precede run(), and repeated publication after an XUDP
        // rotation reuses the already-started slot reader rather than spawning.
        [[nodiscard]] auto request(this LazyReaders& self,std::size_t index) noexcept -> bool {
            if(self.stopped_ || index>=Capacity)return false;
            if(self.started_[index] || self.requested_[index])return true;
            self.requested_[index]=true;self.changed_.set();return true;
        }
        auto stop(this LazyReaders& self) noexcept -> void {
            self.stopped_=true;self.changed_.set();
        }
        [[nodiscard]] auto stopped(this LazyReaders const& self) noexcept -> bool {return self.stopped_;}
        template<class Factory>
        auto run(this LazyReaders& self,Factory factory) -> capy::task<capy::results<>> {
            auto token=co_await capy::this_coro::stop_token;
            for(;;) {
                if(self.stopped_ || token.stop_requested())co_return capy::results<>{};
                for(std::size_t index=0;index<Capacity;++index)if(self.requested_[index]) {
                    self.requested_[index]=false;self.started_[index]=true;
                    // Both child frames are made before when_all publishes
                    // either. Its existing owner chain handles failed launch,
                    // sibling cancellation, and context abandonment.
                    auto reader=factory(index);
                    auto remaining=self.run(factory);
                    auto result=co_await capy::when_all(std::move(reader),std::move(remaining));
                    co_return capy::results<>{std::get<0>(result)};
                }
                self.changed_.clear();
                auto [error]=co_await self.changed_.wait();
                if(error)co_return capy::results<>{error};
            }
        }
    };
}
