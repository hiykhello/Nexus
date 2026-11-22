export module dns.evaluate_race;
import std;

export namespace dns {
    // Synchronous scheduling core for one DNS question. The caller owns all
    // query tasks and response data, and evaluates predicates on judge events.
    // Publish all completions observed in one executor wake, then poll. Ready
    // races are judged in rule order within that batch. Resolve each judge
    // before scanning later rules.
    // Every evaluate gets a distinct ticket, including anonymous generations.
    template<std::size_t Queries=32,std::size_t Races=64>
    class EvaluateRace {
        static_assert(Queries>0 && Races>0);
    public:
        struct Ticket {std::size_t index;std::uint64_t generation;auto operator==(Ticket const&) const -> bool = default;};
        enum class Error {invalid_state,capacity,stale_ticket,duplicate_completion};
        enum class Kind {scan,judge,wait,proceed,commit};
        struct Event {Kind kind;std::size_t rule=0;std::optional<Ticket> response;bool failed=false;};
    private:
        struct Query {std::uint64_t generation=0;bool used=false,ready=false,failed=false;};
        struct Armed {std::size_t rule=0;std::optional<Ticket> response;std::uint64_t order=0;bool used=false;};
        std::array<Query,Queries> queries_{};
        std::array<Armed,Races> races_{};
        std::uint64_t generation_=0,armed_=0;
        std::optional<std::size_t> judging_;
        std::optional<Event> held_,winner_;
        bool terminal_=false;
        [[nodiscard]] auto query(Ticket ticket) noexcept -> Query* {
            if(ticket.index>=Queries)return nullptr;
            auto& item=queries_[ticket.index];
            return item.used && item.generation==ticket.generation ? &item : nullptr;
        }
        [[nodiscard]] auto pending_races() const noexcept -> bool {
            return std::ranges::any_of(races_,[](auto const& item){return item.used;});
        }
    public:
        // Tickets are deliberately not recycled while the walk is alive:
        // armed rules may still reference an earlier anonymous generation.
        [[nodiscard]] auto start() noexcept -> std::expected<Ticket,Error> {
            if(terminal_ || held_ || judging_)return std::unexpected(Error::invalid_state);
            if(generation_==std::numeric_limits<std::uint64_t>::max())return std::unexpected(Error::capacity);
            auto found=std::ranges::find_if(queries_,[](auto const& item){return !item.used;});
            if(found==queries_.end())return std::unexpected(Error::capacity);
            found->used=true;found->generation=++generation_;
            return Ticket{static_cast<std::size_t>(found-queries_.begin()),found->generation};
        }
        [[nodiscard]] auto complete(Ticket ticket,bool failed=false) noexcept -> std::expected<void,Error> {
            if(terminal_)return std::unexpected(Error::invalid_state);
            auto* item=query(ticket);if(!item)return std::unexpected(Error::stale_ticket);
            if(item->ready)return std::unexpected(Error::duplicate_completion);
            item->ready=true;item->failed=failed;return {};
        }
        // A missing response is a settled unknown, not a pending task.
        [[nodiscard]] auto arm(std::size_t rule,std::optional<Ticket> response) noexcept -> std::expected<void,Error> {
            if(terminal_ || held_ || judging_)return std::unexpected(Error::invalid_state);
            if(response && !query(*response))return std::unexpected(Error::stale_ticket);
            if(armed_==std::numeric_limits<std::uint64_t>::max())return std::unexpected(Error::capacity);
            auto found=std::ranges::find_if(races_,[](auto const& item){return !item.used;});
            if(found==races_.end())return std::unexpected(Error::capacity);
            *found={rule,response,++armed_,true};return {};
        }
        // Hold a matched non-race terminal action, or a non-speculative
        // evaluate, until earlier races settle. A speculative terminal route
        // may already be running; its ticket is preserved. A speculative
        // evaluate instead starts a ticket and continues scanning directly.
        // Nonterminal evaluate produces proceed, allowing the scan to resume.
        [[nodiscard]] auto hold(std::size_t rule,std::optional<Ticket> speculative={},bool terminal=true) noexcept -> std::expected<void,Error> {
            if(terminal_ || held_ || judging_)return std::unexpected(Error::invalid_state);
            if(speculative && !query(*speculative))return std::unexpected(Error::stale_ticket);
            held_=Event{terminal ? Kind::commit : Kind::proceed,rule,speculative,false};return {};
        }
        [[nodiscard]] auto poll() noexcept -> std::expected<Event,Error> {
            if(terminal_ || judging_)return std::unexpected(Error::invalid_state);
            if(winner_) {terminal_=true;return *winner_;}
            std::optional<std::size_t> selected;
            std::uint64_t first_order=std::numeric_limits<std::uint64_t>::max();
            for(std::size_t i=0;i<Races;++i) {
                auto const& race=races_[i];if(!race.used)continue;
                auto* value=race.response ? query(*race.response) : nullptr;
                if(value && !value->ready)continue;
                if(!selected || race.order<first_order) {
                    selected=i;first_order=race.order;
                }
            }
            if(selected) {
                judging_=*selected;auto const& race=races_[*selected];
                auto* value=race.response ? query(*race.response) : nullptr;
                return Event{Kind::judge,race.rule,race.response,!value || value->failed};
            }
            if(held_) {
                if(pending_races())return Event{Kind::wait};
                auto event=*held_;held_.reset();
                if(event.kind==Kind::commit)terminal_=true;
                return event;
            }
            return Event{Kind::scan};
        }
        // Only an explicit yes wins. No and unknown both retire this rule.
        [[nodiscard]] auto judged(bool matched) noexcept -> std::expected<void,Error> {
            if(!judging_ || terminal_)return std::unexpected(Error::invalid_state);
            auto& race=races_[*judging_];
            if(matched)winner_=Event{Kind::commit,race.rule,race.response,false};
            race.used=false;judging_.reset();return {};
        }
    };
}
