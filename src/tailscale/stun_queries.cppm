export module tailscale.stun_queries;
export import tailscale.stun;
import std;

export namespace tailscale::stun {
    using Clock=std::chrono::steady_clock;
    enum class QueryError { invalid,full,duplicate,closed,exhausted,unknown_transaction,wrong_source,timeout,protocol };
    struct QueryFailure { QueryError error; std::optional<Error> protocol; };
    struct QueryTicket { std::size_t slot; std::uint64_t sequence; auto operator==(QueryTicket const&) const -> bool = default; };
    struct QueryResult { Endpoint server,mapped; Clock::duration elapsed; };
    // A single executor owns the table. The caller supplies unpredictable
    // transaction IDs and exact server addresses, sends the encoded request,
    // and schedules expire() at the original deadlines. No I/O is retained.
    template<std::size_t Capacity=32>
    class Queries {
        static_assert(Capacity>0 && Capacity<=1024);
        struct Pending {
            Transaction transaction;
            Endpoint server;
            Clock::time_point started,deadline;
            std::uint64_t sequence;
        };
        std::array<std::optional<Pending>,Capacity> pending_{};
        std::uint64_t next_=1;
        std::size_t count_=0;
        bool closed_=false;
        auto remove(std::size_t slot) noexcept -> void { pending_[slot].reset(); --count_; }
        static auto valid_server(Endpoint const& peer) noexcept -> bool {
            auto size=peer.family==4 ? 4u : peer.family==6 ? 16u : 0u;
            return size && peer.port && std::ranges::any_of(std::span(peer.address).first(size),[](auto byte) { return byte!=0; }) &&
                (size!=4 || std::ranges::all_of(std::span(peer.address).subspan(4),[](auto byte) { return byte==0; }));
        }
    public:
        Queries()=default;
        Queries(Queries const&)=delete;
        auto operator=(Queries const&) -> Queries& = delete;
        auto size() const noexcept -> std::size_t { return count_; }
        auto closed() const noexcept -> bool { return closed_; }
        auto expire(Clock::time_point now) noexcept -> std::size_t {
            auto before=count_;
            for (std::size_t i=0;i<Capacity;++i) if (pending_[i] && now>=pending_[i]->deadline) remove(i);
            return before-count_;
        }
        auto reserve(Transaction const& transaction,Endpoint server,Clock::time_point now,Clock::time_point deadline)
            noexcept -> std::expected<QueryTicket,QueryError> {
            if (closed_) return std::unexpected(QueryError::closed);
            server=detail::normalize(server);
            if (deadline<=now || !valid_server(server)) return std::unexpected(QueryError::invalid);
            if (!next_) return std::unexpected(QueryError::exhausted);
            expire(now);
            if (std::ranges::any_of(pending_,[&](auto const& entry) { return entry && entry->transaction==transaction; }))
                return std::unexpected(QueryError::duplicate);
            if (count_==Capacity) return std::unexpected(QueryError::full);
            for (std::size_t i=0;i<Capacity;++i) if (!pending_[i]) {
                auto sequence=next_++;
                pending_[i].emplace(transaction,server,now,deadline,sequence); ++count_;
                return QueryTicket{i,sequence};
            }
            return std::unexpected(QueryError::full);
        }
        auto cancel(QueryTicket ticket) noexcept -> bool {
            if (ticket.slot>=Capacity || !pending_[ticket.slot] || pending_[ticket.slot]->sequence!=ticket.sequence) return false;
            remove(ticket.slot); return true;
        }
        auto accept(std::span<std::uint8_t const> packet,Endpoint source,Clock::time_point now)
            noexcept -> std::expected<QueryResult,QueryFailure> {
            if (closed_) return std::unexpected(QueryFailure{QueryError::closed});
            auto response=parse_response(packet);
            if (!response) return std::unexpected(QueryFailure{QueryError::protocol,response.error()});
            source=detail::normalize(source);
            for (std::size_t i=0;i<Capacity;++i) {
                auto const& entry=pending_[i];
                if (!entry || entry->transaction!=response->transaction) continue;
                if (now<entry->started) return std::unexpected(QueryFailure{QueryError::invalid});
                if (source!=entry->server) return std::unexpected(QueryFailure{QueryError::wrong_source});
                if (now>=entry->deadline) { remove(i); return std::unexpected(QueryFailure{QueryError::timeout}); }
                QueryResult result{entry->server,response->mapped,now-entry->started};
                remove(i); return result;
            }
            return std::unexpected(QueryFailure{QueryError::unknown_transaction});
        }
        auto stop() noexcept -> void {
            closed_=true;
            for (auto& entry:pending_) entry.reset();
            count_=0;
        }
    };
}

