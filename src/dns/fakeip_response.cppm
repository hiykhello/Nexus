export module dns.fakeip_response;
import std;
import dns.fakeip;

export namespace dns {
    enum class FakeIpDnsError { malformed, unsupported, invalid_name, full, clock, exhausted };
    // Checks the same restricted query grammar used by fakeip_response.
    [[nodiscard]] auto validate_fakeip_query(std::span<std::uint8_t const> query,bool ipv6=false)
        -> std::expected<void,FakeIpDnsError>;
    class FakeIpResponse {
        FakeIpPool* pool_;
        FakeIpLease lease_;
        std::vector<std::uint8_t> wire_;
        bool pending_=true;
        FakeIpResponse(FakeIpPool& pool,FakeIpLease lease,std::vector<std::uint8_t> wire)
            : pool_(&pool),lease_(lease),wire_(std::move(wire)) {}
        friend auto fakeip_response(FakeIpPool&,std::span<std::uint8_t const>,std::uint64_t,
            std::chrono::steady_clock::time_point,std::optional<FakeIpIpv6Range>)
            -> std::expected<std::unique_ptr<FakeIpResponse>,FakeIpDnsError>;
    public:
        FakeIpResponse(FakeIpResponse const&)=delete;
        auto operator=(FakeIpResponse const&) -> FakeIpResponse& = delete;
        // Destroying an unfinished response leaves its pin held, deliberately
        // failing closed. The pool must outlive all pending responses.
        [[nodiscard]] auto wire() const noexcept -> std::span<std::uint8_t const> {
            return pending_ ? std::span<std::uint8_t const>{wire_} : std::span<std::uint8_t const>{};
        }
        // Call exactly once, after transport completion or confirmed cancellation.
        // `possibly_sent` includes successful and ambiguous completions.
        [[nodiscard]] auto finish(bool possibly_sent,std::chrono::steady_clock::time_point now)
            -> std::expected<void,FakeIpError> {
            if (!pending_) return std::unexpected(FakeIpError::stale);
            auto result=possibly_sent ? pool_->finish_publication(lease_,now) : pool_->unpin(lease_,now);
            if (result) pending_=false;
            return result;
        }
    };
    // Restricted IN/A or alias IN/AAAA standard query, exactly one uncompressed question and
    // optional EDNS(0) without flags or options; caller handles other queries explicitly.
    // Pending work must be bounded and serialized with the pool; this object
    // does not submit I/O or determine when a datagram reaches its recipient.
    [[nodiscard]] auto fakeip_response(FakeIpPool& pool,std::span<std::uint8_t const> query,
        std::uint64_t view,std::chrono::steady_clock::time_point now,std::optional<FakeIpIpv6Range> ipv6={})
        -> std::expected<std::unique_ptr<FakeIpResponse>,FakeIpDnsError>;
}
