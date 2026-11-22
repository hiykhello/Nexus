export module dns.message_fakeip;
import std;
import dns.fakeip_shared;
import dns.fakeip_response;
import dns.message;
import dns.corosio_resolver;

export namespace dns {
    struct FakeIpPublisher {
        FakeIpShared& registry;
        std::uint32_t first, ttl;
        std::uint64_t view;
        bool ipv6;

        [[nodiscard]] auto query_wire(QueryMessage const& query) const
            -> std::optional<Bytes> {
            auto use_ipv6=query.question.type==28;
            if (query.question.klass!=1 || (query.question.type!=1 && !(use_ipv6 && ipv6)))
                return std::nullopt;
            auto wire = encode_query(query);
            if (!wire || !validate_fakeip_query(*wire,use_ipv6)) return std::nullopt;
            return std::move(*wire);
        }
    };

    // Exists only for the client exchange, and finishes after its transport
    // completes. Ambiguous sends extend the lease just like successful ones.
    class FakeIpPublication {
        std::unique_ptr<FakeIpShared::Response> response_;
        bool possibly_sent_ = false;
    public:
        FakeIpPublication() = default;
        FakeIpPublication(FakeIpPublication const&) = delete;
        auto operator=(FakeIpPublication const&) -> FakeIpPublication& = delete;
        ~FakeIpPublication() { finish(); }
        auto finish() noexcept -> void {
            if (response_) {
                try { (void)response_->finish(possibly_sent_); }
                catch (...) {} // The retained pin prevents address reuse.
                response_.reset();
            }
        }
        auto begin_send() noexcept -> void { possibly_sent_ = true; }
        [[nodiscard]] auto respond(FakeIpPublisher const& publisher, QueryMessage const& query,
            Bytes const& query_wire,std::optional<std::uint32_t> ttl,std::optional<std::uint64_t> policy_view={})
            -> std::expected<Bytes, detail::ResolveError> {
            using Error = detail::ResolveError;
            if (response_) return std::unexpected(Error::state);
            auto response = publisher.registry.respond(publisher.first,query_wire,policy_view.value_or(publisher.view),query.question.type==28);
            if (!response) return std::unexpected(Error::transport);
            response_ = std::move(*response);
            auto answer = response_->wire();
            if (!ttl || *ttl >= publisher.ttl) return Bytes(answer.begin(), answer.end());
            auto parsed = parse_response(answer, query.id, query.question);
            if (!parsed) return std::unexpected(Error::protocol);
            auto encoded = encode_response(*parsed, query.id, ttl);
            if (!encoded) return std::unexpected(Error::protocol);
            return std::move(*encoded);
        }
    };
}
