export module tls.resuming_client;
export import tls.psk_client_policy;
export import tls.client_session_handshake;
import std;

export namespace tls {
    namespace detail {
        template<std::size_t Capacity>
        struct ResumptionTicketSink {
            static constexpr bool enabled=true;
            ResumptionReceiver& receiver;
            ResumptionCache<Capacity>& cache;
            std::uint64_t now_ms;
            auto ticket(std::span<std::uint8_t const> body) -> std::expected<void,RecordError> {
                auto delivered=receiver.ticket(body,cache,now_ms);
                if (!delivered) return std::unexpected(delivered.error()==PskError::crypto_error ? RecordError::crypto_error : RecordError::invalid_record);
                return {};
            }
        };
    }
    class ResumedApplication {
        ApplicationRecords records_;
        ResumptionReceiver receiver_;
    public:
        ResumedApplication(ApplicationRecords&& records,ResumptionReceiver&& receiver) noexcept
            : records_(std::move(records)),receiver_(std::move(receiver)) {}
        ResumedApplication(ResumedApplication const&)=delete;
        auto operator=(ResumedApplication const&) -> ResumedApplication& = delete;
        ResumedApplication(ResumedApplication&&) noexcept = default;
        auto operator=(ResumedApplication&&) noexcept -> ResumedApplication& = default;
        [[nodiscard]] auto seal(std::span<std::uint8_t const> bytes) -> std::expected<crypto::Bytes,RecordError> {return records_.seal(bytes);}
        template<std::size_t Capacity>
        [[nodiscard]] auto open_event(std::span<std::uint8_t const> record,ResumptionCache<Capacity>& cache,std::uint64_t now_ms)
            -> std::expected<ApplicationEvent,RecordError> {
            detail::ResumptionTicketSink<Capacity> sink{receiver_,cache,now_ms};return records_.open_event(record,sink);
        }
        [[nodiscard]] auto key_update(bool request) -> std::expected<crypto::Bytes,RecordError> {return records_.key_update(request);}
        [[nodiscard]] auto close_notify() -> std::expected<crypto::Bytes,RecordError> {return records_.close_notify();}
        [[nodiscard]] auto finish_input() -> std::expected<void,RecordError> {return records_.finish_input();}
        [[nodiscard]] auto max_write_size() const noexcept -> std::size_t {return records_.max_write_size();}
    };
    // This enabled owner directly composes the original concrete session and
    // its necessary material. Every parse/Hello/HRR/record loop is the same
    // statically selected algorithm used by the unchanged ordinary owner.
    template<class Policy=PskClientPolicy<>>
    class ResumingClientSession {
        static_assert(Policy::enabled);
        ClientSessionHandshake core_;
        Policy policy_;
        ResumingClientSession(ClientSessionHandshake&& core,Policy&& policy) noexcept
            : core_(std::move(core)),policy_(std::move(policy)) {}
    public:
        ResumingClientSession(ResumingClientSession const&)=delete;
        auto operator=(ResumingClientSession const&) -> ResumingClientSession& = delete;
        ResumingClientSession(ResumingClientSession&&) noexcept = default;
        auto operator=(ResumingClientSession&&) noexcept -> ResumingClientSession& = default;
        // Binding must be made from this same immutable anchor/name/SNI/scope
        // snapshot before selecting tickets from the caller-owned cache.
        [[nodiscard]] static auto create(ClientHello hello,std::span<std::uint16_t const> groups,
            std::span<std::span<std::uint8_t const> const> anchors,PeerNameKind kind,std::span<std::uint8_t const> name,
            std::int64_t verification_time,Policy policy,std::span<std::uint8_t const> application_scope={})
            -> std::expected<ResumingClientSession,ClientSessionHandshakeError> {
            auto expected=make_ticket_binding(hello,anchors,kind,name,policy.binding().alpn,application_scope);
            if (!expected || *expected!=policy.binding()) {policy.cancel();return std::unexpected(expected ? ClientSessionHandshakeError::invalid_configuration :
                expected.error()==PskError::crypto_error ? ClientSessionHandshakeError::crypto_error : ClientSessionHandshakeError::invalid_configuration);}
            try {
                auto core=ClientSessionHandshake::create(std::move(hello),groups,anchors,kind,name,verification_time,policy);
                if (!core) {policy.cancel();return std::unexpected(core.error());}
                return ResumingClientSession(std::move(*core),std::move(policy));
            } catch (...) {policy.cancel();throw;}
        }
        auto abort() noexcept -> void {core_.abort();policy_.cancel();}
        [[nodiscard]] auto initial_record() const -> std::expected<crypto::Bytes,ClientSessionHandshakeError> {return core_.initial_record();}
        [[nodiscard]] auto sent() -> std::expected<void,ClientSessionHandshakeError> {
            auto result=core_.sent(policy_);if (!result)abort();return result;
        }
        [[nodiscard]] auto feed(std::span<std::uint8_t const> input) -> std::expected<ClientSessionHandshakeFeed,ClientSessionHandshakeError> {
            try {auto result=core_.feed(input,policy_);if (!result)abort();return result;}catch(...){abort();throw;}
        }
        [[nodiscard]] auto finish_input() -> std::expected<void,ClientSessionHandshakeError> {auto result=core_.finish_input();abort();return result;}
        [[nodiscard]] auto negotiated() const noexcept -> EncryptedExtensions const* {return core_.negotiated();}
        [[nodiscard]] auto psk_selected() const noexcept -> bool {return policy_.selected() && policy_.complete();}
        [[nodiscard]] auto resumed() const noexcept -> bool {return Policy::ticket_resumption && psk_selected();}
        [[nodiscard]] auto take_application() -> std::expected<ResumedApplication,ClientSessionHandshakeError> {
            auto records=core_.take_application_records();if (!records)return std::unexpected(records.error());
            auto receiver=policy_.take_receiver();if (!receiver){abort();return std::unexpected(ClientSessionHandshakeError::crypto_error);}
            return ResumedApplication(std::move(*records),std::move(*receiver));
        }
    };
}
