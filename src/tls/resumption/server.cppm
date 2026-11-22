export module tls.resuming_server;
export import tls.psk_server_policy;
export import tls.server_handshake_io;
import std;

export namespace tls {
    template<class Store=ServerTicketStore<>,class Clock=PskSteadyClock>
    class ResumingServerHandshake {
        ServerHandshakeIo core_;
        PskServerPolicy<Store,Clock> policy_;
        ResumingServerHandshake(ServerHandshakeIo&& core,PskServerPolicy<Store,Clock>&& policy) noexcept
            : core_(std::move(core)),policy_(std::move(policy)) {}
    public:
        ResumingServerHandshake(ResumingServerHandshake const&)=delete;
        auto operator=(ResumingServerHandshake const&) -> ResumingServerHandshake& = delete;
        ResumingServerHandshake(ResumingServerHandshake&&) noexcept = default;
        [[nodiscard]] static auto create(ServerCredential&& credential,std::uint64_t now,std::uint64_t deadline,Store& store,
            std::string_view required_alpn={},std::span<std::uint8_t const> application_scope={})
            -> std::expected<ResumingServerHandshake,ServerHandshakeIoError> {
            auto binding=make_server_ticket_binding(credential,std::span(reinterpret_cast<std::uint8_t const*>(required_alpn.data()),required_alpn.size()),application_scope);
            if (!binding)return std::unexpected(binding.error()==PskError::crypto_error ? ServerHandshakeIoError::crypto_error : ServerHandshakeIoError::invalid_argument);
            PskServerPolicy<Store,Clock> policy(store,std::move(*binding));auto core=ServerHandshakeIo::create(std::move(credential),now,deadline,required_alpn);
            if (!core)return std::unexpected(core.error());return ResumingServerHandshake(std::move(*core),std::move(policy));
        }
        auto abort() noexcept -> void {core_.abort();policy_.cancel();}
        [[nodiscard]] auto pending_output() const noexcept -> std::span<std::uint8_t const> {return core_.pending_output();}
        [[nodiscard]] auto complete() const noexcept -> bool {return core_.complete();}
        [[nodiscard]] auto resumed() const noexcept -> bool {return complete() && policy_.selected();}
        [[nodiscard]] auto written(std::size_t count,std::uint64_t now) -> std::expected<void,ServerHandshakeIoError> {
            try {auto result=core_.written(count,now);if (!result)abort();return result;}catch(...){abort();throw;}
        }
        [[nodiscard]] auto feed(std::span<std::uint8_t const> input,std::uint64_t now) -> std::expected<ServerHandshakeIoFeed,ServerHandshakeIoError> {
            try {auto result=core_.feed(input,now,policy_);if (!result)abort();return result;}catch(...){abort();throw;}
        }
        [[nodiscard]] auto tick(std::uint64_t now) -> std::expected<void,ServerHandshakeIoError> {auto result=core_.tick(now);if (!result)abort();return result;}
        [[nodiscard]] auto finish_input(std::uint64_t now) -> std::expected<void,ServerHandshakeIoError> {auto result=core_.finish_input(now);abort();return result;}
        [[nodiscard]] auto take_application_records() -> std::expected<ApplicationRecords,ServerHandshakeIoError> {return core_.take_application_records();}
        [[nodiscard]] auto take_issuer() -> std::expected<ServerTicketIssuer<Store,Clock>,PskError> {
            if (!core_.complete())return std::unexpected(PskError::invalid_state);return policy_.take_issuer();
        }
    };
}
