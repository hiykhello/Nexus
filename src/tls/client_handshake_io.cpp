module nexus.tls.client_handshake_io;
import std;
namespace nexus::tls {
    ClientHandshakeIo::ClientHandshakeIo(ClientSessionHandshake&& h, crypto::Bytes&& output, std::uint64_t now, std::uint64_t deadline) noexcept : handshake_(std::move(h)), output_(std::move(output)), now_(now), deadline_(deadline) {}
    ClientHandshakeIo::ClientHandshakeIo(ClientHandshakeIo&& o) noexcept : state_(o.state_), handshake_(std::move(o.handshake_)), output_(std::move(o.output_)), offset_(o.offset_), finished_output_(o.finished_output_), now_(o.now_), deadline_(o.deadline_) { o.state_=State::failed; o.handshake_.reset(); o.output_.clear(); o.offset_=0; }
    auto ClientHandshakeIo::operator=(ClientHandshakeIo&& o) noexcept -> ClientHandshakeIo& {
        if (this!=&o) { state_=o.state_; handshake_=std::move(o.handshake_); output_=std::move(o.output_); offset_=o.offset_; finished_output_=o.finished_output_; now_=o.now_; deadline_=o.deadline_; o.state_=State::failed; o.handshake_.reset(); o.output_.clear(); o.offset_=0; } return *this;
    }
    auto ClientHandshakeIo::fail(ClientHandshakeIoError error) -> std::unexpected<ClientHandshakeIoError> {
        state_=State::failed; handshake_.reset(); output_.clear(); offset_=0; return std::unexpected(error);
    }
    auto ClientHandshakeIo::check_time(std::uint64_t now) -> std::expected<void,ClientHandshakeIoError> {
        if (state_==State::failed) return std::unexpected(ClientHandshakeIoError::invalid_state);
        if (now<now_) return std::unexpected(ClientHandshakeIoError::time_reversed);
        now_=now; if (state_==State::active && now>=deadline_) return fail(ClientHandshakeIoError::timeout); return {};
    }
    auto ClientHandshakeIo::create(ClientSessionHandshake&& h, std::uint64_t now, std::uint64_t deadline) -> std::expected<ClientHandshakeIo,ClientHandshakeIoError> {
        if (deadline<=now) return std::unexpected(ClientHandshakeIoError::invalid_argument);
        auto output=h.initial_record(); if (!output) return std::unexpected(ClientHandshakeIoError::invalid_state);
        return ClientHandshakeIo(std::move(h),std::move(*output),now,deadline);
    }
    auto ClientHandshakeIo::pending_output() const noexcept -> std::span<std::uint8_t const> { return std::span{output_}.subspan(offset_); }
    auto ClientHandshakeIo::written(std::size_t count, std::uint64_t now) -> std::expected<void,ClientHandshakeIoError> {
        auto time=check_time(now); if (!time) return std::unexpected(time.error());
        if (state_!=State::active || output_.empty()) return std::unexpected(ClientHandshakeIoError::invalid_state);
        if (count>output_.size()-offset_) return std::unexpected(ClientHandshakeIoError::invalid_argument);
        offset_+=count; if (offset_!=output_.size()) return {};
        if (!handshake_->sent()) return fail(ClientHandshakeIoError::protocol_error);
        output_.clear(); offset_=0; if (finished_output_) state_=State::complete; return {};
    }
    auto ClientHandshakeIo::feed(std::span<std::uint8_t const> input, std::uint64_t now) -> std::expected<ClientHandshakeIoFeed,ClientHandshakeIoError> {
        auto time=check_time(now); if (!time) return std::unexpected(time.error());
        if (state_==State::complete || !output_.empty()) return ClientHandshakeIoFeed{};
        auto result=handshake_->feed(input); if (!result) return fail(result.error()==ClientSessionHandshakeError::authentication_failed ? ClientHandshakeIoError::authentication_failed : ClientHandshakeIoError::protocol_error);
        if (result->outbound) { output_=std::move(*result->outbound); finished_output_=output_[0]==23; }
        return ClientHandshakeIoFeed{result->consumed};
    }
    auto ClientHandshakeIo::tick(std::uint64_t now) -> std::expected<void,ClientHandshakeIoError> { return check_time(now); }
    auto ClientHandshakeIo::cancel() -> std::expected<void,ClientHandshakeIoError> {
        if (state_!=State::active) return std::unexpected(ClientHandshakeIoError::invalid_state); (void)fail(ClientHandshakeIoError::canceled); return {};
    }
    auto ClientHandshakeIo::finish_input(std::uint64_t now) -> std::expected<void,ClientHandshakeIoError> {
        auto time=check_time(now); if (!time) return std::unexpected(time.error());
        if (state_!=State::active) return std::unexpected(ClientHandshakeIoError::invalid_state); return fail(ClientHandshakeIoError::protocol_error);
    }
    auto ClientHandshakeIo::negotiated() const noexcept -> EncryptedExtensions const* { return state_==State::complete ? handshake_->negotiated() : nullptr; }
    auto ClientHandshakeIo::take_application_records() -> std::expected<ApplicationRecords,ClientHandshakeIoError> {
        if (state_!=State::complete || !handshake_) return std::unexpected(ClientHandshakeIoError::invalid_state);
        auto records=handshake_->take_application_records(); if (!records) return std::unexpected(ClientHandshakeIoError::invalid_state); return std::move(*records);
    }
}
