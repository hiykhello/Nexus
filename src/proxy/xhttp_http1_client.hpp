#pragma once

        class Http1Carrier {
            CarrierDns dns_;
            Connection connection_;
            std::optional<Response> response_;
            bool stopped_=false,downlink_=false;
        public:
            using Ticket=std::monostate;
            Http1Carrier(Session& session,nex::corosio::io_context& context,Peer const& peer,
                std::optional<std::size_t> bootstrap,TcpSocketOptions const& options)
                :dns_(session,context),connection_(dns_.session,context,peer,bootstrap,options) {}
            auto connect(std::shared_ptr<Http1Carrier>,nex::corosio::io_context&,Clock::time_point until)
                -> nex::capy::task<bool> {
                if (stopped_) co_return false;
                auto connected=co_await connection_.connect(until);
                if (!connected) cancel();
                co_return connected && !stopped_;
            }
            auto wait_ready(Clock::time_point) -> nex::capy::task<bool> {co_return !stopped_;}
            auto failed() const noexcept -> bool {return stopped_;}
            auto record_peer(Session& session) const noexcept -> void {
                if (connection_.connected_peer) session.record_physical_peer(*connection_.connected_peer);
            }
            auto cancel() noexcept -> void {
                if (std::exchange(stopped_,true)) return;
                connection_.cancel();
            }
            auto open(xhttp::Request const& request,Peer const& peer,http2::BodyView body,Clock::time_point until)
                -> nex::capy::task<std::optional<Ticket>> {
                if (stopped_ || response_ || !body.end_stream) co_return std::nullopt;
                downlink_=request.method=="GET";
                auto head=request_head(request,peer.endpoint.authority,
                    downlink_ ? std::nullopt : std::optional(body.bytes.size()),downlink_);
                auto sent=co_await connection_.stream.send(bytes(head),until);
                if (!sent) {cancel();co_return std::nullopt;}
                if (!body.bytes.empty()) {
                    sent=co_await connection_.stream.send(body.bytes,until);
                    if (!sent) {cancel();co_return std::nullopt;}
                }
                response_.emplace();
                co_return Ticket{};
            }
            auto read(Ticket,std::span<std::uint8_t> out,Deadline until)
                -> nex::capy::task<std::expected<std::size_t,IoError>> {
                if (stopped_ || !response_) co_return std::unexpected(IoError::state);
                co_return co_await response_->read(connection_.stream,out,until);
            }
            auto transmit(Ticket,http2::BodyView,Deadline) -> nex::capy::task<bool> {co_return false;}
            auto release(Ticket) noexcept -> void {
                // A pending read has exclusive ownership of Response until
                // it wakes. Closing its socket leaves the decoder alive.
                if (downlink_ || !response_ || !response_->reusable()) cancel();
                else response_.reset();
            }
        };
