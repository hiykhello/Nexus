export module http2.server_streams;
import std;
import http2.client_types;
import http2.client_state;
import http2.headers;
import http2.session_core;
import memory.budget;
import nexus.thirdparty.nghttp2;

export namespace http2 {
    struct IncomingView {
        std::span<Header const> headers;
        bool local_end,remote_end,closed;
        std::optional<ClientFailure> failure;
    };

    namespace detail {
        template<std::size_t Capacity>
        struct StreamingServerPolicy : ClientPolicy<Capacity> {
            using Parent=ClientPolicy<Capacity>;
            using Parent::Parent;
            std::array<bool,Capacity> accepted{},responded{};
            template<class Core>
            auto begin(Core& core,h2::nghttp2_frame const& frame) noexcept -> int {
                if (frame.headers.cat!=h2::NGHTTP2_HCAT_REQUEST) return 0;
                auto entry=std::ranges::find_if(this->streams,[](auto const& stream){return !stream;});
                auto index=static_cast<std::size_t>(entry-this->streams.begin());
                auto capacity=this->limits.stream_window;
                if (entry==this->streams.end() || this->local_draining || capacity>core.available() ||
                    this->generations[index]==std::numeric_limits<std::uint32_t>::max()) {
                    auto rc=h2::nghttp2_submit_rst_stream(core.native(),0,frame.hd.stream_id,h2::NGHTTP2_REFUSED_STREAM);
                    return rc ? this->core_fail(CoreError::http2,rc) : h2::NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
                }
                try {entry->emplace(capacity,BodyView{{},false});}
                catch (...) {return this->core_fail(CoreError::allocation);}
                (**entry).id=frame.hd.stream_id;
                ++this->active_streams;
                ++this->generations[index];
                accepted[index]=responded[index]=false;
                return 0;
            }
            template<class Core>
            auto frame(Core& core,h2::nghttp2_frame const& frame) noexcept -> int {
                if (frame.hd.type==h2::NGHTTP2_GOAWAY) {
                    this->local_draining=true;
                    if (frame.goaway.error_code) return this->core_fail(CoreError::http2,static_cast<int>(frame.goaway.error_code));
                    return 0;
                }
                auto* stream=this->find(frame.hd.stream_id);
                if (!stream || stream->failure) return 0;
                bool end=(frame.hd.flags&h2::NGHTTP2_FLAG_END_STREAM)!=0;
                if (frame.hd.type==h2::NGHTTP2_HEADERS) {
                    if (stream->status) {
                        if (!end) return this->reject(core,*stream,ClientError::headers);
                    } else {
                        auto fields=core.headers().fields();
                        if (header_charge(fields)>core.available()) return this->reject(core,*stream,ClientError::limit,h2::NGHTTP2_REFUSED_STREAM);
                        for (auto const& field:fields) if (field.name=="content-length") {
                            std::size_t length=0;
                            if (stream->response_length || !Parent::unsigned_field(field.value,length))
                                return this->reject(core,*stream,ClientError::headers);
                            stream->response_length=length;
                        }
                        try {stream->headers.assign(fields.begin(),fields.end());}
                        catch (...) {return this->reject(core,*stream,ClientError::allocation,h2::NGHTTP2_INTERNAL_ERROR);}
                        stream->status=200;
                    }
                }
                if (end && (frame.hd.type==h2::NGHTTP2_HEADERS || frame.hd.type==h2::NGHTTP2_DATA)) {
                    if (stream->response_length && stream->received!=*stream->response_length)
                        return this->reject(core,*stream,ClientError::headers);
                    stream->remote_end=true;
                }
                return 0;
            }
        };
    }

    // The owner drives one HTTP/2 connection on one executor. Submitted
    // response data is owned until nghttp2 has consumed or discarded it.
    template<std::size_t Capacity=16>
    class ServerStreams {
        static_assert(Capacity>0 && Capacity<=256);
        using Policy=detail::StreamingServerPolicy<Capacity>;
        using Core=detail::SessionCore<Policy,detail::SharedAccounting>;
        Core core_;
        std::array<std::unique_ptr<std::uint8_t[]>,Capacity> bodies_;
        static auto settings(ClientLimits const& limits) noexcept -> detail::CoreLimits {
            return {limits.stream_window*Capacity,limits.stream_window,limits.header_fields,limits.header_bytes,
                static_cast<std::uint32_t>(Capacity),limits.decoder_table,limits.encoder_table,limits.outbound_ack,limits.outbound_queue_limit};
        }
        explicit ServerStreams(ClientLimits limits,std::shared_ptr<memory::Budget> budget)
            :core_(settings(limits),detail::SharedAccounting(limits.library_bytes,std::move(budget)),limits) {}
        auto state() noexcept -> Policy& {return core_.policy();}
        auto error(ClientError kind=ClientError::state) const noexcept -> std::unexpected<ClientFailure> {
            return std::unexpected(failure().value_or(ClientFailure{kind}));
        }
        auto reclaim() noexcept -> void {
            for (std::size_t i=0;i<Capacity;++i) {
                auto& stream=state().streams[i];
                if (!stream) continue;
                if (stream->body.empty()) bodies_[i].reset();
                if (stream->closed && !state().accepted[i]) {
                    if (stream->input.size() && !state().discard_input(core_,*stream)) return;
                    stream.reset();
                }
            }
        }
    public:
        static auto create(ClientLimits limits={}) -> std::expected<std::unique_ptr<ServerStreams>,ClientFailure> {
            if (limits.stream_window<65535 || limits.stream_window>std::size_t(std::numeric_limits<std::int32_t>::max())/Capacity ||
                limits.header_fields==0 || limits.header_fields>100 || limits.header_bytes<32 || !limits.library_bytes ||
                !limits.shared_bytes || !limits.max_body_chunk || !limits.outbound_queue_limit)
                return std::unexpected(ClientFailure{ClientError::limit});
            std::unique_ptr<ServerStreams> owner;
            try {owner.reset(new ServerStreams(limits,std::make_shared<memory::Budget>(limits.shared_bytes)));}
            catch (...) {return std::unexpected(ClientFailure{ClientError::allocation});}
            auto start=owner->core_.start(detail::Role::server,settings(limits));
            if (!start) return std::unexpected(start.error());
            return owner;
        }
        auto failure() const noexcept -> std::optional<ClientFailure> {return core_.failure();}
        auto draining() const noexcept -> bool {return core_.policy().local_draining;}
        auto all_closed() const noexcept -> bool {return core_.policy().active_streams==0;}
        auto receive(std::span<std::uint8_t const> input) noexcept -> std::expected<std::size_t,ClientFailure> {
            auto result=core_.receive(input);
            if (result) reclaim();
            return result;
        }
        auto output(std::span<std::uint8_t> out) noexcept -> std::expected<std::size_t,ClientFailure> {
            auto result=core_.output(out);
            if (result) reclaim();
            return result;
        }
        auto cancel(ClientFailure reason) noexcept -> void {
            if (core_.active() || failure()) return;
            core_.abort_native();
            state().connection_failure=reason;
            state().cleanup();
            for (auto& body:bodies_) body.reset();
        }
        auto finish_input() noexcept -> std::expected<void,ClientFailure> {
            state().local_draining=true;
            if (!all_closed()) return error(ClientError::truncated);
            return {};
        }
        auto accept() noexcept -> std::optional<StreamTicket> {
            if (!core_.usable()) return {};
            for (std::size_t i=0;i<Capacity;++i)
                if (auto& stream=state().streams[i];stream && stream->status && !stream->failure && !state().accepted[i]) {
                    state().accepted[i]=true;
                    return StreamTicket{static_cast<std::uint32_t>(i),state().generations[i],stream->id};
                }
            return {};
        }
        auto inspect(StreamTicket ticket) noexcept -> std::expected<IncomingView,ClientFailure> {
            auto stream=state().ticket(ticket);
            if (!stream || !core_.usable()) return error();
            return IncomingView{stream->headers,stream->local_end,stream->remote_end,stream->closed,stream->failure};
        }
        auto respond(StreamTicket ticket,std::span<FieldView const> fields,bool end=false) noexcept -> std::expected<void,ClientFailure> {
            auto stream=state().ticket(ticket);
            if (!stream || !core_.usable() || stream->closed || stream->failure || state().responded[ticket.slot] ||
                fields.empty() || fields.size()>state().limits.header_fields) return error();
            std::array<detail::h2::nghttp2_nv,100> wire;
            std::size_t charge=0;
            for (auto field:fields) {
                charge+=field.name.size()+field.value.size()+32;
                if (charge>state().limits.header_bytes) return error(ClientError::limit);
            }
            std::ranges::transform(fields,wire.begin(),[](auto field){return Core::nv(field.name,field.value);});
            auto provider=core_.provider(stream);
            auto rc=detail::h2::nghttp2_submit_response2(core_.native(),ticket.id,wire.data(),fields.size(),end ? nullptr : &provider);
            if (rc) return std::unexpected(ClientFailure{ClientError::http2,rc,ticket.id});
            state().responded[ticket.slot]=true;
            stream->end_requested=end;
            return {};
        }
        auto provide(StreamTicket ticket,BodyView data) noexcept -> std::expected<bool,ClientFailure> {
            auto stream=state().ticket(ticket);
            if (!stream || !core_.usable() || stream->closed || stream->failure || !state().responded[ticket.slot] ||
                stream->end_requested) return error();
            if (!stream->body.empty()) return false;
            if (data.bytes.size()>core_.available() || data.bytes.size()>state().limits.max_body_chunk) return error(ClientError::limit);
            if (!data.bytes.empty()) {
                try {bodies_[ticket.slot]=std::make_unique_for_overwrite<std::uint8_t[]>(data.bytes.size());}
                catch (...) {return error(ClientError::allocation);}
                std::ranges::copy(data.bytes,bodies_[ticket.slot].get());
                stream->body={bodies_[ticket.slot].get(),data.bytes.size()};
                stream->body_reserved=data.bytes.size();
            }
            stream->end_requested=data.end_stream;
            if (stream->deferred) {
                auto rc=detail::h2::nghttp2_session_resume_data(core_.native(),ticket.id);
                if (rc) return std::unexpected(ClientFailure{ClientError::http2,rc,ticket.id});
                stream->deferred=false;
            }
            return true;
        }
        auto tx_consumed(StreamTicket ticket) noexcept -> std::expected<bool,ClientFailure> {
            auto stream=state().ticket(ticket);
            if (!stream || !core_.usable()) return error();
            if (stream->failure) return std::unexpected(*stream->failure);
            return stream->body.empty();
        }
        auto pull(StreamTicket ticket,std::span<std::uint8_t> out) noexcept -> std::expected<std::optional<std::size_t>,ClientFailure> {
            auto stream=state().ticket(ticket);
            if (!stream || !core_.usable()) return error();
            if (stream->failure) return std::unexpected(*stream->failure);
            auto data=stream->input.peek();
            auto count=std::min(out.size(),data.size());
            if (!count) {
                if (stream->remote_end || out.empty()) return 0;
                return std::nullopt;
            }
            auto rc=stream->closed ? detail::h2::nghttp2_session_consume_connection(core_.native(),count) :
                detail::h2::nghttp2_session_consume(core_.native(),ticket.id,count);
            if (rc) return std::unexpected(ClientFailure{ClientError::http2,rc,ticket.id});
            std::ranges::copy(data.first(count),out.begin());
            stream->input.consume(count);
            return count;
        }
        // Release the application lease. If necessary, reset the stream while
        // keeping its provider alive until the nghttp2 close callback.
        auto release(StreamTicket ticket,bool reset=true) noexcept -> void {
            auto stream=state().ticket(ticket);
            if (!stream || !core_.usable()) return;
            if (reset && !stream->closed)
                (void)state().reject(core_,*stream,ClientError::canceled,detail::h2::NGHTTP2_CANCEL);
            state().accepted[ticket.slot]=false;
            if (!stream->closed) stream->status=0;
            reclaim();
        }
    };
}
