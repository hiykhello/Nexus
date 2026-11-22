export module http2.client;
import std;
export import http2.client_types;
import http2.client_state;
import http2.session_core;
import memory.budget;
import nexus.thirdparty.nghttp2;

export namespace http2 {
    namespace detail { struct ClientTest; }
    // Synchronous state only. One external driver owns receive/output and its
    // transport; caller body spans remain borrowed until tx_consumed is true.
    template<std::size_t Capacity=16>
    class Client {
        friend struct detail::ClientTest;
        static_assert(Capacity>0 && Capacity<=1024);
        using Policy=detail::ClientPolicy<Capacity>;
        using Core=detail::SessionCore<Policy,detail::SharedAccounting>;
        Core core_;
        static auto settings(ClientLimits const& limits) noexcept -> detail::CoreLimits {
            return {limits.connection_window,limits.stream_window,limits.header_fields,limits.header_bytes,
                static_cast<std::uint32_t>(Capacity),limits.decoder_table,limits.encoder_table,limits.outbound_ack,limits.outbound_queue_limit};
        }
        explicit Client(ClientLimits limits,std::shared_ptr<memory::Budget> budget)
            : core_(settings(limits),
                detail::SharedAccounting(limits.library_bytes,std::move(budget)),limits) {}
        auto failure_or_state() const noexcept -> ClientFailure { return failure().value_or(ClientFailure{ClientError::state}); }
        auto stop_native(ClientFailure reason) noexcept -> void {
            core_.abort_native();
            auto& state=core_.policy();state.local_draining=true;
            if(!state.connection_failure)state.connection_failure=reason;
            for(auto& stream:state.streams)if(stream){
                if(!stream->closed&&!stream->failure)stream->failure=ClientFailure{reason.error,reason.code,stream->id};
                stream->closed=true;stream->release_body();
            }
            state.active_streams=0;
        }
        struct Request {
            bool head=false;
            std::optional<std::size_t> length;
        };
        auto request(std::span<FieldView const> fields) const noexcept -> std::expected<Request,ClientFailure> {
            auto const& limits=core_.policy().limits;
            if (fields.size()>limits.header_fields) return std::unexpected(ClientFailure{ClientError::limit});
            bool method=false,scheme=false,path=false,authority=false,regular=false,length_seen=false;
            bool connect=false; Request result; std::size_t total=0;
            for (auto [name,value]:fields) {
                if (name.empty() || name.size()>limits.header_bytes-total || value.size()>limits.header_bytes-total-name.size() ||
                    32>limits.header_bytes-total-name.size()-value.size()) return std::unexpected(ClientFailure{ClientError::headers});
                total+=name.size()+value.size()+32;
                if (!nex::nghttp2::nghttp2_check_header_name(reinterpret_cast<std::uint8_t const*>(name.data()),name.size()) ||
                    !nex::nghttp2::nghttp2_check_header_value_rfc9113(reinterpret_cast<std::uint8_t const*>(value.data()),value.size()) ||
                    std::ranges::any_of(name,[](char c) { return c>='A' && c<='Z'; })) return std::unexpected(ClientFailure{ClientError::headers});
                if (name.front()==':') {
                    if (regular) return std::unexpected(ClientFailure{ClientError::headers});
                    auto bytes=reinterpret_cast<std::uint8_t const*>(value.data());
                    if (name==":method" && !method && nex::nghttp2::nghttp2_check_method(bytes,value.size())) { method=true; connect=value=="CONNECT"; result.head=value=="HEAD"; }
                    else if (name==":scheme" && !scheme && (value=="http" || value=="https")) scheme=true;
                    else if (name==":path" && !path && !value.empty() && (value.front()=='/' || value=="*") && nex::nghttp2::nghttp2_check_path(bytes,value.size())) path=true;
                    else if (name==":authority" && !authority && !value.empty() && value.find('@')==value.npos && nex::nghttp2::nghttp2_check_authority(bytes,value.size())) authority=true;
                    else return std::unexpected(ClientFailure{ClientError::headers});
                } else {
                    regular=true;
                    if (name=="connection" || name=="proxy-connection" || name=="keep-alive" || name=="transfer-encoding" ||
                        name=="upgrade" || (name=="te" && value!="trailers")) return std::unexpected(ClientFailure{ClientError::headers});
                    if (name=="content-length") {
                        std::size_t length=0;
                        if (length_seen || !Policy::unsigned_field(value,length)) return std::unexpected(ClientFailure{ClientError::headers});
                        length_seen=true; result.length=length;
                    }
                }
            }
            if (!method || !authority || (connect ? scheme || path : !scheme || !path)) return std::unexpected(ClientFailure{ClientError::headers});
            return result;
        }
    public:
        Client(Client const&)=delete;
        auto operator=(Client const&) -> Client& = delete;
        static auto create(ClientLimits limits={},std::shared_ptr<memory::Budget> budget={})
            -> std::expected<std::unique_ptr<Client>,ClientFailure> {
            auto capacity=std::max(limits.stream_window,std::size_t{65535});
            if (!limits.stream_window || limits.stream_window>std::size_t(std::numeric_limits<std::int32_t>::max()) ||
                capacity>std::size_t(std::numeric_limits<std::int32_t>::max())/Capacity || !limits.header_fields || limits.header_fields>100 ||
                limits.header_bytes<32 || !limits.library_bytes || !limits.shared_bytes || !limits.outbound_ack || !limits.outbound_queue_limit || !limits.max_body_chunk)
                return std::unexpected(ClientFailure{ClientError::limit});
            if (!limits.connection_window) limits.connection_window=capacity*Capacity;
            if (limits.connection_window<capacity*Capacity || limits.connection_window>std::size_t(std::numeric_limits<std::int32_t>::max()) ||
                limits.shared_bytes<sizeof(Client) || (budget && budget->limit()!=limits.shared_bytes)) return std::unexpected(ClientFailure{ClientError::limit});
            std::unique_ptr<Client> self;
            try {
                if (!budget) budget=std::make_shared<memory::Budget>(limits.shared_bytes);
                self.reset(new Client(limits,std::move(budget)));
            } catch (...) { return std::unexpected(ClientFailure{ClientError::allocation}); }
            auto started=self->core_.start(detail::Role::client,settings(limits));
            if (!started) return std::unexpected(started.error()); return self;
        }
        auto failure() const noexcept -> std::optional<ClientFailure> { return core_.policy().application_failure(core_.fragment_pending()); }
        auto goaway() const noexcept -> std::optional<Goaway> { auto const& state=core_.policy();return state.goaway?state.goaway:state.local_goaway; }
        auto library_used() const noexcept -> std::size_t { return core_.library_used(); }
        auto library_peak() const noexcept -> std::size_t { return core_.library_peak(); }
        [[nodiscard]] auto outbound_queue_size() const noexcept -> std::size_t { return core_.outbound_queue_size(); }
        auto memory_charge() const noexcept -> std::size_t { return core_.memory_charge(); }
        auto write_pending() const noexcept -> bool { return core_.write_pending(); }
        auto draining() const noexcept -> bool {auto const& state=core_.policy();return state.local_draining||state.goaway.has_value();}
        auto all_closed() const noexcept -> bool {return core_.policy().active_streams==0;}
        auto receive(std::span<std::uint8_t const> bytes) noexcept -> std::expected<std::size_t,ClientFailure> {
            auto result=core_.receive(bytes);if(!result&&core_.failure())stop_native(*core_.failure());return result;
        }
        auto output(std::span<std::uint8_t> bytes) noexcept -> std::expected<std::size_t,ClientFailure> {
            auto& state=core_.policy();
            if(state.local_draining&&!state.local_goaway&&!state.active_streams&&!core_.failure()){
                auto last=nex::nghttp2::nghttp2_session_get_last_proc_stream_id(core_.native());
                auto rc=nex::nghttp2::nghttp2_submit_goaway(core_.native(),0,last,nex::nghttp2::NGHTTP2_NO_ERROR,nullptr,0);
                if(rc){state.core_fail(detail::CoreError::http2,rc);stop_native(*core_.failure());return std::unexpected(*core_.failure());}
                state.local_goaway=Goaway{last,0};
            }
            auto result=core_.output(bytes);if(!result&&core_.failure())stop_native(*core_.failure());return result;
        }
        auto cancel(ClientFailure reason={ClientError::canceled}) noexcept -> void { if(!core_.active())stop_native(reason); }
        auto shutdown() noexcept -> std::expected<void,ClientFailure> {
            if(!core_.usable()||failure())return std::unexpected(failure_or_state());core_.policy().local_draining=true;return {};
        }
        auto submit(std::span<FieldView const> fields,BodyView body={}) noexcept -> std::expected<StreamTicket,ClientFailure> {
            if (!core_.usable()) return std::unexpected(failure_or_state());
            auto& state=core_.policy();
            if (state.goaway || state.local_draining) return std::unexpected(ClientFailure{ClientError::goaway});
            if (state.last_id==std::numeric_limits<std::int32_t>::max() || body.bytes.size()>state.limits.max_body_chunk ||
                state.active_streams>=nex::nghttp2::nghttp2_session_get_remote_settings(core_.native(),nex::nghttp2::NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS))
                return std::unexpected(ClientFailure{ClientError::limit});
            auto checked=request(fields); if (!checked) return std::unexpected(checked.error());
            if (checked->length && (body.bytes.size()>*checked->length || (body.end_stream && body.bytes.size()!=*checked->length)))
                return std::unexpected(ClientFailure{ClientError::headers});
            auto selected=Capacity;
            for (std::size_t index=0;index<Capacity;++index)
                if (!state.streams[index] && state.generations[index]!=std::numeric_limits<std::uint32_t>::max()) { selected=index; break; }
            if (selected==Capacity) return std::unexpected(ClientFailure{ClientError::limit});
            auto capacity=std::max(state.limits.stream_window,std::size_t{65535});
            if (capacity>core_.available() || body.bytes.size()>core_.available()-capacity) return std::unexpected(ClientFailure{ClientError::limit});
            state.pending_charge=capacity+body.bytes.size();
            try { state.streams[selected].emplace(capacity,body); }
            catch (...) { state.pending_charge=0; return std::unexpected(ClientFailure{ClientError::allocation}); }
            state.pending_charge=0;
            auto& stream=*state.streams[selected]; stream.head=checked->head; stream.request_length=checked->length;
            std::array<nex::nghttp2::nghttp2_nv,100> headers{};
            std::ranges::transform(fields,headers.begin(),[](auto field) { return Core::nv(field.name,field.value); });
            auto provider=core_.provider(&stream);
            auto id=nex::nghttp2::nghttp2_submit_request2(core_.native(),nullptr,headers.data(),fields.size(),body.bytes.empty() && body.end_stream ? nullptr : &provider,&stream);
            if (id<0) {
                state.streams[selected].reset();
                if (nex::nghttp2::nghttp2_is_fatal(id)) {state.core_fail(detail::CoreError::http2,id);stop_native(*core_.failure());}
                return std::unexpected(ClientFailure{ClientError::http2,id});
            }
            if (!(id&1) || id<=state.last_id) { state.core_fail(detail::CoreError::state);stop_native(*core_.failure());return std::unexpected(*failure()); }
            stream.id=id; state.last_id=id; ++state.active_streams; ++state.generations[selected];
            return StreamTicket{static_cast<std::uint32_t>(selected),state.generations[selected],id};
        }
        auto provide(StreamTicket ticket,BodyView body) noexcept -> std::expected<bool,ClientFailure> {
            if (!core_.usable() || failure()) return std::unexpected(failure_or_state());
            auto& state=core_.policy(); auto stream=state.ticket(ticket);
            if (!stream || stream->closed || stream->cancel_requested || stream->end_requested) return std::unexpected(ClientFailure{ClientError::state});
            if (!stream->body.empty()) return false;
            if (body.bytes.size()>state.limits.max_body_chunk || body.bytes.size()>core_.available() ||
                body.bytes.size()>std::numeric_limits<std::size_t>::max()-stream->provided) return std::unexpected(ClientFailure{ClientError::limit});
            auto total=stream->provided+body.bytes.size();
            if (stream->request_length && (total>*stream->request_length || (body.end_stream && total!=*stream->request_length)))
                return std::unexpected(ClientFailure{ClientError::headers});
            stream->body=body.bytes; stream->body_offset=0; stream->body_reserved=body.bytes.size(); stream->end_requested=body.end_stream; stream->provided=total;
            if (stream->deferred) {
                auto rc=nex::nghttp2::nghttp2_session_resume_data(core_.native(),stream->id);
                if (rc) { state.core_fail(detail::CoreError::http2,rc);stop_native(*core_.failure());return std::unexpected(*failure()); }
                stream->deferred=false;
            }
            return true;
        }
        auto tx_consumed(StreamTicket ticket) noexcept -> std::expected<bool,ClientFailure> {
            if (core_.active()) return std::unexpected(ClientFailure{ClientError::state});
            auto stream=core_.policy().ticket(ticket); if (!stream) return std::unexpected(ClientFailure{ClientError::state});
            return stream->body.empty();
        }
        auto response(StreamTicket ticket) noexcept -> std::expected<ResponseView,ClientFailure> {
            if (core_.active()) return std::unexpected(ClientFailure{ClientError::state});
            auto stream=core_.policy().ticket(ticket); if (!stream) return std::unexpected(ClientFailure{ClientError::state});
            return ResponseView{stream->status,stream->headers,stream->trailers,stream->local_end,stream->remote_end,stream->closed,
                stream->body.empty(),stream->failure ? stream->failure : failure()};
        }
        auto peek(StreamTicket ticket) noexcept -> std::expected<std::span<std::uint8_t const>,ClientFailure> {
            if (core_.active()) return std::unexpected(ClientFailure{ClientError::state});
            auto stream=core_.policy().ticket(ticket); if (!stream) return std::unexpected(ClientFailure{ClientError::state});
            if (stream->failure || failure()) return std::unexpected(stream->failure ? *stream->failure : *failure());
            return stream->input.peek();
        }
        auto consume(StreamTicket ticket,std::size_t count) noexcept -> std::expected<void,ClientFailure> {
            if (!core_.usable()) return std::unexpected(failure_or_state());
            auto& state=core_.policy(); auto stream=state.ticket(ticket);
            if (!stream || stream->failure || count>stream->input.size()) return std::unexpected(ClientFailure{ClientError::state});
            auto rc=stream->closed ? nex::nghttp2::nghttp2_session_consume_connection(core_.native(),count) :
                nex::nghttp2::nghttp2_session_consume(core_.native(),stream->id,count);
            if (rc) { state.core_fail(detail::CoreError::http2,rc);stop_native(*core_.failure());return std::unexpected(*failure()); }
            stream->input.consume(count); state.credited_connection+=count; if (!stream->closed) state.credited_stream+=count; return {};
        }
        auto reset(StreamTicket ticket,std::uint32_t code=nex::nghttp2::NGHTTP2_CANCEL) noexcept -> std::expected<void,ClientFailure> {
            if (!core_.usable()) return std::unexpected(failure_or_state());
            auto& state=core_.policy(); auto stream=state.ticket(ticket); if (!stream) return std::unexpected(ClientFailure{ClientError::state});
            if (state.reject(core_,*stream,ClientError::reset,code)) {stop_native(*core_.failure());return std::unexpected(*failure());}return {};
        }
        // False means a reset is queued but nghttp2 still retains its provider.
        // Continue draining output/receiving before releasing caller storage.
        auto release(StreamTicket ticket) noexcept -> std::expected<bool,ClientFailure> {
            if (core_.active()) return std::unexpected(ClientFailure{ClientError::state});
            auto& state=core_.policy(); auto stream=state.ticket(ticket); if (!stream) return std::unexpected(ClientFailure{ClientError::state});
            if (!stream->closed && !core_.failure()) {
                auto rejected=reset(ticket); if (!rejected) return std::unexpected(rejected.error()); return false;
            }
            if (!core_.failure() && !state.discard_input(core_,*stream)) return std::unexpected(*failure());
            state.streams[ticket.slot].reset(); return true;
        }
        auto finish_input() noexcept -> std::expected<void,ClientFailure> {
            if (!core_.usable()) return std::unexpected(failure_or_state());
            auto& state=core_.policy(); state.local_draining=true;
            bool truncated=false;
            for (auto& stream:state.streams) if (stream && !stream->closed) {
                truncated=true; stream->failure=ClientFailure{ClientError::truncated,0,stream->id};
            }
            if (truncated) {stop_native({ClientError::truncated});return std::unexpected(*failure());}
            return {};
        }
    };
}
