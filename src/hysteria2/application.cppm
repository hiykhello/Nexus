export module hysteria2.application;
import std;
import hysteria2.auth;
import hysteria2.dispatch;
import hysteria2.wire;
import hysteria2.stream_state;
import quic.connection;
import quic.http3;
import http.header;
import ngtcp2;
import nghttp3;

export namespace hysteria2 {
    // One executor, borrowed immutable authentication profile and concrete
    // notification/authentication hooks. Stream storage has a fixed budget.
    // Host joins driver and application tasks before joined()/transport.stop().
    template<class Tls,class Hooks,std::size_t Streams=16,std::size_t Window=16384>
    class Application {
        static_assert(Streams && Streams<=65535 && Window>=8192);
        using State=StreamState<Window>;
    public:
        using Transport=quic::Connection<Tls,Application>;
        using Http3=quic::Http3<Application>;
        static constexpr std::size_t stream_capacity=Streams,window_bytes=Window;
    private:
        Tls& tls_;
        Hooks& hooks_;
        nghttp3::nghttp3_mem memory_;
        Http3 http3_{*this};
        Transport* transport_=nullptr;
        std::array<std::optional<State>,Streams> streams_;
        std::uint64_t next_generation_=1,time_=0;
        std::size_t cursor_=0;
        std::size_t receive_limit_;
        std::int64_t auth_stream_=-1;
        std::optional<ClientAuthHeaders> client_auth_;
        ServerAuth local_auth_{false,true,0};
        std::optional<ServerAuth> peer_auth_;
        std::optional<CongestionPolicy> congestion_;
        std::optional<std::pair<std::uint64_t,bool>> pending_congestion_;
        bool server_,handshake_=false,authenticated_=false,stopping_=false,io_joined_=false;
        std::uint8_t output_turn_=0;
        auto signal() noexcept -> void { static_assert(noexcept(hooks_.changed())); hooks_.changed(); }
        auto stop_business() noexcept -> void {
            if (std::exchange(stopping_,true)) return;
            if constexpr (requires {hooks_.stopping();}) hooks_.stopping();
            signal();
        }
        auto find(std::int64_t id) noexcept -> State* {
            for (auto& state:streams_) if (state && state->id==id) return &*state;
            return nullptr;
        }
        auto uses_http3(State const& state) const noexcept -> bool {
            // A rejected or incomplete first-byte prefix has never entered
            // nghttp3. Its native terminal callbacks must not create an H3
            // stream or poison the authenticated connection.
            return !state.tcp && (!server_ || state.dispatch.route()==StreamRoute::http3);
        }
        auto get(StreamHandle handle) noexcept -> State* {
            if (handle.slot>=Streams || !streams_[handle.slot] || streams_[handle.slot]->generation!=handle.generation) return nullptr;
            return &*streams_[handle.slot];
        }
        auto create(std::int64_t id) -> State* {
            if (!next_generation_) return nullptr;
            for (auto& state:streams_) if (!state) { state.emplace(id,next_generation_++,server_,memory_,receive_limit_); return &*state; }
            return nullptr;
        }
        auto handle(State const& state) const noexcept -> StreamHandle {
            for (std::size_t i=0;i<Streams;++i) if (streams_[i] && &*streams_[i]==&state) return {static_cast<std::uint16_t>(i),state.generation};
            return {};
        }
        auto credit(std::int64_t id,std::size_t bytes) -> int {
            auto error=ngtcp2::ngtcp2_conn_extend_max_stream_offset(transport_->native(),id,bytes);
            if (!error) ngtcp2::ngtcp2_conn_extend_max_offset(transport_->native(),bytes);
            return error;
        }
        auto reject(State& state,std::uint64_t code=0x100) -> int {
            state.phase=StreamPhase::reset; state.reset_code=code; signal();
            return ngtcp2::ngtcp2_conn_shutdown_stream(transport_->native(),0,state.id,code);
        }
        auto tcp_input(State& state,std::span<std::uint8_t const> bytes,bool fin) -> int {
            if (state.phase==StreamPhase::reset || state.transport_closed) return 0;
            if (!state.header_done) {
                auto parsed=std::visit([&](auto& decoder) { return decoder.feed(bytes); },state.decoder);
                if (parsed.status!=WireStatus::incomplete && parsed.status!=WireStatus::accepted) return reject(state);
                if (auto error=credit(state.id,parsed.consumed)) return error;
                bytes=bytes.subspan(parsed.consumed);
                if (parsed.status==WireStatus::accepted) {
                    state.header_done=true;
                    if (server_) state.phase=StreamPhase::request;
                    else state.phase=std::get<TcpResponseDecoder>(state.decoder).response()->status==TcpStatus::success ? StreamPhase::ready : StreamPhase::rejected;
                    signal();
                } else if (fin) return reject(state);
            }
            if (!state.input.append(bytes)) return ngtcp2::err_callback_failure;
            if (fin) state.input_fin=true;
            if (!bytes.empty() || fin) signal();
            return 0;
        }
        template<std::size_t Count> static auto fields(std::array<http::HeaderField,Count> const& source) noexcept -> std::array<nghttp3::nghttp3_nv,Count> {
            std::array<nghttp3::nghttp3_nv,Count> out{};
            for (std::size_t i=0;i<Count;++i) { auto const& field=source[i];
                out[i]={reinterpret_cast<std::uint8_t const*>(field.name.data()),reinterpret_cast<std::uint8_t const*>(field.value.data()),field.name.size(),field.value.size(),
                    static_cast<std::uint8_t>(field.name=="hysteria-auth" ? nghttp3::nv_flag_never_index : nghttp3::nv_flag_none)};
            } return out;
        }
        auto authenticate_client() -> int {
            auto* state=create(-1); if (!state) return ngtcp2::err_callback_failure;
            auto error=ngtcp2::ngtcp2_conn_open_bidi_stream(transport_->native(),&state->id,nullptr);
            if (error) { streams_[handle(*state).slot].reset(); return error; }
            auth_stream_=state->id;
            return http3_.request(auth_stream_,fields(client_auth_->fields()));
        }
    public:
        Application(Tls& tls,Hooks& hooks,bool server,nghttp3::nghttp3_mem const& memory,
            std::string_view credential={},ServerAuth auth={false,true,0},std::optional<CongestionPolicy> congestion={},
            std::size_t receive_limit=Window)
            :tls_(tls),hooks_(hooks),memory_(memory),receive_limit_(receive_limit ? receive_limit : Window),
             local_auth_(auth),congestion_(congestion),server_(server) {
            if (!server) {
                auto headers=ClientAuthHeaders::create(credential,congestion_ ? congestion_->receive_bps : 0); if (!headers) throw std::invalid_argument("invalid Hy2 credential");
                client_auth_=*headers;
            }
            // Explicit congestion policy is applied after authentication.
            if (auth.receive_bps && !congestion_) throw std::invalid_argument("unsupported Hy2 congestion policy");
        }
        Application(Application const&)=delete;
        auto operator=(Application const&) -> Application& = delete;
        auto attach(Transport& transport) noexcept -> void { transport_=&transport; }
        auto take_congestion() noexcept -> std::optional<std::pair<std::uint64_t,bool>> {return std::exchange(pending_congestion_,{});}
        auto authenticated() const noexcept -> bool { return authenticated_; }
        auto handshake_complete() const noexcept -> bool { return handshake_; }
        auto peer_auth() const noexcept -> std::optional<ServerAuth> { return peer_auth_; }
        auto stopping() const noexcept -> bool { return stopping_; }
        auto time(std::uint64_t now) noexcept -> void { time_=now; }
        auto request_stop() noexcept -> void {
            stop_business();
            http3_.stop();
        }
        auto joined() noexcept -> void {
            io_joined_=true;
            for (auto& state:streams_) if (state) state->input.clear();
        }
        auto drain() noexcept -> void { http3_.stop(); }
        auto clean() const noexcept -> bool { return !http3_.native() && (!transport_ || !transport_->native()); }
        auto pending() noexcept -> std::optional<StreamHandle> {
            for (auto& state:streams_) if (state && state->tcp && state->phase==StreamPhase::request) return handle(*state);
            return {};
        }
        // Claim before launching asynchronous routing so another maintenance
        // pass cannot launch the same request while its DNS/dial is suspended.
        auto claim(StreamHandle id) noexcept -> bool {
            auto* state=get(id);if(!server_ || !state || state->phase!=StreamPhase::request || stopping_)return false;
            state->phase=StreamPhase::routing;state->business_owned=true;return true;
        }
        auto phase(StreamHandle id) noexcept -> std::optional<StreamPhase> { auto* state=get(id); return state ? std::optional(state->phase) : std::nullopt; }
        auto address(StreamHandle id) noexcept -> std::string_view { auto* state=get(id); return state ? state->address() : std::string_view{}; }
        auto acknowledged(StreamHandle id) noexcept -> bool { auto* state=get(id); return state && !state->output.size() && (!state->output_fin || state->fin_accepted); }
        auto fin_accepted(StreamHandle id) noexcept -> bool { auto* state=get(id); return state && state->fin_accepted; }
        auto output_stopped(StreamHandle id) noexcept -> bool { auto* state=get(id); return !state || state->output_stopped; }
        auto reset_code(StreamHandle id) noexcept -> std::optional<std::uint64_t> { auto* state=get(id); return state && state->phase==StreamPhase::reset ? std::optional(state->reset_code) : std::nullopt; }
        auto buffered_input(StreamHandle id) noexcept -> std::optional<std::size_t> { auto* state=get(id);return state?std::optional(state->input.size()):std::nullopt; }
        auto buffered_output(StreamHandle id) noexcept -> std::optional<std::size_t> { auto* state=get(id);return state?std::optional(state->output.size()):std::nullopt; }
        auto datagram_budget() const noexcept -> std::size_t {
            if (!authenticated_ || stopping_ || !(server_ ? local_auth_.udp : peer_auth_->udp)) return 0;
            auto* parameters=ngtcp2::ngtcp2_conn_get_remote_transport_params2(transport_->native());
            // Conservative minimum-path budget includes a maximal short CID,
            // packet number and AEAD tag, without relying on PMTU growth.
            return parameters && parameters->max_datagram_frame_size>3 ? static_cast<std::size_t>(std::min<std::uint64_t>(1150,parameters->max_datagram_frame_size-3)) : 0;
        }
        auto open(std::string_view address,std::span<std::uint8_t const> padding={}) -> std::expected<StreamHandle,ApplicationError> {
            if (server_ || !authenticated_ || stopping_) return std::unexpected(ApplicationError::state);
            auto encoded=encode_tcp_request(address,padding); if (!encoded) return std::unexpected(ApplicationError::header);
            auto* state=create(-1); if (!state) return std::unexpected(ApplicationError::capacity);
            auto id=handle(*state);
            if (ngtcp2::ngtcp2_conn_open_bidi_stream(transport_->native(),&state->id,nullptr)) { streams_[id.slot].reset(); return std::unexpected(ApplicationError::capacity); }
            state->tcp=true; state->business_owned=true; state->output.append(*encoded); signal(); return id;
        }
        auto respond(StreamHandle id,TcpStatus status,std::string_view message={},std::span<std::uint8_t const> padding={}) -> std::expected<void,ApplicationError> {
            auto* state=get(id); if (!server_ || !state || (state->phase!=StreamPhase::request && state->phase!=StreamPhase::routing) || stopping_) return std::unexpected(ApplicationError::state);
            auto encoded=encode_tcp_response(status,message,padding); if (!encoded || !state->output.append(*encoded)) return std::unexpected(ApplicationError::header);
            state->business_owned=true;
            state->phase=status==TcpStatus::success ? StreamPhase::ready : StreamPhase::rejected;
            if (status!=TcpStatus::success) state->output_fin=true;
            signal(); return {};
        }
    private:
        auto writable(State const& state,bool early) const noexcept -> bool {
            return state.phase==StreamPhase::ready ||
                (early && !server_ && state.tcp && state.phase==StreamPhase::opening);
        }
    public:
        auto send(StreamHandle id,std::span<std::uint8_t const> bytes,bool early=false) noexcept -> std::expected<std::size_t,ApplicationError> {
            auto* state=get(id); if (!state || !writable(*state,early) || state->output_fin || state->output_stopped || stopping_) return std::unexpected(ApplicationError::state);
            auto size=std::min(bytes.size(),state->output.available()); if (!state->output.append(bytes.first(size))) return std::unexpected(ApplicationError::flow_control);
            if (size) signal(); return size;
        }
        auto close_output(StreamHandle id,bool early=false) noexcept -> bool {
            auto* state=get(id); if (!state || !writable(*state,early) || state->output_stopped || stopping_) return false;
            state->output_fin=true; signal(); return true;
        }
        auto reset(StreamHandle id,std::uint64_t code=0x100) -> bool {
            auto* state=get(id); return state && !stopping_ && !state->transport_closed && !reject(*state,code);
        }
        auto read(StreamHandle id,std::span<std::uint8_t> output) -> std::expected<StreamRead,ApplicationError> {
            auto* state=get(id); if (!state || !state->tcp || state->phase==StreamPhase::reset) return std::unexpected(ApplicationError::state);
            if (state->phase!=StreamPhase::ready && state->phase!=StreamPhase::closed) return std::unexpected(ApplicationError::state);
            auto size=state->input.pull(output);
            if (size && !state->transport_closed && credit(state->id,size)) return std::unexpected(ApplicationError::flow_control);
            if (size) signal(); return StreamRead{size,state->input_fin && !state->input.size()};
        }
        auto release(StreamHandle id) noexcept -> bool {
            auto* state=get(id); if (!state || !state->transport_closed) return false;
            auto remote=server_ && (state->id&3)==0;
            streams_[id.slot].reset();
            if (remote && transport_->active()) ngtcp2::ngtcp2_conn_extend_max_streams_bidi(transport_->native(),1);
            return true;
        }
        auto abandon(StreamHandle id) noexcept -> void {
            auto* state=get(id);if(!state)return;
            if(state->transport_closed){(void)release(id);return;}
            state->abandoned=true;
            // A negative server response already owns a bounded wire header
            // and FIN. Its business task may return before native output/ACK.
            // Preserve that response until native close; any actual peer
            // reset still follows the ordinary reset callbacks below.
            if(server_ && state->phase==StreamPhase::rejected && state->output_fin)return;
            if(state->input_fin && state->output_fin && state->fin_accepted && !state->input.size())return;
            if(!stopping_)try{(void)reject(*state);}catch(...){}
        }
        auto closing(Http3&,int) noexcept -> bool { stop_business(); return io_joined_ && (!transport_ || !transport_->native()); }
        auto connection_closed(Http3&,int) noexcept -> void { for (auto& state:streams_) if (state) state->headers.clear(); }
        auto connection_closed(Transport&,int) noexcept -> void {
            request_stop();
            for (auto& state:streams_) if (state) { state->transport_closed=true; if (state->phase!=StreamPhase::reset && state->phase!=StreamPhase::rejected) state->phase=state->input_fin && state->header_done ? StreamPhase::closed : StreamPhase::reset; }
            http3_.stop(); tls_.cancel(); signal();
            for(auto& state:streams_)if(state && (state->abandoned || !state->business_owned))state.reset();
        }
        auto handshake_complete(Transport& transport) -> int {
            if (!tls_.complete() || &transport!=transport_ || stopping_) return ngtcp2::err_callback_failure;
            auto* parameters=ngtcp2::ngtcp2_conn_get_local_transport_params2(transport.native());
            if (!parameters || parameters->initial_max_streams_bidi>Streams ||
                parameters->initial_max_stream_data_bidi_local>receive_limit_ ||
                parameters->initial_max_stream_data_bidi_remote>receive_limit_) return ngtcp2::err_callback_failure;
            handshake_=true;
            nghttp3::nghttp3_settings settings{}; nghttp3::nghttp3_settings_default_versioned(nghttp3::settings_version,&settings);
            settings.qpack_max_dtable_capacity=settings.qpack_encoder_max_dtable_capacity=4096; settings.qpack_blocked_streams=Streams;
            if (auto error=http3_.start(server_,settings,memory_)) return error;
            if (server_) nghttp3::nghttp3_conn_set_max_client_streams_bidi(http3_.native(),Streams);
            nghttp3::nghttp3_conn_set_max_concurrent_streams(http3_.native(),Streams);
            std::array<std::int64_t,3> ids{};
            for (auto& id:ids) if (auto error=ngtcp2::ngtcp2_conn_open_uni_stream(transport.native(),&id,nullptr)) return error;
            if (auto error=http3_.bind(ids[0],ids[1],ids[2])) return error;
            signal(); return server_ ? 0 : authenticate_client();
        }
        auto handshake_confirmed(Transport&) -> int { return 0; }
        auto stream_data(Transport&,std::uint32_t flags,std::int64_t id,std::uint64_t offset,std::span<std::uint8_t const> bytes,void*) -> int {
            bool fin=flags&ngtcp2::stream_data_flag_fin;
            if (stopping_ || !handshake_) return ngtcp2::err_callback_failure;
            if (id&2) { auto consumed=http3_.read(id,bytes,fin,time_); return consumed ? credit(id,*consumed) : ngtcp2::err_callback_failure; }
            auto* state=find(id); if (!state) state=create(id);
            if (!state) return ngtcp2::err_callback_failure;
            if (state->phase==StreamPhase::reset || state->transport_closed) return 0;
            if (state->received!=offset) return ngtcp2::err_callback_failure;
            state->received+=bytes.size();
            if (server_ && state->dispatch.route()==StreamRoute::pending) {
                auto route=state->dispatch.feed(bytes,authenticated_,fin); bytes=bytes.subspan(route.consumed);
                if (route.route==StreamRoute::pending) return 0;
                if (route.route==StreamRoute::rejected) { state->abandoned=true;return reject(*state); }
                state->tcp=route.route==StreamRoute::tcp;
                if (state->tcp) { if (auto error=tcp_input(*state,state->dispatch.prefix(),false)) return error; }
                else { auto result=http3_.read(id,state->dispatch.prefix(),false,time_); if (!result) return ngtcp2::err_callback_failure; if (auto error=credit(id,*result)) return error; }
            }
            if (state->tcp) return tcp_input(*state,bytes,fin);
            auto consumed=http3_.read(id,bytes,fin,time_); return consumed ? credit(id,*consumed) : ngtcp2::err_callback_failure;
        }
        auto stream_acked(Transport&,std::int64_t id,std::uint64_t offset,std::uint64_t size,void*) -> int {
            auto* state=find(id);
            if (state && !uses_http3(*state)) { if (!state->output.acknowledge(offset,size)) return ngtcp2::err_callback_failure; signal(); return 0; }
            return http3_.active() ? http3_.acknowledged(id,size) : 0;
        }
        auto stream_close(Transport&,std::uint32_t flags,std::int64_t id,std::uint64_t rx,std::uint64_t tx,void*) -> int {
            auto* state=find(id);
            if (state && !uses_http3(*state)) {
                state->transport_closed=true;
                if (state->phase==StreamPhase::opening) state->phase=StreamPhase::reset;
                else if (state->phase!=StreamPhase::reset && state->phase!=StreamPhase::rejected) state->phase=StreamPhase::closed;
                signal();if(state->abandoned || !state->business_owned || !state->tcp)(void)release(handle(*state));return 0;
            }
            auto error=http3_.active() ? http3_.close_stream(flags,id,rx,tx) : 0;
            if (state) streams_[handle(*state).slot].reset();
            if (server_ && (id&3)==0) ngtcp2::ngtcp2_conn_extend_max_streams_bidi(transport_->native(),1);
            return error;
        }
        auto stream_reset(Transport&,std::int64_t id,std::uint64_t,std::uint64_t code,void*) -> int {
            if (auto* state=find(id);state && !uses_http3(*state)) {
                if (server_ && !state->business_owned) { state->abandoned=true; return reject(*state,code); }
                state->phase=StreamPhase::reset; state->reset_code=code; signal(); return 0;
            }
            return http3_.shutdown_read(id);
        }
        auto stop_sending(Transport&,std::int64_t id,std::uint64_t code,void*) -> int {
            if (auto* state=find(id);state && !uses_http3(*state)) {
                // STOP_SENDING affects only our write side. Preserve buffered
                // input and FIN until the business reader consumes them.
                // ngtcp2 closes the write side after this callback returns.
                state->output_stopped=true; signal(); return 0;
            }
            http3_.shutdown_write(id); return 0;
        }
        auto stream_limit(Transport&,std::int64_t id,std::uint64_t,void*) -> int { signal(); auto* state=find(id);return http3_.active() && (!state || uses_http3(*state)) ? http3_.unblock(id) : 0; }
        auto stream_limit(Transport&,bool,std::uint64_t) -> int { signal(); return 0; }
        auto datagram(Transport&,std::span<std::uint8_t const> bytes) -> int {
            if (!authenticated_ || stopping_ || !(server_ ? local_auth_.udp : peer_auth_->udp)) return ngtcp2::err_callback_failure;
            return hooks_.datagram(bytes);
        }
        auto add_connection_id(Transport&,ngtcp2::ngtcp2_cid const& id,ngtcp2::ngtcp2_stateless_reset_token const& token) -> int {
            if constexpr(requires{hooks_.add_connection_id(id,token);})return hooks_.add_connection_id(id,token);
            else return 0;
        }
        auto remove_connection_id(Transport&,ngtcp2::ngtcp2_cid const& id) -> int {
            if constexpr(requires{hooks_.remove_connection_id(id);})return hooks_.remove_connection_id(id);
            else return 0;
        }
        auto begin_headers(Http3&,std::int64_t id,bool trailer,void*) -> int {
            auto* state=find(id); if (!state || trailer || state->tcp) return nghttp3::err_callback_failure;
            state->headers.clear(); return 0;
        }
        auto header(Http3&,std::int64_t id,std::int32_t,nghttp3::nghttp3_rcbuf* name,nghttp3::nghttp3_rcbuf* value,std::uint8_t,bool,void*) -> int {
            auto* state=find(id); return state && state->headers.append(name,value) ? 0 : nghttp3::err_callback_failure;
        }
        auto end_headers(Http3& owner,std::int64_t id,bool,bool,void*) -> int {
            auto* state=find(id); if (!state) return nghttp3::err_callback_failure;
            if (!server_) {
                if (id!=auth_stream_ || authenticated_) return nghttp3::err_callback_failure;
                auto auth=parse_server_auth(state->headers.fields()); if (!auth) return nghttp3::err_callback_failure;
                if(congestion_)pending_congestion_=std::pair{client_congestion(*congestion_,*auth),!congestion_->disable_compensation};
                peer_auth_=*auth; authenticated_=true; signal(); return 0;
            }
            auto auth=parse_client_auth(state->headers.fields());
            // A repeated well-formed request keeps the authenticated identity
            // and the initially selected controller.
            if (auth && authenticated_) {
                auto response=ServerAuthHeaders::create(local_auth_); if (!response) return nghttp3::err_callback_failure;
                return owner.response(id,fields(response->fields()));
            }
            auto selected=auth && congestion_ ? server_congestion(*congestion_,auth->receive_bps) : std::optional<std::uint64_t>{0};
            if (auth && !authenticated_ && selected && (congestion_ || local_auth_.automatic || !auth->receive_bps) && hooks_.authenticate(*auth)) {
                if(congestion_) {
                    local_auth_.automatic=!*selected;local_auth_.receive_bps=congestion_->receive_bps;
                }
                auto response=ServerAuthHeaders::create(local_auth_); if (!response) return nghttp3::err_callback_failure;
                auto error=owner.response(id,fields(response->fields()));
                if (!error) {
                    if(congestion_)pending_congestion_=std::pair{*selected,!congestion_->disable_compensation};
                    authenticated_=true; auth_stream_=id; signal();
                }
                return error;
            }
            std::array<http::HeaderField,2> cover{{{":status","404"},{"content-length","0"}}}; return owner.response(id,fields(cover));
        }
        auto data(Http3&,std::int64_t id,std::span<std::uint8_t const> bytes,void*) -> int { return credit(id,bytes.size()); }
        auto deferred_consume(Http3&,std::int64_t id,std::size_t count,void*) -> int { return credit(id,count); }
        auto data_acked(Http3&,std::int64_t,std::uint64_t,void*) -> int { return 0; }
        auto end_stream(Http3&,std::int64_t,void*) -> int { return 0; }
        auto stream_closed(Http3&,std::uint32_t,std::int64_t,std::uint64_t,std::uint64_t,void*) -> int { return 0; }
        auto stop_sending(Http3&,std::int64_t id,std::uint64_t code,void*) -> int { return ngtcp2::ngtcp2_conn_shutdown_stream_read(transport_->native(),0,id,code); }
        auto reset_stream(Http3&,std::int64_t id,std::uint64_t code,void*) -> int { return ngtcp2::ngtcp2_conn_shutdown_stream_write(transport_->native(),0,id,code); }
        auto shutdown(Http3&,std::int64_t) -> int { return 0; }
        auto settings(Http3&,nghttp3::nghttp3_settings const&) -> int { return 0; }
        auto read_data(Http3&,std::int64_t,std::span<nghttp3::nghttp3_vec>,std::uint32_t&,void*) -> nghttp3::nghttp3_ssize { return nghttp3::err_wouldblock; }
        auto output(std::span<std::uint8_t> output,std::uint64_t now,ngtcp2::ngtcp2_path* path=nullptr) -> std::expected<std::size_t,int> {
            time_=now; if (stopping_) return std::unexpected(ngtcp2::err_callback_failure);
            auto first=output_turn_++%3;
            for (unsigned attempt=0;attempt<3;++attempt) {
                auto kind=(first+attempt)%3;
                if (kind==0 && http3_.active()) {
                    std::array<nghttp3::nghttp3_vec,16> vectors{}; auto pending=http3_.write(vectors); if (!pending) return std::unexpected(pending.error());
                    if (pending->stream!=-1) {
                        std::array<ngtcp2::ngtcp2_vec,16> data{}; for (std::size_t i=0;i<pending->vectors;++i) data[i]={vectors[i].base,vectors[i].len};
                        auto result=transport_->write_stream(output,path,nullptr,pending->stream,std::span(data).first(pending->vectors),pending->fin,now);
                        if (!result) { if (result.error()!=ngtcp2::err_stream_data_blocked) return std::unexpected(result.error()); http3_.block(pending->stream); }
                        else { if (result->stream_bytes>=0) if (auto error=http3_.accepted(pending->stream,result->stream_bytes)) return std::unexpected(error); if (result->packet_bytes) return result->packet_bytes; }
                    }
                } else if (kind==1) {
                    bool stream_credit=transport_->max_data_left()>0;
                    for (std::size_t count=0;count<Streams;++count) {
                        auto& state=streams_[cursor_++%Streams]; if (!state || !state->tcp || state->transport_closed || state->output_stopped || state->phase==StreamPhase::reset || (!state->output.pending() && (!state->output_fin || state->fin_accepted))) continue;
                        if (state->output.pending() && !stream_credit) continue;
                        auto spans=state->output.view(); std::array<ngtcp2::ngtcp2_vec,2> data{{{const_cast<std::uint8_t*>(spans[0].data()),spans[0].size()},{const_cast<std::uint8_t*>(spans[1].data()),spans[1].size()}}};
                        auto result=transport_->write_stream(output,path,nullptr,state->id,data,state->output_fin,now);
                        if (!result) { if (result.error()==ngtcp2::err_stream_data_blocked) continue; return std::unexpected(result.error()); }
                        if (result->stream_bytes>=0) { state->output.accept(result->stream_bytes); if (state->output_fin && !state->output.pending()) state->fin_accepted=true; }
                        if (result->packet_bytes) return result->packet_bytes;
                    }
                } else if (kind==2) {
                    if constexpr(requires{hooks_.datagram_output();hooks_.datagram_accepted();}) {
                        if (authenticated_) if (auto pending=hooks_.datagram_output()) {
                            auto budget=datagram_budget();
                            if (!budget || pending->header.size()>budget || pending->payload.size()>budget-pending->header.size()) {
                                if constexpr(requires{hooks_.datagram_rejected();})hooks_.datagram_rejected();
                                else return std::unexpected(ngtcp2::err_invalid_argument);
                                signal();continue;
                            }
                            std::array<ngtcp2::ngtcp2_vec,2> data{{{const_cast<std::uint8_t*>(pending->header.data()),pending->header.size()},{const_cast<std::uint8_t*>(pending->payload.data()),pending->payload.size()}}};
                            auto result=transport_->write_datagram(output,path,nullptr,0,data,now);
                            if (!result) return std::unexpected(result.error());
                            if (result->accepted) { hooks_.datagram_accepted();signal(); }
                            if (result->packet_bytes) return result->packet_bytes;
                        }
                    }
                }
            }
            return transport_->write_packet(output,path,nullptr,now);
        }
    };
}
