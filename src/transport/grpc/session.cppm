export module grpc.session;
import std;
import grpc.headers;
import grpc.message;
import http2.headers;
import http2.session_core;
import nghttp2;

export namespace grpc {
    namespace h2 = ::nghttp2;
    enum class Role { client,server };
    enum class Error { state,limit,allocation,http2,headers,message,reset,goaway,truncated,transport,timeout,canceled };
    struct Failure { Error error; int code=0; };
    struct Limits {
        std::size_t input_window=2*1024*1024,message_bytes=max_hunk_bytes+64,hunk_bytes=max_hunk_bytes;
        std::size_t output_bytes=2*1024*1024,output_messages=64,library_bytes=4*1024*1024;
        std::uint32_t idle_timeout_ms=0,ping_timeout_ms=0;
        bool permit_without_stream=false;
    };
    struct Pull { std::size_t size=0; bool eof=false; };
    namespace detail {
    inline auto valid_limits(Limits limits) noexcept -> bool {
        return limits.hunk_bytes&&limits.hunk_bytes<=max_hunk_bytes&&limits.message_bytes<=max_message_bytes&&
            limits.message_bytes>=limits.hunk_bytes+4&&limits.input_window>=limits.message_bytes+5&&
            limits.input_window<=std::size_t(std::numeric_limits<std::int32_t>::max())&&limits.output_bytes>=5&&
            limits.output_messages&&limits.output_messages<=64&&limits.library_bytes&&
            limits.idle_timeout_ms<=3600000&&limits.ping_timeout_ms<=3600000;
    }
    struct KeepaliveState {
        std::uint32_t idle_timeout_ms=0,ping_timeout_ms=0;
        bool permit_without_stream=false,ping_in_flight=false;
        std::array<std::uint8_t,8> ping_opaque{};
        std::uint64_t ping_seq=0;
        std::chrono::steady_clock::time_point last_rx=std::chrono::steady_clock::now();
        std::chrono::steady_clock::time_point ping_deadline{};
        std::size_t pings_sent=0,ping_acks=0;
        KeepaliveState() noexcept = default;
        explicit KeepaliveState(Limits const& limits) noexcept
            : idle_timeout_ms(limits.idle_timeout_ms),ping_timeout_ms(limits.ping_timeout_ms),
              permit_without_stream(limits.permit_without_stream),last_rx(std::chrono::steady_clock::now()) {}
        auto enabled() const noexcept -> bool { return idle_timeout_ms>0; }
        auto on_rx(h2::nghttp2_frame const& frame) noexcept -> void {
            last_rx=std::chrono::steady_clock::now();
            if (frame.hd.type==h2::NGHTTP2_PING && (frame.hd.flags&h2::NGHTTP2_FLAG_ACK) &&
                ping_in_flight && std::memcmp(frame.ping.opaque_data,ping_opaque.data(),8)==0) {
                ping_in_flight=false;
                ++ping_acks;
            }
        }
        auto on_activity() noexcept -> void { last_rx=std::chrono::steady_clock::now(); }
        auto on_stream_opened(bool was_empty) noexcept -> void {
            if (was_empty && !ping_in_flight) last_rx=std::chrono::steady_clock::now();
        }
        auto next_deadline(bool active_streams) const noexcept -> std::optional<std::chrono::steady_clock::time_point> {
            if (!enabled()) return {};
            if (ping_in_flight) return ping_deadline;
            if (!permit_without_stream && !active_streams) return {};
            return last_rx+std::chrono::milliseconds(idle_timeout_ms);
        }
        auto in_flight_deadline() const noexcept -> std::optional<std::chrono::steady_clock::time_point> {
            return ping_in_flight ? std::optional{ping_deadline} : std::nullopt;
        }
        auto check(h2::nghttp2_session* native,bool active_streams,std::chrono::steady_clock::time_point now) noexcept
            -> std::expected<bool,Failure> {
            if (!enabled() || !native) return false;
            if (ping_in_flight) {
                if (now>=ping_deadline) return std::unexpected(Failure{Error::timeout});
                return false;
            }
            if (!permit_without_stream && !active_streams) return false;
            if (now<last_rx+std::chrono::milliseconds(idle_timeout_ms)) return false;
            auto seq=++ping_seq;
            for (std::size_t i=0;i<8;++i) ping_opaque[i]=static_cast<std::uint8_t>((seq>>(i*8))&0xffu);
            auto rc=h2::nghttp2_submit_ping(native,h2::NGHTTP2_FLAG_NONE,ping_opaque.data());
            if (rc) return std::unexpected(Failure{Error::http2,rc});
            ping_in_flight=true;
            auto const pt=ping_timeout_ms ? ping_timeout_ms : 15000u;
            ping_deadline=now+std::chrono::milliseconds(pt);
            ++pings_sent;
            return true;
        }
    };
    struct MessageLimits {
        std::size_t input_window,message_bytes,hunk_bytes,output_bytes,output_messages;
        explicit MessageLimits(Limits value) noexcept
            : input_window(value.input_window),message_bytes(value.message_bytes),hunk_bytes(value.hunk_bytes),
              output_bytes(value.output_bytes),output_messages(value.output_messages) {}
    };
    inline auto max_payload_for(MessageLimits const& limits) noexcept -> std::size_t {
        auto const out=limits.output_bytes;
        std::size_t cap=0;
        if (out>=16384+9) cap=out-9;
        else if (out>=128+8) cap=std::min<std::size_t>(16383,out-8);
        else if (out>=8) cap=std::min<std::size_t>(127,out-7);
        return std::min(limits.hunk_bytes,cap);
    }
    struct GrpcPolicy {
        using Failure=grpc::Failure;
        Role role_;
        RequestProfile profile_;
        MessageLimits limits_;
        ResponseHeaders response_;
        MessageDecoder decoder_;
        std::int32_t stream_=0;
        std::optional<Failure> failure_;
        std::optional<std::chrono::nanoseconds> peer_timeout_;
        std::vector<std::uint8_t> input_;
        std::size_t input_offset_=0,payload_offset_=0,uncredited_=0;
        std::deque<std::vector<std::uint8_t>> outgoing_;
        std::size_t outgoing_bytes_=0,outgoing_reserved_=0,outgoing_offset_=0;
        std::string final_status_="0";
        bool ready_=false,remote_end_=false,local_end_=false,closed_=false;
        bool close_requested_=false,deferred_=false,trailer_submitted_=false;
        KeepaliveState keepalive_;
        GrpcPolicy(Role role,RequestProfile const& profile,ResponsePolicy policy,Limits limits)
            : role_(role),profile_(profile),limits_(limits),response_(policy),decoder_(limits.message_bytes,limits.hunk_bytes),keepalive_(limits) {}
        auto fail(Error error,int code=0) noexcept -> int {
            if (!failure_) failure_=Failure{error,code}; return h2::NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        auto failure() const noexcept -> std::optional<Failure> { return failure_; }
        static auto core_error(http2::detail::CoreError error,int code=0) noexcept -> Failure {
            using C=http2::detail::CoreError;
            return {error==C::state ? Error::state : error==C::limit ? Error::limit : error==C::allocation ? Error::allocation : error==C::headers ? Error::headers : Error::http2,code};
        }
        auto core_fail(http2::detail::CoreError error,int code=0) noexcept -> int { auto value=core_error(error,code); return fail(value.error,value.code); }
        auto memory_charge() const noexcept -> std::size_t { return 0; }
        auto cleanup() noexcept -> void { outgoing_.clear(); std::vector<std::uint8_t>{}.swap(input_); input_offset_=0; decoder_.close(); }
        auto accepts_header(std::int32_t id) const noexcept -> bool { return id==stream_; }
        static auto nv(FieldView field) noexcept -> h2::nghttp2_nv {
            return {reinterpret_cast<std::uint8_t*>(const_cast<char*>(field.name.data())),
                reinterpret_cast<std::uint8_t*>(const_cast<char*>(field.value.data())),field.name.size(),field.value.size(),0};
        }
        template<class Core> auto resume(Core& core) noexcept -> bool {
            if (!deferred_) return true;
            auto rc=h2::nghttp2_session_resume_data(core.native(),stream_);
            if (rc) { fail(Error::http2,rc); return false; }
            deferred_=false; return true;
        }
        template<class Core> auto provide(Core& core,std::int32_t stream,std::uint8_t* output,std::size_t length,
                            std::uint32_t* flags,h2::nghttp2_data_source*) noexcept -> h2::nghttp2_ssize {
            auto& self=*this; auto* session=core.native();
            if (self.outgoing_.empty() && !self.close_requested_) { self.deferred_=true; return h2::NGHTTP2_ERR_DEFERRED; }
            std::size_t copied=0;
            while (copied<length && !self.outgoing_.empty()) {
                auto& front=self.outgoing_.front();
                auto count=std::min(length-copied,front.size()-self.outgoing_offset_);
                std::memcpy(output+copied,front.data()+self.outgoing_offset_,count);
                copied+=count; self.outgoing_offset_+=count; self.outgoing_bytes_-=count;
                if (self.outgoing_offset_==front.size()) {
                    self.outgoing_reserved_-=front.size(); self.outgoing_.pop_front(); self.outgoing_offset_=0;
                }
            }
            if (self.outgoing_.empty() && self.close_requested_) {
                *flags|=h2::NGHTTP2_DATA_FLAG_EOF;
                if (self.role_==Role::server) {
                    *flags|=h2::NGHTTP2_DATA_FLAG_NO_END_STREAM;
                    if (!self.trailer_submitted_) {
                        auto trailer=nv({"grpc-status",self.final_status_});
                        auto rc=h2::nghttp2_submit_trailer(session,stream,&trailer,1);
                        if (rc) return self.fail(Error::http2,rc);
                        self.trailer_submitted_=true;
                    }
                }
            }
            return static_cast<h2::nghttp2_ssize>(copied);
        }
        template<class Core> auto begin(Core& core,h2::nghttp2_frame const& frame_value) noexcept -> int {
            auto& self=*this; auto* session=core.native(); auto* frame=&frame_value;
            if (self.role_==Role::server && frame->headers.cat==h2::NGHTTP2_HCAT_REQUEST) {
                if (self.stream_) {
                    auto rc=h2::nghttp2_submit_rst_stream(session,0,frame->hd.stream_id,h2::NGHTTP2_REFUSED_STREAM);
                    return rc ? self.fail(Error::http2,rc) : h2::NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
                }
                self.stream_=frame->hd.stream_id;
                // INITIAL_WINDOW_SIZE applies to existing streams when its
                // SETTINGS is acknowledged. Setting this stream manually as
                // well would apply the default-window difference twice.
            }
            return 0;
        }
        template<class Core> auto receive_headers(Core& core,bool end) noexcept -> int {
            std::array<FieldView,100> fields{}; std::size_t count=0;
            for (auto const& field:core.headers().fields()) fields[count++]={field.name,field.value};
            auto values=std::span(fields).first(count);
            if (role_==Role::server) {
                if (ready_) return fail(Error::headers);
                auto request=parse_request_headers(values,profile_);
                if (request.status!=HeaderStatus::accepted) return fail(Error::headers,static_cast<int>(request.status));
                peer_timeout_=request.timeout; ready_=true;
                auto response=response_fields(); std::array<h2::nghttp2_nv,2> wire{nv(response[0]),nv(response[1])};
                auto source=core.provider(); auto rc=h2::nghttp2_submit_response2(core.native(),stream_,wire.data(),wire.size(),&source);
                if (rc) return fail(Error::http2,rc);
            } else {
                auto status=response_.receive(values,end);
                if (status!=HeaderStatus::accepted) return fail(Error::headers,static_cast<int>(status));
                ready_=response_.initial();
            }
            remote_end_|=end; return 0;
        }
        template<class Core> auto frame(Core& core,h2::nghttp2_frame const& frame_value) noexcept -> int {
            auto& self=*this; auto* frame=&frame_value;
            self.keepalive_.on_rx(*frame);
            if (frame->hd.type==h2::NGHTTP2_GOAWAY) {
                if (frame->goaway.error_code || (self.role_==Role::client && self.stream_ && frame->goaway.last_stream_id<self.stream_))
                    return self.fail(Error::goaway,static_cast<int>(frame->goaway.error_code));
                return 0;
            }
            if (frame->hd.stream_id!=self.stream_) return 0;
            auto end=(frame->hd.flags&h2::NGHTTP2_FLAG_END_STREAM)!=0;
            if (frame->hd.type==h2::NGHTTP2_HEADERS) {
                auto rc=self.receive_headers(core,end); return rc;
            }
            if (frame->hd.type==h2::NGHTTP2_DATA && end) {
                if (self.role_==Role::client) {
                    auto status=self.response_.data_end();
                    if (status!=HeaderStatus::accepted) return self.fail(Error::headers,static_cast<int>(status));
                }
                self.remote_end_=true;
            }
            return 0;
        }
        template<class Core> auto sent(Core&,h2::nghttp2_frame const& frame_value) noexcept -> int {
            auto& self=*this; auto* frame=&frame_value;
            if (frame->hd.type==h2::NGHTTP2_GOAWAY && frame->goaway.error_code) return self.fail(Error::goaway,static_cast<int>(frame->goaway.error_code));
            if (frame->hd.stream_id==self.stream_ && (frame->hd.type==h2::NGHTTP2_HEADERS || frame->hd.type==h2::NGHTTP2_DATA) &&
                (frame->hd.flags&h2::NGHTTP2_FLAG_END_STREAM)) self.local_end_=true;
            return 0;
        }
        template<class Core> auto data(Core&,std::uint8_t,std::int32_t stream,std::span<std::uint8_t const> input) noexcept -> int {
            auto& self=*this; auto* bytes=input.data(); auto size=input.size();
            self.keepalive_.on_activity();
            if (stream!=self.stream_) return 0;
            if (!self.ready_ || self.remote_end_) return self.fail(Error::headers);
            if (size>self.limits_.input_window-self.uncredited_) return self.fail(Error::limit);
            auto left=self.input_.size()-self.input_offset_;
            if (size>self.limits_.input_window-left) return self.fail(Error::limit);
            if (self.input_offset_>0 && (self.input_offset_>=65536 || size>self.limits_.input_window-self.input_.size())) {
                if (left) std::memmove(self.input_.data(),self.input_.data()+self.input_offset_,left);
                self.input_.resize(left); self.input_offset_=0;
            }
            try { self.input_.insert(self.input_.end(),bytes,bytes+size); }
            catch (...) { return self.fail(Error::allocation); }
            self.uncredited_+=size; return 0;
        }
        template<class Core> auto closed(Core&,std::int32_t stream,std::uint32_t code) noexcept -> int {
            auto& self=*this;
            if (stream!=self.stream_) return 0;
            self.closed_=true;
            if (code) self.fail(Error::reset,static_cast<int>(code));
            return 0;
        }
        template<class Core> auto credit(Core& core) noexcept -> bool {
            auto bytes=decoder_.wire_size();
            auto rc=h2::nghttp2_session_consume(core.native(),stream_,bytes);
            if (rc) { fail(Error::http2,rc); return false; }
            uncredited_-=bytes; payload_offset_=0; return decoder_.consume();
        }
        template<class Core> auto queue(Core& core,std::span<std::uint8_t const> payload) noexcept -> std::expected<bool,Failure> {
            if (!core.usable() || close_requested_ || closed_ || (role_==Role::server && !ready_)) return std::unexpected(failure_.value_or(Failure{Error::state}));
            if (payload.size()>limits_.hunk_bytes) return std::unexpected(Failure{Error::limit});
            std::size_t varint=1; for (auto value=payload.size();value>=128;value>>=7) ++varint;
            auto size=5+(payload.empty() ? 0 : 1+varint+payload.size());
            if (size>limits_.output_bytes) return std::unexpected(Failure{Error::limit});
            if (outgoing_.size()>=limits_.output_messages || size>limits_.output_bytes-outgoing_reserved_) return false;
            try { auto encoded=encode_message(payload,limits_.hunk_bytes); if (!encoded) return std::unexpected(Failure{Error::message}); outgoing_.push_back(std::move(*encoded)); }
            catch (...) { return std::unexpected(Failure{Error::allocation}); }
            outgoing_bytes_+=size; outgoing_reserved_+=size;
            if (!resume(core)) return std::unexpected(*failure_); return true;
        }
        template<class Core> auto close_output(Core& core,std::uint32_t status=0) noexcept -> std::expected<void,Failure> {
            if (!core.usable() || close_requested_ || closed_ || (role_==Role::client && status) || (role_==Role::server && !ready_))
                return std::unexpected(failure_.value_or(Failure{Error::state}));
            try { final_status_=std::to_string(status); } catch (...) { return std::unexpected(Failure{Error::allocation}); }
            close_requested_=true; if (!resume(core)) return std::unexpected(*failure_); return {};
        }
        template<class Core> auto pull(Core& core,std::span<std::uint8_t> bytes) noexcept -> std::expected<Pull,Failure> {
            if (!core.usable()) return std::unexpected(failure_.value_or(Failure{Error::state}));
            if (bytes.empty()) return Pull{};
            for (;;) {
                if (auto payload=decoder_.data()) {
                    auto count=std::min(bytes.size(),payload->size()-payload_offset_);
                    if (count) std::memcpy(bytes.data(),payload->data()+payload_offset_,count);
                    payload_offset_+=count;
                    if (payload_offset_==payload->size() && !credit(core)) return std::unexpected(*failure_);
                    if (count) return Pull{count};
                }
                if (input_offset_<input_.size()) {
                    MessageFeed fed;
                    try { fed=decoder_.feed(std::span(input_).subspan(input_offset_)); }
                    catch (...) { fail(Error::allocation); return std::unexpected(*failure_); }
                    input_offset_+=fed.consumed;
                    if (input_offset_==input_.size()) {
                        input_.clear(); input_offset_=0;
                        if (input_.capacity()>65536) std::vector<std::uint8_t>{}.swap(input_);
                    }
                    if (fed.status==MessageStatus::accepted) continue;
                    if (fed.status!=MessageStatus::incomplete) { fail(Error::message,static_cast<int>(fed.status)); return std::unexpected(*failure_); }
                }
                if (remote_end_) {
                    if (decoder_.finish()!=MessageStatus::accepted) { fail(Error::truncated); return std::unexpected(*failure_); }
                    return Pull{0,true};
                }
                // NO_ERROR RST is still a request/response interruption to a
                // byte reader. A completed server response may use the native
                // stream terminal state only to finish its transport owner.
                if(closed_){fail(Error::reset,h2::NGHTTP2_NO_ERROR);return std::unexpected(*failure_);}
                return Pull{};
            }
        }
        template<class Core> auto finish_input(Core& core) noexcept -> std::expected<void,Failure> {
            if (!core.usable()) return std::unexpected(failure_.value_or(Failure{Error::state}));
            if (!remote_end_) { fail(Error::truncated); return std::unexpected(*failure_); } return {};
        }
    };
    }
    class Session {
        using Core=http2::detail::SessionCore<detail::GrpcPolicy>;
        Core core_;
        Session(Role role,RequestProfile const& profile,ResponsePolicy policy,Limits limits)
            : core_(http2::detail::CoreLimits{limits.input_window,limits.input_window,100,8192,1,4096,4096,64},
                http2::detail::LocalAccounting(limits.library_bytes),role,profile,policy,limits) {}
        auto state() const noexcept -> detail::GrpcPolicy const& { return core_.policy(); }
    public:
        Session(Session const&)=delete;
        auto operator=(Session const&) -> Session& = delete;
        static auto create(Role role,RequestProfile const& profile,ResponsePolicy policy=ResponsePolicy::standard,Limits limits={})
            -> std::expected<std::unique_ptr<Session>,Failure> {
            if (!detail::valid_limits(limits)) return std::unexpected(Failure{Error::limit});
            std::unique_ptr<Session> self;
            try { self.reset(new Session(role,profile,policy,limits)); }
            catch (...) { return std::unexpected(Failure{Error::allocation}); }
            auto started=self->core_.start(role==Role::client ? http2::detail::Role::client : http2::detail::Role::server,http2::detail::CoreLimits{limits.input_window,limits.input_window,100,8192,1,4096,4096,64});
            if (!started) return std::unexpected(started.error());
            if (role==Role::client) {
                auto fields=profile.request_fields(); std::array<h2::nghttp2_nv,7> wire{};
                std::ranges::transform(fields,wire.begin(),detail::GrpcPolicy::nv); auto source=self->core_.provider();
                auto id=h2::nghttp2_submit_request2(self->core_.native(),nullptr,wire.data(),wire.size(),&source,nullptr);
                if (id<0) return std::unexpected(Failure{Error::http2,id});
                self->core_.policy().stream_=id;
            }
            return self;
        }
        // This single-RPC owner cannot accept another call on its connection.
        // Announce the accepted stream before its response completes, so peer
        // connection pools open a new transport rather than racing a FIN.
        auto retire_connection() noexcept -> std::expected<void,Failure> {
            auto const& value=state();
            if (value.role_!=Role::server || !value.ready_ || !core_.usable()) return std::unexpected(Failure{Error::state});
            auto result=h2::nghttp2_submit_goaway(core_.native(),0,value.stream_,h2::NGHTTP2_NO_ERROR,nullptr,0);
            if (result) return std::unexpected(Failure{Error::http2,result});
            return {};
        }
        auto failure() const noexcept -> std::optional<Failure> { return core_.failure(); }
        auto ready() const noexcept -> bool { return state().ready_; }
        auto local_ended() const noexcept -> bool { return state().local_end_; }
        auto remote_ended() const noexcept -> bool { return state().remote_end_; }
        auto transport_ended() const noexcept -> bool {
            auto const& value=state();
            return value.local_end_&&(value.remote_end_||(value.role_==Role::server&&value.closed_))&&!value.failure_;
        }
        auto peer_timeout() const noexcept -> std::optional<std::chrono::nanoseconds> { return state().peer_timeout_; }
        auto remote_status() const noexcept -> std::optional<std::uint32_t> { return state().response_.remote_status(); }
        auto queued_bytes() const noexcept -> std::size_t { return state().outgoing_bytes_; }
        auto retained_output_bytes() const noexcept -> std::size_t { return state().outgoing_reserved_; }
        auto uncredited_bytes() const noexcept -> std::size_t { return state().uncredited_; }
        auto library_peak() const noexcept -> std::size_t { return core_.library_peak(); }
        auto max_payload() const noexcept -> std::size_t { return detail::max_payload_for(state().limits_); }
        auto write_pending() const noexcept -> bool { return core_.write_pending(); }
        auto receive(std::span<std::uint8_t const> bytes) noexcept -> std::expected<std::size_t,Failure> { return core_.receive(bytes); }
        auto output(std::span<std::uint8_t> bytes) noexcept -> std::expected<std::size_t,Failure> { return core_.output(bytes); }
        auto queue(std::span<std::uint8_t const> bytes) noexcept -> std::expected<bool,Failure> { return core_.policy().queue(core_,bytes); }
        auto close_output(std::uint32_t status=0) noexcept -> std::expected<void,Failure> { return core_.policy().close_output(core_,status); }
        auto pull(std::span<std::uint8_t> bytes) noexcept -> std::expected<Pull,Failure> { return core_.policy().pull(core_,bytes); }
        auto finish_input() noexcept -> std::expected<void,Failure> { return core_.policy().finish_input(core_); }
        auto keepalive_enabled() const noexcept -> bool { return state().keepalive_.enabled(); }
        auto has_active_streams() const noexcept -> bool { return state().stream_!=0 && !state().closed_; }
        auto next_keepalive_deadline() const noexcept -> std::optional<std::chrono::steady_clock::time_point> {
            return core_.usable() ? state().keepalive_.next_deadline(has_active_streams()) : std::nullopt;
        }
        auto ping_in_flight_deadline() const noexcept -> std::optional<std::chrono::steady_clock::time_point> {
            return core_.usable() ? state().keepalive_.in_flight_deadline() : std::nullopt;
        }
        auto check_keepalive(std::chrono::steady_clock::time_point now) noexcept -> std::expected<bool,Failure> {
            if (!core_.usable()) return std::unexpected(failure().value_or(Failure{Error::state}));
            auto res=core_.policy().keepalive_.check(core_.native(),has_active_streams(),now);
            if (!res) core_.policy().fail(res.error().error,res.error().code);
            return res;
        }
        auto pings_sent() const noexcept -> std::size_t { return state().keepalive_.pings_sent; }
        auto ping_acks_received() const noexcept -> std::size_t { return state().keepalive_.ping_acks; }
    };
}
