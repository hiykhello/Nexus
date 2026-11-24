export module grpc.multiplex;
import std;
import grpc.session;
import grpc.headers;
import grpc.message;
import http2.session_core;
import nghttp2;

export namespace grpc {
    struct RpcTicket {
        std::uint32_t slot=0,generation=0;
        std::int32_t id=0;
        auto operator==(RpcTicket const&) const -> bool = default;
    };
    namespace detail {
        template<std::size_t Capacity>
        struct MultiplexPolicy {
            using Failure=grpc::Failure;
            Role role;
            RequestProfile profile;
            ResponsePolicy response_policy;
            Limits limits;
            std::array<std::optional<GrpcPolicy>,Capacity> streams;
            std::array<std::uint32_t,Capacity> generations{};
            std::array<std::uint8_t,Capacity> accepted{};
            std::array<std::optional<std::chrono::steady_clock::time_point>,Capacity> deadlines{};
            std::optional<Failure> connection_failure;
            std::int32_t last_accepted=0,output_stream=0;
            std::optional<std::int32_t> peer_last;
            bool draining=false,frame_complete=false,output_final=false;
            MultiplexPolicy(Role value,RequestProfile const& request,ResponsePolicy response,Limits bound)
                :role(value),profile(request),response_policy(response),limits(bound) {}
            static auto core_error(http2::detail::CoreError error,int code=0) noexcept -> Failure {
                return GrpcPolicy::core_error(error,code);
            }
            auto core_fail(http2::detail::CoreError error,int code=0) noexcept -> int {
                if(!connection_failure)connection_failure=core_error(error,code);
                return h2::NGHTTP2_ERR_CALLBACK_FAILURE;
            }
            auto failure() const noexcept -> std::optional<Failure>{return connection_failure;}
            auto memory_charge() const noexcept -> std::size_t{return 0;}
            auto cleanup() noexcept -> void {for(auto& stream:streams)stream.reset();}
            auto find(std::int32_t id) noexcept -> GrpcPolicy* {
                for(auto& stream:streams)if(stream&&stream->stream_==id)return &*stream;
                return nullptr;
            }
            auto ticket(RpcTicket value) noexcept -> GrpcPolicy* {
                if(value.slot>=Capacity||generations[value.slot]!=value.generation)return nullptr;
                auto& stream=streams[value.slot];return stream&&stream->stream_==value.id?&*stream:nullptr;
            }
            auto vacant() const noexcept -> std::size_t {
                for(std::size_t i=0;i<Capacity;++i)if(!streams[i]&&generations[i]!=std::numeric_limits<std::uint32_t>::max())return i;
                return Capacity;
            }
            auto add(std::int32_t id,RequestProfile const* request=nullptr) noexcept -> std::optional<RpcTicket> {
                auto i=vacant();if(i==Capacity)return {};
                try {streams[i].emplace(role,request?*request:profile,response_policy,limits);}
                catch(...){return {};}
                streams[i]->stream_=id;accepted[i]=0;deadlines[i].reset();++generations[i];
                return RpcTicket{static_cast<std::uint32_t>(i),generations[i],id};
            }
            template<class Core> auto reject(Core& core,GrpcPolicy& stream,Failure reason) noexcept -> int {
                if(!stream.failure_)stream.failure_=reason;
                auto rc=h2::nghttp2_submit_rst_stream(core.native(),0,stream.stream_,h2::NGHTTP2_CANCEL);
                return rc?core_fail(http2::detail::CoreError::http2,rc):0;
            }
            template<class Core> auto scoped(Core& core,GrpcPolicy& stream,int result) noexcept -> int {
                if(!result)return 0;
                if(stream.failure_&&stream.failure_->error==Error::http2&&h2::nghttp2_is_fatal(stream.failure_->code))
                    return core_fail(http2::detail::CoreError::http2,stream.failure_->code);
                return reject(core,stream,stream.failure_.value_or(Failure{Error::http2,result}));
            }
            auto accepts_header(std::int32_t id) noexcept -> bool {auto* stream=find(id);return stream&&!stream->failure_;}
            template<class Core> auto reject_headers(Core& core,std::int32_t id,http2::detail::CoreError error) noexcept -> int {
                auto* stream=find(id);return stream?reject(core,*stream,core_error(error)):0;
            }
            template<class Core> auto begin(Core& core,h2::nghttp2_frame const& frame) noexcept -> int {
                if(role==Role::server&&frame.headers.cat==h2::NGHTTP2_HCAT_REQUEST){
                    if(draining||!add(frame.hd.stream_id)){
                        auto rc=h2::nghttp2_submit_rst_stream(core.native(),0,frame.hd.stream_id,h2::NGHTTP2_REFUSED_STREAM);
                        return rc?core_fail(http2::detail::CoreError::http2,rc):h2::NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
                    }
                }
                return 0;
            }
            template<class Core> auto frame(Core& core,h2::nghttp2_frame const& frame) noexcept -> int {
                if(frame.hd.type==h2::NGHTTP2_GOAWAY){
                    if(frame.goaway.error_code)return core_fail(http2::detail::CoreError::http2,static_cast<int>(frame.goaway.error_code));
                    peer_last=peer_last?std::min(*peer_last,frame.goaway.last_stream_id):frame.goaway.last_stream_id;
                    for(auto& stream:streams)if(stream&&role==Role::client&&stream->stream_>*peer_last&&!stream->failure_)
                        stream->failure_=Failure{Error::goaway};
                    return 0;
                }
                auto* stream=find(frame.hd.stream_id);if(!stream||stream->failure_)return 0;
                auto initial=!stream->ready_;
                auto result=scoped(core,*stream,stream->frame(core,frame));
                if(initial&&stream->ready_&&stream->peer_timeout_){
                    auto now=std::chrono::steady_clock::now();auto remaining=std::chrono::steady_clock::time_point::max()-now;
                    for(std::size_t i=0;i<Capacity;++i)if(streams[i]&&&*streams[i]==stream)
                        deadlines[i]=*stream->peer_timeout_>=remaining?std::chrono::steady_clock::time_point::max():now+*stream->peer_timeout_;
                }
                if(role==Role::server&&stream->ready_)last_accepted=std::max(last_accepted,stream->stream_);
                return result;
            }
            template<class Core> auto sent(Core& core,h2::nghttp2_frame const& frame) noexcept -> int {
                output_stream=frame.hd.stream_id;frame_complete=true;
                if(frame.hd.type==h2::NGHTTP2_GOAWAY){
                    draining=true;
                    if(frame.goaway.error_code)return core_fail(http2::detail::CoreError::http2,static_cast<int>(frame.goaway.error_code));
                    return 0;
                }
                auto* stream=find(frame.hd.stream_id);return stream?scoped(core,*stream,stream->sent(core,frame)):0;
            }
            template<class Core> auto before(Core&,h2::nghttp2_frame const& frame) noexcept -> int {
                output_stream=frame.hd.stream_id;frame_complete=false;return 0;
            }
            template<class Core> auto data(Core& core,std::uint8_t flags,std::int32_t id,std::span<std::uint8_t const> bytes) noexcept -> int {
                auto* stream=find(id);
                if(stream&&!stream->failure_)return scoped(core,*stream,stream->data(core,flags,id,bytes));
                auto rc=h2::nghttp2_session_consume_connection(core.native(),bytes.size());
                return rc?core_fail(http2::detail::CoreError::http2,rc):0;
            }
            template<class Core> auto closed(Core& core,std::int32_t id,std::uint32_t code) noexcept -> int {
                auto* stream=find(id);if(stream)(void)stream->closed(core,id,code);
                if(role==Role::server)for(std::size_t i=0;i<Capacity;++i)if(streams[i]&&streams[i]->stream_==id&&!(accepted[i]&1))accepted[i]|=2;
                return 0;
            }
            template<class Core> auto provide(Core& core,std::int32_t id,std::uint8_t* bytes,std::size_t count,
                std::uint32_t* flags,h2::nghttp2_data_source* source) noexcept -> h2::nghttp2_ssize {
                auto* stream=find(id);if(!stream||stream->failure_)return h2::NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
                auto result=stream->provide(core,id,bytes,count,flags,source);
                if(result<0&&result!=h2::NGHTTP2_ERR_DEFERRED&&stream->failure_&&stream->failure_->error==Error::http2&&h2::nghttp2_is_fatal(stream->failure_->code)){
                    core_fail(http2::detail::CoreError::http2,stream->failure_->code);return h2::NGHTTP2_ERR_CALLBACK_FAILURE;
                }
                return result<0&&result!=h2::NGHTTP2_ERR_DEFERRED?h2::NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE:result;
            }
        };
    }
    // A synchronous owner. One existing transport Driver serializes callbacks;
    // ticket generations prevent an old business task from touching a new RPC.
    template<std::size_t Capacity=16>
    class MultiplexSession {
        static_assert(Capacity>0&&Capacity<=1024);
        using Policy=detail::MultiplexPolicy<Capacity>;
        using Core=http2::detail::SessionCore<Policy>;
        Core core_;
        static auto settings(Limits limits) noexcept -> http2::detail::CoreLimits {
            return {std::min(limits.input_window*Capacity,std::size_t(std::numeric_limits<std::int32_t>::max())),limits.input_window,100,8192,static_cast<std::uint32_t>(Capacity),4096,4096,64};
        }
        MultiplexSession(Role role,RequestProfile const& profile,ResponsePolicy policy,Limits limits)
            :core_(settings(limits),http2::detail::LocalAccounting(limits.library_bytes),role,profile,policy,limits) {}
        auto state() noexcept -> Policy&{return core_.policy();}
        auto state() const noexcept -> Policy const&{return core_.policy();}
        auto abort_failed() noexcept -> void {
            if(!core_.failure())return;
            core_.abort_native();
            for(auto& stream:state().streams)if(stream){stream->closed_=true;if(!stream->failure_)stream->failure_=core_.failure();}
        }
        auto reclaim() noexcept -> void {
            for(std::size_t i=0;i<Capacity;++i)if((state().accepted[i]&2)&&state().streams[i]&&state().streams[i]->closed_)
                (void)release({static_cast<std::uint32_t>(i),state().generations[i],state().streams[i]->stream_});
        }
        auto stream(RpcTicket ticket) noexcept -> std::expected<detail::GrpcPolicy*,Failure> {
            if(!core_.usable())return std::unexpected(core_.failure().value_or(Failure{Error::state}));
            auto* value=state().ticket(ticket);if(!value)return std::unexpected(Failure{Error::state});
            if(value->failure_)return std::unexpected(*value->failure_);return value;
        }
    public:
        static auto create(Role role,RequestProfile const& profile,ResponsePolicy policy=ResponsePolicy::standard,Limits limits={})
            -> std::expected<std::unique_ptr<MultiplexSession>,Failure> {
            if(!detail::valid_limits(limits))return std::unexpected(Failure{Error::limit});
            std::unique_ptr<MultiplexSession> self;
            try {self.reset(new MultiplexSession(role,profile,policy,limits));}
            catch(...){return std::unexpected(Failure{Error::allocation});}
            auto started=self->core_.start(role==Role::client?http2::detail::Role::client:http2::detail::Role::server,settings(limits));
            if(!started)return std::unexpected(started.error());return self;
        }
        auto failure() const noexcept -> std::optional<Failure>{return core_.failure();}
        auto accepting() const noexcept -> bool{
            return core_.usable()&&core_.native()&&state().role==Role::client&&!state().draining&&!state().peer_last&&
                h2::nghttp2_session_check_request_allowed(core_.native())!=0;
        }
        auto available() noexcept -> bool {
            if(!accepting()||state().vacant()==Capacity)return false;
            auto active=std::ranges::count_if(state().streams,[](auto const& value){return value&&!value->closed_;});
            return active<h2::nghttp2_session_get_remote_settings(core_.native(),h2::NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS);
        }
        auto write_pending() const noexcept -> bool{return core_.write_pending();}
        auto receive(std::span<std::uint8_t const> bytes){auto result=core_.receive(bytes);abort_failed();reclaim();return result;}
        auto output(std::span<std::uint8_t> bytes){
            auto result=core_.output(bytes);
            if(result&&*result){
                state().output_final=state().frame_complete&&!core_.fragment_pending();
                for(std::size_t i=0;i<Capacity;++i)if(state().streams[i]&&state().streams[i]->stream_==state().output_stream)state().accepted[i]|=4;
            }
            abort_failed();reclaim();return result;
        }
        // A transport must acknowledge the returned chunk only after its
        // whole write completes. CONTINUATION/native-buffer and caller-size
        // fragmentation keep this RPC pending until the real last write.
        auto written() noexcept -> void {
            if(!state().output_final)return;
            for(std::size_t i=0;i<Capacity;++i)if(state().streams[i]&&state().streams[i]->stream_==state().output_stream)state().accepted[i]&=std::uint8_t(~4u);
        }
        auto output_drained(RpcTicket ticket) noexcept -> bool {return state().ticket(ticket)&&!(state().accepted[ticket.slot]&4);}
        auto open() noexcept -> std::expected<RpcTicket,Failure> {return open(state().profile);}
        auto open(RequestProfile const& request) noexcept -> std::expected<RpcTicket,Failure> {
            if(!core_.usable()||state().role!=Role::client)return std::unexpected(Failure{Error::state});
            if(state().draining||state().peer_last||!core_.native()||!h2::nghttp2_session_check_request_allowed(core_.native()))return std::unexpected(Failure{Error::goaway});
            auto active=std::ranges::count_if(state().streams,[](auto const& value){return value&&!value->closed_;});
            if(active>=h2::nghttp2_session_get_remote_settings(core_.native(),h2::NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS))return std::unexpected(Failure{Error::limit});
            if(state().vacant()==Capacity)return std::unexpected(Failure{Error::limit});
            auto added=state().add(0,&request);if(!added)return std::unexpected(Failure{Error::allocation});
            auto fields=request.request_fields();std::array<h2::nghttp2_nv,7> wire{};
            std::ranges::transform(fields,wire.begin(),detail::GrpcPolicy::nv);auto source=core_.provider();
            auto id=h2::nghttp2_submit_request2(core_.native(),nullptr,wire.data(),wire.size(),&source,nullptr);
            if(id<0){
                state().streams[added->slot].reset();
                if(h2::nghttp2_is_fatal(id)){state().core_fail(http2::detail::CoreError::http2,id);abort_failed();}
                else if(!h2::nghttp2_session_check_request_allowed(core_.native()))state().draining=true;
                return std::unexpected(Failure{Error::http2,id});
            }
            state().streams[added->slot]->stream_=id;added->id=id;return *added;
        }
        auto accept() noexcept -> std::optional<RpcTicket> {
            if(!core_.usable()||state().role!=Role::server)return {};
            for(std::size_t i=0;i<Capacity;++i)if(auto& stream=state().streams[i];stream&&stream->ready_&&!stream->failure_&&!(state().accepted[i]&3)){
                state().accepted[i]|=1;return RpcTicket{static_cast<std::uint32_t>(i),state().generations[i],stream->stream_};
            }
            return {};
        }
        auto queue(RpcTicket ticket,std::span<std::uint8_t const> bytes) noexcept -> std::expected<bool,Failure> {
            auto value=stream(ticket);if(!value)return std::unexpected(value.error());return (*value)->queue(core_,bytes);
        }
        auto close_output(RpcTicket ticket,std::uint32_t status=0) noexcept -> std::expected<void,Failure> {
            auto value=stream(ticket);if(!value)return std::unexpected(value.error());return (*value)->close_output(core_,status);
        }
        auto pull(RpcTicket ticket,std::span<std::uint8_t> bytes) noexcept -> std::expected<Pull,Failure> {
            auto value=stream(ticket);if(!value)return std::unexpected(value.error());auto result=(*value)->pull(core_,bytes);
            if(!result)(void)state().reject(core_,**value,result.error());return result;
        }
        auto reset(RpcTicket ticket,Failure reason={Error::canceled}) noexcept -> std::expected<void,Failure> {
            auto* value=state().ticket(ticket);if(!value||!core_.usable())return std::unexpected(Failure{Error::state});
            if(state().reject(core_,*value,reason))return std::unexpected(*core_.failure());return {};
        }
        auto release(RpcTicket ticket) noexcept -> std::expected<bool,Failure> {
            auto* value=state().ticket(ticket);if(!value||core_.active())return std::unexpected(Failure{Error::state});
            if(!value->closed_&&!core_.failure()){auto result=reset(ticket);if(!result)return std::unexpected(result.error());return false;}
            if(value->uncredited_&&core_.native()){
                auto rc=h2::nghttp2_session_consume_connection(core_.native(),value->uncredited_);
                if(rc)return std::unexpected(Failure{Error::http2,rc});
            }
            state().streams[ticket.slot].reset();return true;
        }
        auto return_ticket(RpcTicket ticket) noexcept -> void {
            auto* value=state().ticket(ticket);if(!value||core_.active())return;
            state().accepted[ticket.slot]|=2;
            if(!value->closed_)(void)reset(ticket);
            reclaim();
        }
        auto finish_input() noexcept -> std::expected<void,Failure> {
            state().draining=true;
            if(!all_closed()){
                if(!state().connection_failure)state().connection_failure=Failure{Error::truncated};
                return std::unexpected(*state().connection_failure);
            }
            return {};
        }
        auto all_closed() const noexcept -> bool {
            return std::ranges::none_of(state().streams,[](auto const& value){return value&&!value->closed_;});
        }
        auto transport_ended() const noexcept -> bool{return (state().draining||state().peer_last)&&all_closed()&&!failure();}
        auto shutdown() noexcept -> std::expected<void,Failure> {
            if(!core_.usable())return std::unexpected(Failure{Error::state});
            if(state().draining)return {};
            auto rc=h2::nghttp2_submit_goaway(core_.native(),0,state().last_accepted,h2::NGHTTP2_NO_ERROR,nullptr,0);
            if(rc)return std::unexpected(Failure{Error::http2,rc});state().draining=true;return {};
        }
        auto rpc_failure(RpcTicket ticket) noexcept -> std::optional<Failure> {
            auto* value=state().ticket(ticket);return value?(value->failure_?value->failure_:core_.failure()):std::optional<Failure>{{Error::state}};
        }
        auto rpc_complete(RpcTicket ticket) noexcept -> bool {auto* value=state().ticket(ticket);return value&&value->local_end_&&value->remote_end_&&!rpc_failure(ticket);}
        auto ready(RpcTicket ticket) noexcept -> bool {auto* value=state().ticket(ticket);return value&&value->ready_&&!value->failure_;}
        auto local_ended(RpcTicket ticket) noexcept -> bool {auto* value=state().ticket(ticket);return value&&value->local_end_;}
        auto remote_ended(RpcTicket ticket) noexcept -> bool {auto* value=state().ticket(ticket);return value&&value->remote_end_;}
        auto max_payload(RpcTicket ticket) noexcept -> std::size_t {auto* value=state().ticket(ticket);return value?detail::max_payload_for(value->limits_):0;}
        auto peer_timeout(RpcTicket ticket) noexcept -> std::optional<std::chrono::nanoseconds> {auto* value=state().ticket(ticket);return value?value->peer_timeout_:std::optional<std::chrono::nanoseconds>{};}
        auto peer_deadline(RpcTicket ticket) noexcept -> std::optional<std::chrono::steady_clock::time_point> {auto* value=state().ticket(ticket);return value?state().deadlines[ticket.slot]:std::optional<std::chrono::steady_clock::time_point>{};}
        auto closed(RpcTicket ticket) noexcept -> bool {auto* value=state().ticket(ticket);return value&&value->closed_;}
        auto queued_bytes(RpcTicket ticket) noexcept -> std::size_t {auto* value=state().ticket(ticket);return value?value->outgoing_bytes_:0;}
        auto retained_output_bytes(RpcTicket ticket) noexcept -> std::size_t {auto* value=state().ticket(ticket);return value?value->outgoing_reserved_:0;}
        auto uncredited_bytes(RpcTicket ticket) noexcept -> std::size_t {auto* value=state().ticket(ticket);return value?value->uncredited_:0;}
        auto library_peak() const noexcept -> std::size_t{return core_.library_peak();}
    };
}
