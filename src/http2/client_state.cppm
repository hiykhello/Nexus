export module http2.client_state;
import std;
import http2.client_types;
import http2.headers;
import http2.session_core;
import nghttp2;

export namespace http2::detail {
    template<std::size_t Capacity>
    struct ClientPolicy {
        using Failure=ClientFailure;
        std::array<std::optional<ClientStream>,Capacity> streams;
        std::array<std::uint32_t,Capacity> generations{};
        ClientLimits limits;
        std::optional<ClientFailure> connection_failure;
        std::optional<Goaway> goaway;
        std::optional<Goaway> local_goaway;
        std::size_t pending_charge=0,active_streams=0,credited_connection=0,credited_stream=0;
        std::int32_t last_id=0;
        bool local_draining=false;
        explicit ClientPolicy(ClientLimits value) : limits(value) {}
        static auto core_error(CoreError error,int code=0) noexcept -> Failure {
            auto kind=error==CoreError::state ? ClientError::state : error==CoreError::limit ? ClientError::limit :
                error==CoreError::allocation ? ClientError::allocation : error==CoreError::headers ? ClientError::headers : ClientError::http2;
            return {kind,code};
        }
        auto core_fail(CoreError error,int code=0) noexcept -> int {
            if (!connection_failure) connection_failure=core_error(error,code);
            return h2::NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        auto failure() const noexcept -> std::optional<Failure> { return connection_failure; }
        auto application_failure(bool fragment_pending) const noexcept -> std::optional<Failure> {
            if(connection_failure)return connection_failure;
            if(goaway && goaway->code)return Failure{ClientError::goaway,static_cast<int>(goaway->code)};
            if(local_goaway && local_goaway->code && !fragment_pending)return Failure{ClientError::http2,static_cast<int>(local_goaway->code)};
            return {};
        }
        auto memory_charge() const noexcept -> std::size_t {
            std::size_t result=pending_charge;
            for (auto const& stream:streams) if (stream) result+=stream->charge(); return result;
        }
        auto cleanup() noexcept -> void { for (auto& stream:streams) stream.reset(); }
        auto find(std::int32_t id) noexcept -> ClientStream* {
            for (auto& stream:streams) if (stream && stream->id==id) return &*stream; return nullptr;
        }
        auto ticket(StreamTicket value) noexcept -> ClientStream* {
            if (!value.id || value.slot>=Capacity || generations[value.slot]!=value.generation || !streams[value.slot] || streams[value.slot]->id!=value.id) return nullptr;
            return &*streams[value.slot];
        }
        auto accepts_header(std::int32_t id) noexcept -> bool { auto stream=find(id); return stream && !stream->closed && !stream->cancel_requested; }
        template<class Core>
        auto credit_connection(Core& core,std::size_t bytes) noexcept -> bool {
            if (!bytes) return true;
            auto rc=h2::nghttp2_session_consume_connection(core.native(),bytes);
            if (rc) { core_fail(CoreError::http2,rc); return false; }
            credited_connection+=bytes; return true;
        }
        template<class Core>
        auto discard_input(Core& core,ClientStream& stream) noexcept -> bool {
            auto size=stream.input.size();
            if (!credit_connection(core,size)) return false;
            stream.input.discard(); return true;
        }
        template<class Core>
        auto reject(Core& core,ClientStream& stream,ClientError error,std::uint32_t code=h2::NGHTTP2_PROTOCOL_ERROR) noexcept -> int {
            if (!stream.failure) stream.failure=Failure{error,static_cast<int>(code),stream.id};
            if (stream.cancel_requested || stream.closed) return 0;
            stream.cancel_requested=true;
            // The pinned nghttp2 submit_rst_stream cancels queued request
            // HEADERS before HPACK encoding, as well as resetting open streams.
            // Dropping an already encoded HEADERS in before_frame_send would
            // advance the encoder table without updating the peer's table.
            auto rc=h2::nghttp2_submit_rst_stream(core.native(),0,stream.id,code);
            return rc ? core_fail(CoreError::http2,rc) : 0;
        }
        template<class Core>
        auto reject_headers(Core& core,std::int32_t id,CoreError error) noexcept -> int {
            auto stream=find(id);
            if (!stream) return core_fail(CoreError::state);
            auto rc=reject(core,*stream,error==CoreError::allocation ? ClientError::allocation : ClientError::headers);
            return rc ? rc : h2::NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
        }
        template<class Core>
        auto begin(Core& core,h2::nghttp2_frame const& frame) noexcept -> int {
            if (frame.hd.type==h2::NGHTTP2_PUSH_PROMISE) {
                auto rc=h2::nghttp2_submit_rst_stream(core.native(),0,frame.push_promise.promised_stream_id,h2::NGHTTP2_REFUSED_STREAM);
                return rc ? core_fail(CoreError::http2,rc) : h2::NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
            }
            auto stream=find(frame.hd.stream_id);
            return stream && !stream->closed ? 0 : core_fail(CoreError::state);
        }
        static auto unsigned_field(std::string_view value,std::size_t& result) noexcept -> bool {
            auto [last,error]=std::from_chars(value.data(),value.data()+value.size(),result);
            return !value.empty() && error==std::errc{} && last==value.data()+value.size();
        }
        template<class Core>
        auto receive_headers(Core& core,ClientStream& stream,bool end) noexcept -> int {
            auto fields=core.headers().fields();
            std::size_t list_bytes=0; unsigned status=0; bool length_seen=false,status_seen=false;
            std::optional<std::size_t> length;
            for (auto const& field:fields) {
                auto size=field.name.size()+field.value.size()+32;
                if (size>limits.header_bytes-list_bytes) return reject(core,stream,ClientError::headers);
                list_bytes+=size;
                if (field.name==":status") {
                    std::size_t parsed=0;
                    if (stream.status || status_seen || field.value.size()!=3 || !unsigned_field(field.value,parsed) || parsed<100 || parsed>599 || parsed==101)
                        return reject(core,stream,ClientError::headers);
                    status_seen=true; status=static_cast<unsigned>(parsed);
                } else if (!field.name.empty() && field.name.front()==':') return reject(core,stream,ClientError::headers);
                else if (field.name=="content-length") {
                    std::size_t parsed=0;
                    if (stream.status || length_seen || !unsigned_field(field.value,parsed)) return reject(core,stream,ClientError::headers);
                    length=parsed; length_seen=true;
                }
            }
            if (!stream.status && !status_seen) return reject(core,stream,ClientError::headers);
            if (status && status<200) {
                if (end || length || ++stream.hints>8) return reject(core,stream,ClientError::headers);
                return 0;
            }
            if (stream.status && !end) return reject(core,stream,ClientError::headers);
            if (status==204 && length) return reject(core,stream,ClientError::headers);
            auto charge=header_charge(fields);
            if (charge>core.available()) return reject(core,stream,ClientError::limit,h2::NGHTTP2_INTERNAL_ERROR);
            pending_charge=charge;
            try {
                std::vector<Header> owned(fields.begin(),fields.end());
                if (stream.status) stream.trailers=std::move(owned); else stream.headers=std::move(owned);
            } catch (...) { pending_charge=0; return reject(core,stream,ClientError::allocation,h2::NGHTTP2_INTERNAL_ERROR); }
            pending_charge=0;
            if (status) { stream.status=status; stream.no_body=stream.head || status==204 || status==304; stream.response_length=length; }
            if (end) {
                if (!stream.no_body && stream.response_length && stream.received!=*stream.response_length) return reject(core,stream,ClientError::headers);
                stream.remote_end=true;
            }
            return 0;
        }
        template<class Core>
        auto frame(Core& core,h2::nghttp2_frame const& frame) noexcept -> int {
            if (frame.hd.type==h2::NGHTTP2_GOAWAY) {
                auto last=frame.goaway.last_stream_id;
                if (goaway && last>goaway->last_id) return core_fail(CoreError::http2,h2::NGHTTP2_PROTOCOL_ERROR);
                goaway=Goaway{last,frame.goaway.error_code};
                for (auto& stream:streams) if (stream && stream->id>last) {
                    stream->failure=Failure{ClientError::unprocessed,static_cast<int>(frame.goaway.error_code),stream->id};
                    stream->cancel_requested=true;
                }
                return 0;
            }
            auto stream=find(frame.hd.stream_id);
            if (!stream || stream->closed || stream->cancel_requested) return 0;
            auto end=(frame.hd.flags&h2::NGHTTP2_FLAG_END_STREAM)!=0;
            if (frame.hd.type==h2::NGHTTP2_HEADERS) return receive_headers(core,*stream,end);
            if (frame.hd.type==h2::NGHTTP2_DATA && end) {
                if (!stream->no_body && stream->response_length && stream->received!=*stream->response_length) return reject(core,*stream,ClientError::headers);
                stream->remote_end=true;
            }
            return 0;
        }
        template<class Core>
        auto not_sent(Core&,h2::nghttp2_frame const& frame,int code) noexcept -> int {
            auto stream=find(frame.hd.stream_id);
            if (!stream || frame.hd.type!=h2::NGHTTP2_HEADERS || stream->closed) return 0;
            if (!stream->failure) stream->failure=Failure{ClientError::http2,code,stream->id};
            stream->closed=true; stream->release_body(); --active_streams; return 0;
        }
        template<class Core>
        auto sent(Core&,h2::nghttp2_frame const& frame) noexcept -> int {
            if(frame.hd.type==h2::NGHTTP2_GOAWAY){local_draining=true;local_goaway=Goaway{frame.goaway.last_stream_id,frame.goaway.error_code};return 0;}
            auto stream=find(frame.hd.stream_id); if (!stream) return 0;
            if (frame.hd.type==h2::NGHTTP2_HEADERS) stream->headers_sent=true;
            if ((frame.hd.type==h2::NGHTTP2_HEADERS || frame.hd.type==h2::NGHTTP2_DATA) && (frame.hd.flags&h2::NGHTTP2_FLAG_END_STREAM)) stream->local_end=true;
            return 0;
        }
        template<class Core>
        auto data(Core& core,std::uint8_t,std::int32_t id,std::span<std::uint8_t const> bytes) noexcept -> int {
            auto stream=find(id);
            if (!stream) return credit_connection(core,bytes.size()) ? 0 : h2::NGHTTP2_ERR_CALLBACK_FAILURE;
            if (stream->closed || stream->cancel_requested) return credit_connection(core,bytes.size()) ? 0 : h2::NGHTTP2_ERR_CALLBACK_FAILURE;
            if (!stream->status || stream->remote_end || stream->no_body || bytes.size()>std::numeric_limits<std::size_t>::max()-stream->received ||
                (stream->response_length && bytes.size()>*stream->response_length-stream->received) || !stream->input.append(bytes)) {
                if (!credit_connection(core,bytes.size())) return h2::NGHTTP2_ERR_CALLBACK_FAILURE;
                return reject(core,*stream,ClientError::headers);
            }
            stream->received+=bytes.size(); return 0;
        }
        template<class Core>
        auto closed(Core& core,std::int32_t id,std::uint32_t code) noexcept -> int {
            auto stream=find(id); if (!stream || stream->closed) return 0;
            stream->closed=true; stream->release_body(); --active_streams;
            if (code || stream->failure || !stream->remote_end) {
                if (!stream->failure) stream->failure=Failure{ClientError::reset,static_cast<int>(code),id};
                if (!discard_input(core,*stream)) return h2::NGHTTP2_ERR_CALLBACK_FAILURE;
            }
            return 0;
        }
        template<class Core>
        auto provide(Core&,std::int32_t,std::uint8_t* output,std::size_t size,std::uint32_t* flags,h2::nghttp2_data_source* source) noexcept -> h2::nghttp2_ssize {
            auto& stream=*static_cast<ClientStream*>(source->ptr);
            if (stream.cancel_requested || stream.closed) return h2::NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
            auto count=std::min(size,stream.body.size()-stream.body_offset);
            if (count) { std::memcpy(output,stream.body.data()+stream.body_offset,count); stream.body_offset+=count; }
            if (stream.body_offset==stream.body.size()) {
                stream.release_body();
                if (stream.end_requested) *flags|=h2::NGHTTP2_DATA_FLAG_EOF;
                else if (!count) { stream.deferred=true; return h2::NGHTTP2_ERR_DEFERRED; }
            }
            return static_cast<h2::nghttp2_ssize>(count);
        }
    };
}
