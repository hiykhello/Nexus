export module masque.session;
import std;
import masque.http3;
import quic.connection;
import quic.http3;
import nexus.thirdparty.ngtcp2;
import nexus.thirdparty.nghttp3;

export namespace masque {
    // Transport owner for one executor. Hooks own request authorization,
    // bounded packet queues and retained Capsule bodies; this class never
    // treats a TLS handshake or a stream ID as permission to forward UDP.
    // When Hooks queues an abort, it must immediately revoke that request's
    // receive/send permission; further frames in the same QUIC packet may
    // arrive before stream_close. Each queued abort identifies one stream.
    // The driver must join all asynchronous work before joined(), then stop
    // QUIC before H3 can release its retransmission storage.
    template<class Tls,class Hooks,bool HttpDatagrams=true> class Session {
    public:
        using Transport=quic::Connection<Tls,Session>;
        using Http3=quic::Http3<Session>;
    private:
        Tls& tls_; Hooks& hooks_; nex::nghttp3::nghttp3_mem memory_;
        Transport* transport_=nullptr;
        Http3 http3_{*this};
        std::optional<Http3DatagramBoundary> datagrams_;
        std::uint64_t time_=0,app_error_=0,remote_stream_limit_=0;
        bool server_,stopping_=false,joined_=false,handshake_=false,datagram_turn_=false;
        auto signal() noexcept -> void {static_assert(noexcept(hooks_.changed()));hooks_.changed();}
        auto credit(std::int64_t id,std::size_t size) -> int {
            auto error=nex::ngtcp2::ngtcp2_conn_extend_max_stream_offset(transport_->native(),id,size);
            if(!error)nex::ngtcp2::ngtcp2_conn_extend_max_offset(transport_->native(),size);
            return error;
        }
        auto fail(std::uint64_t code) noexcept -> int {app_error_=code;return nex::ngtcp2::err_callback_failure;}
        auto flush_aborts() -> int {
            if constexpr(requires {hooks_.take_abort();}) {
                while(auto abort=hooks_.take_abort()) {
                    if(auto error=http3_.shutdown_read(abort->first))return error;
                    http3_.shutdown_write(abort->first);
                    if(auto error=nex::ngtcp2::ngtcp2_conn_shutdown_stream(transport_->native(),0,abort->first,abort->second))return error;
                }
            }
            return 0;
        }
    public:
        Session(Tls& tls,Hooks& hooks,bool server,nex::nghttp3::nghttp3_mem const& memory) noexcept:tls_(tls),hooks_(hooks),memory_(memory),server_(server) {}
        Session(Session const&)=delete;
        auto operator=(Session const&) -> Session& = delete;
        auto attach(Transport& transport) noexcept -> void {transport_=&transport;}
        auto h3() noexcept -> Http3& {return http3_;}
        auto consume_body(std::int64_t id,std::size_t size) -> bool {
            return !stopping_ && transport_ && transport_->active() && !credit(id,size);
        }
        auto discard_body(std::size_t size) noexcept -> void {
            if (size && transport_ && transport_->active())
                nex::ngtcp2::ngtcp2_conn_extend_max_offset(transport_->native(),size);
        }
        // Called by owner after work outside any native callback queues aborts.
        auto flush_pending() -> int {return stopping_ || !transport_ || !transport_->active() ? nex::ngtcp2::err_callback_failure : flush_aborts();}
        // Driver updates before transport.read(), so nghttp3 sees the actual
        // monotonic receive time even when no writes occur.
        auto time(std::uint64_t now) noexcept -> void {time_=now;}
        auto can_request() const noexcept -> bool {return handshake_ && http3_.active() && !stopping_;}
        auto can_open() const noexcept -> bool {return datagrams_ && datagrams_->can_open_extended_connect();}
        auto application_error() const noexcept -> std::uint64_t {return app_error_;}
        auto request_stop() noexcept -> void {
            if(std::exchange(stopping_,true))return;
            if constexpr(requires {hooks_.stopping();})hooks_.stopping();
            if(datagrams_)datagrams_->stop();http3_.stop();signal();
        }
        auto stopping() const noexcept -> bool {return stopping_;}
        auto joined() noexcept -> void {joined_=true;}
        auto drain() noexcept -> void {http3_.stop();}
        auto clean() const noexcept -> bool {return !http3_.native() && (!transport_ || !transport_->native());}
        auto closing(Http3&,int) noexcept -> bool {stopping_=true;signal();return joined_ && (!transport_ || !transport_->native());}
        auto connection_closed(Http3&,int) noexcept -> void {hooks_.h3_closed();}
        auto connection_closed(Transport&,int) noexcept -> void {
            stopping_=true;if(datagrams_)datagrams_->stop();tls_.cancel();hooks_.transport_closed();http3_.stop();signal();
        }
        auto handshake_complete(Transport& transport) -> int {
            using namespace nex::ngtcp2;
            if(stopping_ || &transport!=transport_ || !tls_.complete())return err_callback_failure;
            auto* peer=ngtcp2_conn_get_remote_transport_params2(transport.native());
            auto* local=ngtcp2_conn_get_local_transport_params2(transport.native());
            if(!peer || !local || local->initial_max_streams_bidi>hooks_.stream_capacity())return err_callback_failure;
            if constexpr (HttpDatagrams) if(!local->max_datagram_frame_size)return err_callback_failure;
            nex::nghttp3::nghttp3_settings settings{};
            nex::nghttp3::nghttp3_settings_default_versioned(nex::nghttp3::settings_version,&settings);
            settings.h3_datagram=HttpDatagrams;settings.enable_connect_protocol=HttpDatagrams && server_;
            settings.qpack_max_dtable_capacity=settings.qpack_encoder_max_dtable_capacity=4096;
            settings.qpack_blocked_streams=hooks_.stream_capacity();
            if(auto error=http3_.start(server_,settings,memory_))return error;
            if(server_) {remote_stream_limit_=local->initial_max_streams_bidi;nex::nghttp3::nghttp3_conn_set_max_client_streams_bidi(http3_.native(),remote_stream_limit_);}
            nex::nghttp3::nghttp3_conn_set_max_concurrent_streams(http3_.native(),hooks_.stream_capacity());
            std::array<std::int64_t,3> ids{};
            for(auto& id:ids)if(auto error=ngtcp2_conn_open_uni_stream(transport.native(),&id,nullptr))return error;
            if constexpr (HttpDatagrams) {
                auto boundary=Http3DatagramBoundary::create(server_,ids[0]);
                if(!boundary)return err_callback_failure;
                datagrams_.emplace(std::move(*boundary));
                if(!datagrams_->peer_transport(peer->max_datagram_frame_size))return err_callback_failure;
            }
            if(auto error=http3_.bind(ids[0],ids[1],ids[2]))return error;
            handshake_=true;signal();return 0;
        }
        auto handshake_confirmed(Transport&) -> int {return 0;}
        auto stream_data(Transport&,std::uint32_t flags,std::int64_t id,std::uint64_t,std::span<std::uint8_t const> bytes,void*) -> int {
            if(stopping_ || !handshake_)return nex::ngtcp2::err_callback_failure;
            auto result=http3_.read(id,bytes,flags&nex::ngtcp2::stream_data_flag_fin,time_);
            if(!result)return nex::ngtcp2::err_callback_failure;
            if(auto error=credit(id,*result))return error;
            // Hooks may defer a malformed Capsule until nghttp3's read call
            // has unwound. Reset only its request stream, not the connection.
            return flush_aborts();
        }
        auto stream_acked(Transport&,std::int64_t id,std::uint64_t offset,std::uint64_t size,void*) -> int {
            if(datagrams_ && !datagrams_->acknowledged_stream(id,offset,size))return nex::ngtcp2::err_callback_failure;
            return http3_.active() ? http3_.acknowledged(id,size) : 0;
        }
        auto stream_close(Transport&,std::uint32_t flags,std::int64_t id,std::uint64_t rx,std::uint64_t tx,void*) -> int {
            auto error=http3_.active() ? http3_.close_stream(flags,id,rx,tx) : 0;
            hooks_.closed(id,rx,tx);
            if(server_ && (id&3)==0 && transport_->active()) {
                nex::ngtcp2::ngtcp2_conn_extend_max_streams_bidi(transport_->native(),1);
                if(remote_stream_limit_ < (std::uint64_t{1}<<60))++remote_stream_limit_;
                if(http3_.active())nex::nghttp3::nghttp3_conn_set_max_client_streams_bidi(http3_.native(),remote_stream_limit_);
            }
            signal();return error;
        }
        auto stream_reset(Transport&,std::int64_t id,std::uint64_t,std::uint64_t code,void*) -> int {hooks_.receive_closed(id,code);signal();if(auto error=http3_.shutdown_read(id))return error;return flush_aborts();}
        auto stop_sending(Transport&,std::int64_t id,std::uint64_t code,void*) -> int {hooks_.send_closed(id,code);http3_.shutdown_write(id);signal();return flush_aborts();}
        auto stream_limit(Transport&,std::int64_t id,std::uint64_t,void*) -> int {signal();return http3_.active() ? http3_.unblock(id) : 0;}
        auto stream_limit(Transport&,bool,std::uint64_t) -> int {signal();return 0;}
        auto datagram(Transport&,std::span<std::uint8_t const> bytes) -> int {
            if constexpr (!HttpDatagrams) return 0;
            else {
            if(stopping_ || !datagrams_)return nex::ngtcp2::err_callback_failure;
            auto result=datagrams_->receive(bytes,[&](auto id){return hooks_.stream_state(id);});
            switch(result.action) {
            case Http3DatagramAction::drop:return 0;
            case Http3DatagramAction::connection_error:return fail(0x33);
            case Http3DatagramAction::stream_error:return nex::ngtcp2::ngtcp2_conn_shutdown_stream(transport_->native(),0,result.stream_id,0x33);
            case Http3DatagramAction::deliver:
                if(auto error=hooks_.datagram(result.stream_id,result.payload))return error;
                return flush_aborts();
            }
            return nex::ngtcp2::err_callback_failure;
            }
        }
        auto add_connection_id(Transport&,nex::ngtcp2::ngtcp2_cid const& id,nex::ngtcp2::ngtcp2_stateless_reset_token const& token) -> int {
            if constexpr(requires{hooks_.add_connection_id(id,token);})return hooks_.add_connection_id(id,token);else return 0;
        }
        auto remove_connection_id(Transport&,nex::ngtcp2::ngtcp2_cid const& id) -> int {
            if constexpr(requires{hooks_.remove_connection_id(id);})return hooks_.remove_connection_id(id);else return 0;
        }
        auto begin_headers(Http3&,std::int64_t id,bool trailer,void*) -> int {return hooks_.begin_headers(id,trailer);}
        auto header(Http3&,std::int64_t id,std::int32_t,nex::nghttp3::nghttp3_rcbuf* name,nex::nghttp3::nghttp3_rcbuf* value,std::uint8_t,bool trailer,void*) -> int {return hooks_.header(id,name,value,trailer);}
        auto end_headers(Http3&,std::int64_t id,bool fin,bool trailer,void*) -> int {return hooks_.end_headers(id,fin,trailer);}
        auto data(Http3&,std::int64_t id,std::span<std::uint8_t const> bytes,void*) -> int {
            if (auto error=hooks_.data(id,bytes)) return error;
            if constexpr (requires {hooks_.defer_body_credit(id);})
                if (hooks_.defer_body_credit(id)) return 0;
            return credit(id,bytes.size());
        }
        auto deferred_consume(Http3&,std::int64_t id,std::size_t count,void*) -> int {return credit(id,count);}
        auto data_acked(Http3&,std::int64_t id,std::uint64_t size,void*) -> int {return hooks_.data_acked(id,size);}
        auto end_stream(Http3&,std::int64_t id,void*) -> int {return hooks_.end_stream(id);}
        auto stream_closed(Http3&,std::uint32_t,std::int64_t,std::uint64_t,std::uint64_t,void*) -> int {return 0;}
        auto stop_sending(Http3&,std::int64_t id,std::uint64_t code,void*) -> int {return nex::ngtcp2::ngtcp2_conn_shutdown_stream_read(transport_->native(),0,id,code);}
        auto reset_stream(Http3&,std::int64_t id,std::uint64_t code,void*) -> int {return nex::ngtcp2::ngtcp2_conn_shutdown_stream_write(transport_->native(),0,id,code);}
        auto shutdown(Http3&,std::int64_t id) -> int {return hooks_.shutdown(id);}
        auto settings(Http3&,nex::nghttp3::nghttp3_settings const& settings) -> int {
            if constexpr (HttpDatagrams)
                if(!datagrams_ || !datagrams_->peer_settings(settings.h3_datagram,settings.enable_connect_protocol))return nex::nghttp3::err_callback_failure;
            signal();return 0;
        }
        auto read_data(Http3&,std::int64_t id,std::span<nex::nghttp3::nghttp3_vec> output,std::uint32_t& flags,void*) -> nex::nghttp3::nghttp3_ssize {return hooks_.read_data(id,output,flags);}
        auto datagram_fits(std::uint64_t stream,std::size_t size) -> bool {
            if (!datagrams_ || !transport_ || !transport_->active()) return false;
            auto path = nex::ngtcp2::ngtcp2_conn_get_path_max_tx_udp_payload_size2(transport_->native());
            // Reserve QUIC packet and frame overhead in addition to the
            // HTTP Datagram stream prefix accounted for by send_prefix.
            if (path <= 64) return false;
            return datagrams_->send_prefix(stream,hooks_.stream_state(stream),size,
                std::min(path-64,hooks_.datagram_budget())).has_value();
        }
        auto output(std::span<std::uint8_t> output,std::uint64_t now,nex::ngtcp2::ngtcp2_path* path=nullptr) -> std::expected<std::size_t,int> {
            time_=now;if(stopping_ || !transport_)return std::unexpected(nex::ngtcp2::err_callback_failure);
            auto first=std::exchange(datagram_turn_,!datagram_turn_);
            for(unsigned turn=0;turn<2;++turn) {
              if((turn==0) != first && http3_.active()) {
                std::array<nex::nghttp3::nghttp3_vec,16> vec{};auto pending=http3_.write(vec);
                if(!pending)return std::unexpected(pending.error());
                if(pending->stream!=-1) {
                    std::array<nex::ngtcp2::ngtcp2_vec,16> data{};
                    for(std::size_t i=0;i<pending->vectors;++i)data[i]={vec[i].base,vec[i].len};
                    auto result=transport_->write_stream(output,path,nullptr,pending->stream,std::span(data).first(pending->vectors),pending->fin,now);
                    if(!result) {if(result.error()!=nex::ngtcp2::err_stream_data_blocked)return std::unexpected(result.error());http3_.block(pending->stream);}
                    else {
                        if(result->stream_bytes>=0) {
                            auto remain=static_cast<std::size_t>(result->stream_bytes);
                            for(auto const& part:std::span(vec).first(pending->vectors)) {
                                auto count=std::min(remain,part.len);
                                if(datagrams_ && count && !datagrams_->accepted_stream(pending->stream,{part.base,count}))return std::unexpected(nex::ngtcp2::err_callback_failure);
                                remain-=count;if(!remain)break;
                            }
                            if(remain)return std::unexpected(nex::ngtcp2::err_callback_failure);
                            if(auto error=http3_.accepted(pending->stream,result->stream_bytes))return std::unexpected(error);
                            if constexpr (requires {hooks_.fin_accepted(pending->stream);})
                                if (pending->fin && std::ranges::all_of(std::span(vec).first(pending->vectors),
                                    [remaining=static_cast<std::size_t>(result->stream_bytes)](auto const& part) mutable {
                                        if (part.len>remaining) return false;
                                        remaining-=part.len;
                                        return true;
                                    })) hooks_.fin_accepted(pending->stream);
                        }
                        if(result->packet_bytes)return result->packet_bytes;
                    }
                }
            }
              if constexpr (HttpDatagrams) if((turn==0) == first && datagrams_ && datagrams_->can_send_datagram())if(auto pending=hooks_.datagram_output()) {
                auto state=hooks_.stream_state(pending->stream);
                auto prefix=datagrams_->send_prefix(pending->stream,state,pending->payload.size(),hooks_.datagram_budget());
                if(!prefix) {hooks_.datagram_rejected();signal();}
                else {
                    std::array<nex::ngtcp2::ngtcp2_vec,2> data{{{prefix->bytes.data(),prefix->size},{const_cast<std::uint8_t*>(pending->payload.data()),pending->payload.size()}}};
                    auto result=transport_->write_datagram(output,path,nullptr,0,data,now);
                    if(!result)return std::unexpected(result.error());
                    if(result->accepted){hooks_.datagram_accepted();signal();}
                    if(result->packet_bytes)return result->packet_bytes;
                }
            }
            }
            return transport_->write_packet(output,path,nullptr,now);
        }
    };
}
