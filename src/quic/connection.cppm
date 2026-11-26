export module quic.connection;
import std;
import crypto;
import quic.packet_keys;
import quic.packet_protection;
import ngtcp2;

export namespace quic {
    struct StreamWrite { std::size_t packet_bytes; std::ptrdiff_t stream_bytes; };
    struct DatagramWrite { std::size_t packet_bytes; bool accepted; };
    // Synchronous QUIC core: the host supplies UDP I/O, a monotonic clock,
    // bounded allocation callbacks, deadlines, cancellation and queue owners.
    // Handshake supplies raw TLS handshake messages, authenticated secret
    // events and transport parameters. TLS records never enter this adapter.
    // Application receives borrowed views only during each C callback. It
    // retains sent stream storage until stream_acked/stream_close, and returns
    // credit only for consumed bytes. Both concrete handlers outlive this owner.
    // connection_closed is noexcept and releases every remaining stream/queue
    // after native deletion, which does not emit per-stream close callbacks.
    template<class Handshake,class Application,std::size_t KeySlots=16>
    class Connection {
        using Native=ngtcp2::ngtcp2_conn;
        Handshake& handshake_;
        Application& application_;
        PacketProtection<KeySlots> protection_;
        ngtcp2::ngtcp2_mem memory_{};
        Native* connection_=nullptr;
        std::array<std::uint64_t,3> crypto_offset_{};
        std::uint64_t last_time_=0;
        int terminal_=0;
        bool started_=false,server_=false,busy_=false,stop_requested_=false,remote_parameters_=false,tls_finished_=false;
        bool client_tls_started_=false,server_early_accepted_=false;
        struct Call { Connection& owner; ~Call() { owner.busy_=false; if (owner.stop_requested_) owner.stop(); } };
        template<class Function> static auto guarded(Function&& function) noexcept -> int {
            try { return std::forward<Function>(function)(); }
            catch (std::bad_alloc const&) { return ngtcp2::err_nomem; }
            catch (...) { return ngtcp2::err_callback_failure; }
        }
        static auto random(std::uint8_t* destination,std::size_t size,ngtcp2::ngtcp2_rand_ctx const*) noexcept -> void {
            if (!crypto::random_bytes({destination,size})) std::terminate();
        }
        auto start_client_tls() -> int {
            if (std::exchange(client_tls_started_,true)) return 0;
            if constexpr(requires {handshake_.resumption_policy();})
                return handshake_.start(*this,handshake_.resumption_policy());
            else
                return handshake_.start(*this);
        }
        auto begin_call(std::uint64_t time,bool terminal_allowed=false) noexcept -> bool {
            if (!connection_ || busy_ || time<last_time_ || (terminal_ && !terminal_allowed)) return false;
            busy_=true; last_time_=time; return true;
        }
        auto write_result(ngtcp2::ngtcp2_ssize result) noexcept -> std::expected<std::size_t,int> {
            if (result>=0) return static_cast<std::size_t>(result);
            auto error=static_cast<int>(result);
            if (ngtcp2::ngtcp2_err_is_fatal(error) || error==ngtcp2::err_draining || error==ngtcp2::err_closing) terminal_=error;
            return std::unexpected(error);
        }
        static auto callbacks() noexcept -> ngtcp2::ngtcp2_callbacks {
            using namespace ngtcp2;
            ngtcp2_callbacks result{};
            result.encrypt=PacketProtection<KeySlots>::encrypt;
            result.decrypt=PacketProtection<KeySlots>::decrypt;
            result.hp_mask=PacketProtection<KeySlots>::hp_mask;
            result.rand=random;
            result.client_initial=[](Native* conn,void* owner) noexcept -> int {
                auto& self=*static_cast<Connection*>(owner);
                return guarded([&] {
                    auto* id=ngtcp2_conn_get_dcid2(conn);
                    auto error=self.protection_.install_initial(*conn,false,1,{id->data,id->datalen});
                    return error ? error : self.start_client_tls();
                });
            };
            result.recv_client_initial=[](Native* conn,ngtcp2_cid const* id,void* owner) noexcept -> int {
                return guarded([&] { return static_cast<Connection*>(owner)->protection_.install_initial(*conn,true,1,{id->data,id->datalen}); });
            };
            result.recv_retry=[](Native* conn,ngtcp2_pkt_hd const* header,void* owner) noexcept -> int {
                return guarded([&] { return static_cast<Connection*>(owner)->protection_.install_initial(*conn,false,1,{header->scid.data,header->scid.datalen}); });
            };
            result.version_negotiation=[](Native* conn,std::uint32_t version,ngtcp2_cid const* id,void* owner) noexcept -> int {
                auto& self=*static_cast<Connection*>(owner);
                return guarded([&] { return self.protection_.install_initial(*conn,self.server_,version,{id->data,id->datalen},true); });
            };
            result.recv_crypto_data=[](Native*,ngtcp2_encryption_level level,std::uint64_t offset,std::uint8_t const* data,std::size_t size,void* owner) noexcept -> int {
                auto& self=*static_cast<Connection*>(owner);
                return guarded([&] {
                    auto index=static_cast<unsigned>(level);
                    if (index>=self.crypto_offset_.size() || offset!=self.crypto_offset_[index] || size>std::numeric_limits<std::uint64_t>::max()-offset) return err_crypto;
                    int error;
                    if constexpr(requires {self.handshake_.resumption_policy();}) error=self.handshake_.receive(self,level,offset,std::span(data,size),self.handshake_.resumption_policy());
                    else error=self.handshake_.receive(self,level,offset,std::span(data,size));
                    if (!error) self.crypto_offset_[index]+=size;
                    return error;
                });
            };
            result.handshake_completed=[](Native*,void* owner) noexcept -> int {
                auto& self=*static_cast<Connection*>(owner);
                return guarded([&] { return self.tls_finished_ ? self.application_.handshake_complete(self) : err_callback_failure; });
            };
            result.handshake_confirmed=[](Native*,void* owner) noexcept -> int {
                auto& self=*static_cast<Connection*>(owner);
                return guarded([&] { return self.application_.handshake_confirmed(self); });
            };
            result.recv_stream_data=[](Native*,std::uint32_t flags,std::int64_t stream,std::uint64_t offset,std::uint8_t const* data,std::size_t size,void* owner,void* stream_owner) noexcept -> int {
                auto& self=*static_cast<Connection*>(owner);
                return guarded([&] {
                    if (flags&stream_data_flag_0rtt) {
                        if (!self.server_ || !self.server_early_accepted_) return err_callback_failure;
                        if constexpr (requires { self.application_.early_stream_data(self,flags,stream,offset,std::span(data,size),stream_owner); })
                            return self.application_.early_stream_data(self,flags,stream,offset,std::span(data,size),stream_owner);
                        return err_callback_failure;
                    }
                    return !self.tls_finished_ ? err_callback_failure : self.application_.stream_data(self,flags,stream,offset,std::span(data,size),stream_owner);
                });
            };
            result.acked_stream_data_offset=[](Native*,std::int64_t stream,std::uint64_t offset,std::uint64_t size,void* owner,void* stream_owner) noexcept -> int {
                auto& self=*static_cast<Connection*>(owner);
                return guarded([&] { return self.application_.stream_acked(self,stream,offset,size,stream_owner); });
            };
            result.stream_close2=[](Native*,std::uint32_t flags,std::int64_t stream,std::uint64_t rx_error,std::uint64_t tx_error,void* owner,void* stream_owner) noexcept -> int {
                auto& self=*static_cast<Connection*>(owner);
                return guarded([&] { return self.application_.stream_close(self,flags,stream,rx_error,tx_error,stream_owner); });
            };
            result.stream_reset=[](Native*,std::int64_t stream,std::uint64_t final_size,std::uint64_t error,void* owner,void* stream_owner) noexcept -> int {
                auto& self=*static_cast<Connection*>(owner);
                return guarded([&] { return self.application_.stream_reset(self,stream,final_size,error,stream_owner); });
            };
            result.recv_stop_sending=[](Native*,std::int64_t stream,std::uint64_t error,void* owner,void* stream_owner) noexcept -> int {
                auto& self=*static_cast<Connection*>(owner);
                return guarded([&] { return self.application_.stop_sending(self,stream,error,stream_owner); });
            };
            result.extend_max_local_streams_bidi=[](Native*,std::uint64_t maximum,void* owner) noexcept -> int {
                auto& self=*static_cast<Connection*>(owner);
                return guarded([&] { return self.application_.stream_limit(self,true,maximum); });
            };
            result.extend_max_local_streams_uni=[](Native*,std::uint64_t maximum,void* owner) noexcept -> int {
                auto& self=*static_cast<Connection*>(owner);
                return guarded([&] { return self.application_.stream_limit(self,false,maximum); });
            };
            result.extend_max_stream_data=[](Native*,std::int64_t stream,std::uint64_t maximum,void* owner,void* stream_owner) noexcept -> int {
                auto& self=*static_cast<Connection*>(owner);
                return guarded([&] { return self.application_.stream_limit(self,stream,maximum,stream_owner); });
            };
            result.recv_datagram=[](Native*,std::uint32_t flags,std::uint8_t const* data,std::size_t size,void* owner) noexcept -> int {
                auto& self=*static_cast<Connection*>(owner);
                return guarded([&] {
                    if (flags&datagram_flag_0rtt) {
                        if (!self.server_ || !self.server_early_accepted_) return err_callback_failure;
                        if constexpr (requires { self.application_.early_datagram(self,std::span(data,size)); })
                            return self.application_.early_datagram(self,std::span(data,size));
                        return err_callback_failure;
                    }
                    return !self.tls_finished_ ? err_callback_failure : self.application_.datagram(self,std::span(data,size));
                });
            };
            result.get_new_connection_id2=[](Native*,ngtcp2_cid* id,ngtcp2_stateless_reset_token* token,std::size_t size,void* owner) noexcept -> int {
                auto& self=*static_cast<Connection*>(owner);
                return guarded([&] {
                    std::array<std::uint8_t,max_cidlen> bytes{};
                    if (size>bytes.size() || !size || !crypto::random_bytes(std::span(bytes).first(size)) || !crypto::random_bytes(token->data)) return err_callback_failure;
                    ngtcp2_cid_init(id,bytes.data(),size);
                    return self.application_.add_connection_id(self,*id,*token);
                });
            };
            result.remove_connection_id=[](Native*,ngtcp2_cid const* id,void* owner) noexcept -> int {
                auto& self=*static_cast<Connection*>(owner);
                return guarded([&] { return self.application_.remove_connection_id(self,*id); });
            };
            result.get_path_challenge_data2=[](Native*,ngtcp2_path_challenge_data* data,void*) noexcept -> int {
                return crypto::random_bytes(data->data) ? 0 : err_callback_failure;
            };
            result.update_key=[](Native*,std::uint8_t* rx_secret,std::uint8_t* tx_secret,ngtcp2_crypto_aead_ctx* rx,std::uint8_t* rx_iv,ngtcp2_crypto_aead_ctx* tx,std::uint8_t* tx_iv,
                std::uint8_t const* old_rx,std::uint8_t const* old_tx,std::size_t size,void* owner) noexcept -> int {
                return static_cast<Connection*>(owner)->protection_.update(rx_secret,tx_secret,*rx,rx_iv,*tx,tx_iv,{old_rx,size},{old_tx,size});
            };
            result.delete_crypto_aead_ctx=[](Native*,ngtcp2_crypto_aead_ctx* context,void* owner) noexcept -> void {
                static_cast<Connection*>(owner)->protection_.release_aead(*context);
            };
            result.delete_crypto_cipher_ctx=[](Native*,ngtcp2_crypto_cipher_ctx* context,void* owner) noexcept -> void {
                static_cast<Connection*>(owner)->protection_.release_header(*context);
            };
            return result;
        }
    public:
        Connection(Handshake& handshake,Application& application) noexcept : handshake_(handshake),application_(application) {}
        ~Connection() { stop(); }
        Connection(Connection const&)=delete;
        auto operator=(Connection const&) -> Connection& = delete;
        Connection(Connection&&)=delete;
        auto operator=(Connection&&) -> Connection& = delete;
        // A connection is a single lifetime. The allocation callback context
        // must remain alive until stop() returns; its ngtcp2_mem is copied here.
        auto start(bool server,ngtcp2::ngtcp2_cid const& destination,ngtcp2::ngtcp2_cid const& source,ngtcp2::ngtcp2_path const& path,
            ngtcp2::ngtcp2_settings const& settings,ngtcp2::ngtcp2_transport_params const& parameters,ngtcp2::ngtcp2_mem const& memory) -> int {
            using namespace ngtcp2;
            if (started_ || source.datalen>max_cidlen || destination.datalen>max_cidlen || (!server && destination.datalen<8) ||
                !memory.malloc || !memory.free || !memory.calloc || !memory.realloc || !path.local.addr || !path.remote.addr) return err_invalid_argument;
            started_=true; server_=server; memory_=memory; last_time_=settings.initial_ts;
            auto events=callbacks();
            auto create=server ? ngtcp2_conn_server_new_versioned : ngtcp2_conn_client_new_versioned;
            auto error=create(&connection_,&destination,&source,&path,proto_ver_v1,callbacks_version,&events,settings_version,&settings,transport_params_version,&parameters,&memory_,this);
            if (!error && !server) {
                error=protection_.install_retry(*connection_);
                // Start an eligible client before the first write so ngtcp2
                // can open its early stream and coalesce it with the Initial.
                if constexpr(requires {handshake_.resumption_policy().early_suite();} || requires {handshake_.supports_early_data();}) {
                    if (!error) error=guarded([&] {return start_client_tls();});
                }
            }
            if (error) { terminal_=error; stop(); }
            return error;
        }
        auto stop() noexcept -> void {
            if (busy_) { stop_requested_=true; return; }
            stop_requested_=false;
            // Enabled material belongs to this handshake attempt and must be
            // erased even if native construction failed before a callback.
            if constexpr(requires {handshake_.resumption_policy();}) handshake_.cancel();
            if (auto* connection=std::exchange(connection_,nullptr)) {
                ngtcp2::ngtcp2_conn_del(connection);
                static_assert(noexcept(application_.connection_closed(*this,terminal_)));
                application_.connection_closed(*this,terminal_);
            }
        }
        auto server() const noexcept -> bool { return server_; }
        auto active() const noexcept -> bool { return connection_ && !terminal_; }
        auto terminal_error() const noexcept -> int { return terminal_; }
        auto key_slots() const noexcept -> std::size_t { return protection_.active_slots(); }
        auto native() const noexcept -> Native* { return connection_; }
        [[nodiscard]] auto max_data_left() const noexcept -> std::uint64_t {
            return connection_ ? ngtcp2::ngtcp2_conn_get_max_data_left_write_thresh(connection_) : 0;
        }
        auto read(ngtcp2::ngtcp2_path const& path,ngtcp2::ngtcp2_pkt_info const* info,std::span<std::uint8_t const> packet,std::uint64_t time) -> int {
            if (!begin_call(time)) return ngtcp2::err_invalid_argument;
            Call call{*this};
            auto error=ngtcp2::ngtcp2_conn_read_pkt_versioned(connection_,&path,ngtcp2::pkt_info_version,info,packet.data(),packet.size(),time);
            if (error) terminal_=error;
            return error;
        }
        auto write_packet(std::span<std::uint8_t> packet,ngtcp2::ngtcp2_path* path,ngtcp2::ngtcp2_pkt_info* info,std::uint64_t time) -> std::expected<std::size_t,int> {
            if (!begin_call(time)) return std::unexpected(ngtcp2::err_invalid_argument);
            Call call{*this};
            return write_result(ngtcp2::ngtcp2_conn_write_pkt_versioned(connection_,path,ngtcp2::pkt_info_version,info,packet.data(),packet.size(),time));
        }
        auto write_stream(std::span<std::uint8_t> packet,ngtcp2::ngtcp2_path* path,ngtcp2::ngtcp2_pkt_info* info,std::int64_t stream,
            std::span<ngtcp2::ngtcp2_vec const> data,bool fin,std::uint64_t time) -> std::expected<StreamWrite,int> {
            using namespace ngtcp2;
            if (!begin_call(time)) return std::unexpected(err_invalid_argument);
            Call call{*this}; ngtcp2_ssize consumed=-1;
            auto result=write_result(ngtcp2_conn_writev_stream_versioned(connection_,path,pkt_info_version,info,packet.data(),packet.size(),&consumed,
                fin ? write_stream_flag_fin : write_stream_flag_none,stream,data.data(),data.size(),time));
            if (!result) return std::unexpected(result.error());
            return StreamWrite{*result,consumed};
        }
        auto write_datagram(std::span<std::uint8_t> packet,ngtcp2::ngtcp2_path* path,ngtcp2::ngtcp2_pkt_info* info,std::uint64_t id,
            std::span<ngtcp2::ngtcp2_vec const> data,std::uint64_t time) -> std::expected<DatagramWrite,int> {
            using namespace ngtcp2;
            if (!begin_call(time)) return std::unexpected(err_invalid_argument);
            Call call{*this}; int accepted=0;
            auto result=write_result(ngtcp2_conn_writev_datagram_versioned(connection_,path,pkt_info_version,info,packet.data(),packet.size(),&accepted,
                write_datagram_flag_none,id,data.data(),data.size(),time));
            if (!result) return std::unexpected(result.error());
            return DatagramWrite{*result,bool(accepted)};
        }
        auto expiry() const noexcept -> std::optional<std::uint64_t> {
            if (!connection_ || terminal_) return {};
            return ngtcp2::ngtcp2_conn_get_expiry2(connection_);
        }
        auto expire(std::uint64_t time) -> int {
            if (!begin_call(time)) return ngtcp2::err_invalid_argument;
            Call call{*this}; auto error=ngtcp2::ngtcp2_conn_handle_expiry(connection_,time);
            if (error) terminal_=error;
            return error;
        }
        auto write_close(std::span<std::uint8_t> packet,ngtcp2::ngtcp2_path* path,ngtcp2::ngtcp2_pkt_info* info,
            ngtcp2::ngtcp2_ccerr const& error,std::uint64_t time) -> std::expected<std::size_t,int> {
            using namespace ngtcp2;
            if (terminal_==err_draining || terminal_==err_drop_conn || terminal_==err_retry || !begin_call(time,true)) return std::unexpected(err_invalid_argument);
            Call call{*this};
            auto result=write_result(ngtcp2_conn_write_connection_close_versioned(connection_,path,pkt_info_version,info,packet.data(),packet.size(),&error,time));
            if (result) terminal_=err_closing;
            return result;
        }
        auto submit_crypto(ngtcp2::ngtcp2_encryption_level level,std::span<std::uint8_t const> bytes) -> int {
            if (!connection_ || level==ngtcp2::NGTCP2_ENCRYPTION_LEVEL_0RTT) return ngtcp2::err_invalid_argument;
            // The native function copies these bytes into its retransmit queue.
            return ngtcp2::ngtcp2_conn_submit_crypto_data(connection_,level,bytes.data(),bytes.size());
        }
        auto install_secret(ngtcp2::ngtcp2_encryption_level level,bool transmit,PacketSuite suite,std::span<std::uint8_t const> secret) -> int {
            if (!connection_) return ngtcp2::err_invalid_argument;
            return protection_.install_secret(*connection_,level,transmit,suite,secret);
        }
        auto install_client_early_data(PacketSuite suite,std::span<std::uint8_t const> secret,
            std::span<std::uint8_t const> parameters) -> int {
            auto error=ngtcp2_abi::ngtcp2_conn_decode_and_set_0rtt_transport_params(
                connection_,parameters.data(),parameters.size());
            if (!error) error=protection_.install_client_early_secret(*connection_,suite,secret);
            if (!error) { if constexpr (requires { application_.allow_early_data(); }) application_.allow_early_data(); }
            return error;
        }
        auto install_server_early_data(PacketSuite suite,std::span<std::uint8_t const> secret) -> int {
            if (!connection_ || !server_) return ngtcp2::err_invalid_argument;
            auto error=protection_.install_early_secret(*connection_,suite,secret);
            if (!error) {
                server_early_accepted_=true;
                if constexpr (requires { application_.accept_server_early_data(); }) application_.accept_server_early_data();
            }
            return error;
        }
        auto resolve_client_early_data(bool accepted) -> int {
            if (accepted) {
                if constexpr (requires { application_.accept_early_data(); }) application_.accept_early_data();
                return 0;
            }
            auto error=ngtcp2_abi::ngtcp2_conn_tls_early_data_rejected(connection_);
            if (!error) { if constexpr (requires { application_.reject_early_data(); }) application_.reject_early_data(); }
            return error;
        }
        auto early_transport_parameters(std::span<std::uint8_t> output) -> std::span<std::uint8_t const> {
            auto size=ngtcp2_abi::ngtcp2_conn_encode_0rtt_transport_params2(connection_,output.data(),output.size());
            return size>0 ? output.first(static_cast<std::size_t>(size)) : std::span<std::uint8_t>{};
        }
        auto local_transport_parameters(std::span<std::uint8_t> output) -> std::expected<std::size_t,int> {
            if (!connection_) return std::unexpected(ngtcp2::err_invalid_argument);
            return write_result(ngtcp2::ngtcp2_conn_encode_local_transport_params2(connection_,output.data(),output.size()));
        }
        auto remote_transport_parameters(std::span<std::uint8_t const> input) -> int {
            if (!connection_ || remote_parameters_ || input.size()>65535) return ngtcp2::err_invalid_argument;
            auto error=ngtcp2::ngtcp2_conn_decode_and_set_remote_transport_params(connection_,input.data(),input.size());
            if (!error) remote_parameters_=true;
            return error;
        }
        // The raw TLS driver calls this only after its Finished and peer
        // identity checks succeed, both application keys exist, and the
        // authenticated peer transport-parameter extension has been decoded.
        auto complete_handshake() -> int {
            if (!connection_ || tls_finished_ || !remote_parameters_ || !protection_.application_keys_ready()) return ngtcp2::err_invalid_argument;
            tls_finished_=true; ngtcp2::ngtcp2_conn_tls_handshake_completed(connection_); return 0;
        }
        auto tls_alert(std::uint8_t alert) noexcept -> void {
            if (connection_) ngtcp2::ngtcp2_conn_set_tls_alert(connection_,alert);
        }
    };
}
