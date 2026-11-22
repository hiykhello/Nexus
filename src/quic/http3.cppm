export module quic.http3;
import std;
import nexus.thirdparty.nghttp3;

export namespace quic {
    struct Http3Write { std::int64_t stream=-1; std::size_t vectors=0; bool fin=false; };
    // Native HTTP3/QPACK ownership only. Hooks directly receive borrowed
    // headers/DATA and own stream limits, retained bodies and transport credit.
    // read returns framing credit; deferred_consume adds later QPACK credit.
    // DATA payload credit is returned only when Hooks consumes that payload.
    template<class Hooks>
    class Http3 {
        using Native=nex::nghttp3::nghttp3_conn;
        Hooks& hooks_;
        Native* connection_=nullptr;
        nex::nghttp3::nghttp3_mem memory_{};
        std::uint64_t last_time_=0;
        int terminal_=0;
        bool started_=false,busy_=false,stop_requested_=false,closing_=false;
        struct Call { Http3& self; ~Call() { self.busy_=false; if (self.stop_requested_) self.stop(); } };
        template<class Function> auto callback(Function&& function) noexcept -> int {
            if (stop_requested_) return nex::nghttp3::err_callback_failure;
            try { return std::forward<Function>(function)(); }
            catch (std::bad_alloc const&) { terminal_=nex::nghttp3::err_nomem; }
            catch (...) { terminal_=nex::nghttp3::err_callback_failure; }
            return nex::nghttp3::err_callback_failure;
        }
        auto result(int error) noexcept -> int {
            if (error && !terminal_) terminal_=error;
            return terminal_ ? terminal_ : error;
        }
        auto begin() noexcept -> bool {
            if (!connection_ || busy_ || terminal_ || stop_requested_) return false;
            busy_=true; return true;
        }
        static auto callbacks() noexcept -> nex::nghttp3::nghttp3_callbacks {
            using namespace nex::nghttp3;
            nghttp3_callbacks callbacks{};
            callbacks.begin_headers=[](Native*,std::int64_t stream,void* owner,void* state) noexcept -> int {
                auto& self=*static_cast<Http3*>(owner);
                return self.callback([&] { return self.hooks_.begin_headers(self,stream,false,state); });
            };
            callbacks.begin_trailers=[](Native*,std::int64_t stream,void* owner,void* state) noexcept -> int {
                auto& self=*static_cast<Http3*>(owner);
                return self.callback([&] { return self.hooks_.begin_headers(self,stream,true,state); });
            };
            callbacks.recv_header=[](Native*,std::int64_t stream,std::int32_t token,nghttp3_rcbuf* name,nghttp3_rcbuf* value,std::uint8_t flags,void* owner,void* state) noexcept -> int {
                auto& self=*static_cast<Http3*>(owner);
                return self.callback([&] { return self.hooks_.header(self,stream,token,name,value,flags,false,state); });
            };
            callbacks.recv_trailer=[](Native*,std::int64_t stream,std::int32_t token,nghttp3_rcbuf* name,nghttp3_rcbuf* value,std::uint8_t flags,void* owner,void* state) noexcept -> int {
                auto& self=*static_cast<Http3*>(owner);
                return self.callback([&] { return self.hooks_.header(self,stream,token,name,value,flags,true,state); });
            };
            callbacks.end_headers=[](Native*,std::int64_t stream,int fin,void* owner,void* state) noexcept -> int {
                auto& self=*static_cast<Http3*>(owner);
                return self.callback([&] { return self.hooks_.end_headers(self,stream,bool(fin),false,state); });
            };
            callbacks.end_trailers=[](Native*,std::int64_t stream,int fin,void* owner,void* state) noexcept -> int {
                auto& self=*static_cast<Http3*>(owner);
                return self.callback([&] { return self.hooks_.end_headers(self,stream,bool(fin),true,state); });
            };
            callbacks.recv_data=[](Native*,std::int64_t stream,std::uint8_t const* bytes,std::size_t size,void* owner,void* state) noexcept -> int {
                auto& self=*static_cast<Http3*>(owner);
                return self.callback([&] { return self.hooks_.data(self,stream,std::span(bytes,size),state); });
            };
            callbacks.deferred_consume=[](Native*,std::int64_t stream,std::size_t size,void* owner,void* state) noexcept -> int {
                auto& self=*static_cast<Http3*>(owner);
                return self.callback([&] { return self.hooks_.deferred_consume(self,stream,size,state); });
            };
            callbacks.acked_stream_data=[](Native*,std::int64_t stream,std::uint64_t size,void* owner,void* state) noexcept -> int {
                auto& self=*static_cast<Http3*>(owner);
                return self.callback([&] { return self.hooks_.data_acked(self,stream,size,state); });
            };
            callbacks.end_stream=[](Native*,std::int64_t stream,void* owner,void* state) noexcept -> int {
                auto& self=*static_cast<Http3*>(owner);
                return self.callback([&] { return self.hooks_.end_stream(self,stream,state); });
            };
            callbacks.stream_close2=[](Native*,std::uint32_t flags,std::int64_t stream,std::uint64_t rx,std::uint64_t tx,void* owner,void* state) noexcept -> int {
                auto& self=*static_cast<Http3*>(owner);
                return self.callback([&] { return self.hooks_.stream_closed(self,flags,stream,rx,tx,state); });
            };
            callbacks.stop_sending=[](Native*,std::int64_t stream,std::uint64_t code,void* owner,void* state) noexcept -> int {
                auto& self=*static_cast<Http3*>(owner);
                return self.callback([&] { return self.hooks_.stop_sending(self,stream,code,state); });
            };
            callbacks.reset_stream=[](Native*,std::int64_t stream,std::uint64_t code,void* owner,void* state) noexcept -> int {
                auto& self=*static_cast<Http3*>(owner);
                return self.callback([&] { return self.hooks_.reset_stream(self,stream,code,state); });
            };
            callbacks.shutdown=[](Native*,std::int64_t stream,void* owner) noexcept -> int {
                auto& self=*static_cast<Http3*>(owner);
                return self.callback([&] { return self.hooks_.shutdown(self,stream); });
            };
            callbacks.recv_settings=[](Native*,nghttp3_settings const* settings,void* owner) noexcept -> int {
                auto& self=*static_cast<Http3*>(owner);
                return self.callback([&] { return self.hooks_.settings(self,*settings); });
            };
            return callbacks;
        }
        static auto reader() noexcept -> nex::nghttp3::nghttp3_data_reader {
            using namespace nex::nghttp3;
            return {[](Native*,std::int64_t stream,nghttp3_vec* output,std::size_t count,std::uint32_t* flags,void* owner,void* state) noexcept -> nghttp3_ssize {
                auto& self=*static_cast<Http3*>(owner);
                if (self.stop_requested_) return err_callback_failure;
                try {
                    auto size=self.hooks_.read_data(self,stream,std::span(output,count),*flags,state);
                    if (size==err_wouldblock) return size;
                    if (size<0 || static_cast<std::size_t>(size)>count) {
                        self.result(size==err_nomem ? err_nomem : err_callback_failure); return err_callback_failure;
                    }
                    return size;
                } catch (std::bad_alloc const&) { self.terminal_=err_nomem; }
                catch (...) { self.terminal_=err_callback_failure; }
                return err_callback_failure;
            }};
        }
    public:
        explicit Http3(Hooks& hooks) noexcept:hooks_(hooks) {}
        ~Http3() { stop(); if (connection_) std::terminate(); }
        Http3(Http3 const&)=delete;
        auto operator=(Http3 const&) -> Http3& = delete;
        Http3(Http3&&)=delete;
        auto operator=(Http3&&) -> Http3& = delete;
        auto native() const noexcept -> Native* { return connection_; }
        auto active() const noexcept -> bool { return connection_ && !terminal_ && !stop_requested_; }
        auto terminal_error() const noexcept -> int { return terminal_; }
        // The allocator context and Hooks outlive stop. Native owns a copied
        // nghttp3_mem pointing to this stable direct member.
        auto start(bool server,nex::nghttp3::nghttp3_settings const& settings,nex::nghttp3::nghttp3_mem const& memory) -> int {
            using namespace nex::nghttp3;
            if (started_ || !memory.malloc || !memory.free || !memory.calloc || !memory.realloc) return err_callback_failure;
            started_=true; memory_=memory; auto events=callbacks();
            auto create=server ? nghttp3_conn_server_new_versioned : nghttp3_conn_client_new_versioned;
            auto error=create(&connection_,callbacks_version,&events,settings_version,&settings,&memory_,this);
            if (error) { result(error); stop(); }
            return error;
        }
        auto stop() noexcept -> void {
            if (!connection_) return;
            stop_requested_=true;
            if (busy_ || closing_) return;
            // QUIC retransmit queues may still borrow native H3 frame bytes.
            // closing first requests transport cancellation and returns true
            // only after that transport has released every borrowed buffer.
            // A false result retains this owner until transport's closed hook
            // invokes stop again. Destruction requires that drain to finish.
            static_assert(noexcept(hooks_.closing(*this,terminal_)));
            closing_=true; auto drained=hooks_.closing(*this,terminal_); closing_=false;
            if (!drained) return;
            stop_requested_=false;
            if (auto* native=std::exchange(connection_,nullptr)) {
                nex::nghttp3::nghttp3_conn_del(native);
                static_assert(noexcept(hooks_.connection_closed(*this,terminal_)));
                hooks_.connection_closed(*this,terminal_);
            }
        }
        auto bind(std::int64_t control,std::int64_t encoder,std::int64_t decoder) -> int {
            using namespace nex::nghttp3;
            if (!begin()) return err_callback_failure;
            Call call{*this};
            auto error=nghttp3_conn_bind_control_stream(connection_,control);
            if (!error) error=nghttp3_conn_bind_qpack_streams(connection_,encoder,decoder);
            return result(error);
        }
        auto read(std::int64_t stream,std::span<std::uint8_t const> bytes,bool fin,std::uint64_t time) -> std::expected<std::size_t,int> {
            using namespace nex::nghttp3;
            if (time<last_time_ || !begin()) return std::unexpected(err_callback_failure);
            Call call{*this}; last_time_=time;
            auto consumed=nghttp3_conn_read_stream2(connection_,stream,bytes.data(),bytes.size(),fin,time);
            if (consumed<0) return std::unexpected(result(static_cast<int>(consumed)));
            return static_cast<std::size_t>(consumed);
        }
        // Vectors borrow native frame storage or the caller's body storage.
        // Do not advance accepted bytes until QUIC has actually accepted them;
        // native/body storage remains live until acknowledged or stream close.
        auto write(std::span<nex::nghttp3::nghttp3_vec> output) -> std::expected<Http3Write,int> {
            using namespace nex::nghttp3;
            if (!begin()) return std::unexpected(err_callback_failure);
            Call call{*this}; std::int64_t stream=-1; int fin=0;
            auto count=nghttp3_conn_writev_stream(connection_,&stream,&fin,output.data(),output.size());
            if (count<0) return std::unexpected(result(static_cast<int>(count)));
            return Http3Write{stream,static_cast<std::size_t>(count),bool(fin)};
        }
        auto accepted(std::int64_t stream,std::size_t bytes) -> int {
            if (!begin()) return nex::nghttp3::err_callback_failure;
            Call call{*this}; return result(nex::nghttp3::nghttp3_conn_add_write_offset(connection_,stream,bytes));
        }
        auto acknowledged(std::int64_t stream,std::uint64_t bytes) -> int {
            if (!begin()) return nex::nghttp3::err_callback_failure;
            Call call{*this}; return result(nex::nghttp3::nghttp3_conn_add_ack_offset(connection_,stream,bytes));
        }
        auto block(std::int64_t stream) noexcept -> void { if (connection_) nex::nghttp3::nghttp3_conn_block_stream(connection_,stream); }
        auto unblock(std::int64_t stream) -> int {
            if (!begin()) return nex::nghttp3::err_callback_failure;
            Call call{*this}; return result(nex::nghttp3::nghttp3_conn_unblock_stream(connection_,stream));
        }
        auto close_stream(std::uint32_t flags,std::int64_t stream,std::uint64_t rx,std::uint64_t tx) -> int {
            if (!begin()) return nex::nghttp3::err_callback_failure;
            Call call{*this}; return result(nex::nghttp3::nghttp3_conn_close_stream2(connection_,flags,stream,rx,tx));
        }
        auto shutdown_read(std::int64_t stream) -> int {
            if (!connection_) return nex::nghttp3::err_callback_failure;
            return result(nex::nghttp3::nghttp3_conn_shutdown_stream_read(connection_,stream));
        }
        auto shutdown_write(std::int64_t stream) noexcept -> void { if (connection_) nex::nghttp3::nghttp3_conn_shutdown_stream_write(connection_,stream); }
        auto resume(std::int64_t stream) -> int {
            if (!connection_) return nex::nghttp3::err_callback_failure;
            return result(nex::nghttp3::nghttp3_conn_resume_stream(connection_,stream));
        }
        // Submission is allowed from end_headers callbacks. nghttp3 copies
        // ordinary fields before return; callers must not set NO_COPY flags
        // without retaining the corresponding storage through stream close.
        auto request(std::int64_t stream,std::span<nex::nghttp3::nghttp3_nv const> fields,bool body=false,void* state=nullptr) -> int {
            if (!connection_ || terminal_ || stop_requested_) return nex::nghttp3::err_callback_failure;
            auto data=reader(); return result(nex::nghttp3::nghttp3_conn_submit_request(connection_,stream,fields.data(),fields.size(),body ? &data : nullptr,state));
        }
        auto response(std::int64_t stream,std::span<nex::nghttp3::nghttp3_nv const> fields,bool body=false) -> int {
            if (!connection_ || terminal_ || stop_requested_) return nex::nghttp3::err_callback_failure;
            auto data=reader(); return result(nex::nghttp3::nghttp3_conn_submit_response(connection_,stream,fields.data(),fields.size(),body ? &data : nullptr));
        }
    };
}
