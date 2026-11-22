export module http2.session_core;
import std;
import http2.headers;
import memory.budget;
import nexus.thirdparty.nghttp2;

export namespace http2::detail {
    namespace h2=nex::nghttp2;
    enum class CoreError { state,limit,allocation,http2,headers };
    enum class Role { client,server };
    struct CoreLimits {
        std::size_t connection_window=65535,stream_window=65535,header_fields=100,header_bytes=8192;
        std::uint32_t concurrent_streams=1,decoder_table=4096,max_frame_size=16384;
        std::size_t encoder_table=4096,outbound_ack=64,outbound_queue_limit=5000;
    };
    class LocalAccounting {
        std::size_t limit_,used_=0,peak_=0;
    public:
        static constexpr bool shared=false;
        explicit LocalAccounting(std::size_t limit) noexcept : limit_(limit) {}
        auto admit(std::size_t size) const noexcept -> bool { return size<=limit_-used_; }
        auto add(std::size_t size) noexcept -> void { used_+=size; peak_=std::max(peak_,used_); }
        auto replace(std::size_t old,std::size_t size) noexcept -> void { peak_=std::max(peak_,used_+size); used_=used_-old+size; }
        auto remove(std::size_t size) noexcept -> void { used_-=size; }
        auto used() const noexcept -> std::size_t { return used_; }
        auto peak() const noexcept -> std::size_t { return peak_; }
    };
    class SharedAccounting : public LocalAccounting {
        std::shared_ptr<memory::Budget> budget_;
    public:
        static constexpr bool shared=true;
        SharedAccounting(std::size_t library,std::shared_ptr<memory::Budget> budget) noexcept
            : LocalAccounting(library),budget_(std::move(budget)) {}
        auto admit(std::size_t size) const noexcept -> bool { return LocalAccounting::admit(size) && available()>=size; }
        auto available() const noexcept -> std::size_t { auto used=budget_->used(); return used>budget_->limit() ? 0 : budget_->limit()-used; }
        auto attach(void* owner,std::size_t (*usage)(void*) noexcept) noexcept -> bool { return budget_->attach(owner,usage); }
        auto detach(void* owner) noexcept -> void { budget_->detach(owner); }
        auto budget() const noexcept -> std::shared_ptr<memory::Budget> const& { return budget_; }
    };
    struct EmptyCharge {};
    struct EmptyAttachment {};
    // The policy is direct storage. nghttp2's required C callbacks dispatch
    // statically to it; this engine introduces no application coroutine/heap.
    template<class Policy,class Accounting=LocalAccounting>
    class SessionCore {
        using Failure=typename Policy::Failure;
        [[no_unique_address]] Policy policy_;
        bool active_=false;
        [[no_unique_address]] std::conditional_t<Accounting::shared,bool,EmptyAttachment> attached_{};
        Accounting memory_;
        h2::nghttp2_session* session_=nullptr;
        HeaderBlock headers_;
        std::uint8_t const* output_=nullptr;
        std::size_t output_left_=0;
        [[no_unique_address]] std::conditional_t<Accounting::shared,std::size_t,EmptyCharge> field_charge_{};
        struct alignas(std::max_align_t) Allocation { std::size_t size; };
        static auto allocate(std::size_t size,void* context) noexcept -> void* {
            auto& self=*static_cast<SessionCore*>(context);
            if (size>std::numeric_limits<std::size_t>::max()-sizeof(Allocation)) return nullptr;
            auto total=size+sizeof(Allocation);
            if (!self.memory_.admit(total)) return nullptr;
            auto block=static_cast<Allocation*>(std::malloc(total));
            if (!block) return nullptr;
            block->size=total; self.memory_.add(total); return block+1;
        }
        static auto deallocate(void* pointer,void* context) noexcept -> void {
            if (!pointer) return;
            auto& self=*static_cast<SessionCore*>(context); auto block=static_cast<Allocation*>(pointer)-1;
            self.memory_.remove(block->size); std::free(block);
        }
        static auto allocate_zero(std::size_t count,std::size_t size,void* context) noexcept -> void* {
            if (size && count>std::numeric_limits<std::size_t>::max()/size) return nullptr;
            auto bytes=count*size; auto block=allocate(bytes,context); if (block) std::memset(block,0,bytes); return block;
        }
        static auto resize(void* pointer,std::size_t size,void* context) noexcept -> void* {
            if (!pointer) return allocate(size,context);
            if (!size) { deallocate(pointer,context); return nullptr; }
            auto& self=*static_cast<SessionCore*>(context); auto block=static_cast<Allocation*>(pointer)-1;
            if (size>std::numeric_limits<std::size_t>::max()-sizeof(Allocation)) return nullptr;
            auto total=size+sizeof(Allocation),old=block->size;
            if (!self.memory_.admit(total)) return nullptr;
            auto replacement=static_cast<Allocation*>(std::realloc(block,total));
            if (!replacement) return nullptr;
            replacement->size=total; self.memory_.replace(old,total); return replacement+1;
        }
        static auto begin(h2::nghttp2_session*,h2::nghttp2_frame const* frame,void* context) noexcept -> int {
            auto& self=*static_cast<SessionCore*>(context);
            auto rc=self.policy_.begin(self,*frame);
            if (!rc) self.headers_.begin(frame->hd.stream_id);
            return rc;
        }
        static auto header(h2::nghttp2_session*,h2::nghttp2_frame const* frame,std::uint8_t const* name,std::size_t n,
                           std::uint8_t const* value,std::size_t v,std::uint8_t,void* context) noexcept -> int {
            auto& self=*static_cast<SessionCore*>(context);
            if (!self.policy_.accepts_header(frame->hd.stream_id)) return 0;
            if constexpr (Accounting::shared) {
                auto available=self.memory_.available();
                if (sizeof(Header)>available || n>available-sizeof(Header) || v>available-sizeof(Header)-n)
                    return self.header_failure(frame->hd.stream_id,CoreError::limit);
                self.field_charge_=sizeof(Header)+n+v;
            }
            auto result=self.headers_.add(frame->hd.stream_id,{reinterpret_cast<char const*>(name),n},{reinterpret_cast<char const*>(value),v});
            if constexpr (Accounting::shared) self.field_charge_=0;
            return result==HeaderResult::accepted ? 0 : self.header_failure(frame->hd.stream_id,result==HeaderResult::allocation_failed ? CoreError::allocation : CoreError::headers);
        }
        auto header_failure(std::int32_t stream,CoreError error) noexcept -> int {
            headers_.discard();
            if constexpr (requires { policy_.reject_headers(*this,stream,error); }) return policy_.reject_headers(*this,stream,error);
            else return policy_.core_fail(error);
        }
        static auto frame(h2::nghttp2_session*,h2::nghttp2_frame const* frame,void* context) noexcept -> int {
            auto& self=*static_cast<SessionCore*>(context);
            auto rc=self.policy_.frame(self,*frame);
            if (frame->hd.type==h2::NGHTTP2_HEADERS) self.headers_.discard();
            return rc;
        }
        static auto sent(h2::nghttp2_session*,h2::nghttp2_frame const* frame,void* context) noexcept -> int {
            auto& self=*static_cast<SessionCore*>(context); return self.policy_.sent(self,*frame);
        }
        static auto before(h2::nghttp2_session*,h2::nghttp2_frame const* frame,void* context) noexcept -> int {
            auto& self=*static_cast<SessionCore*>(context);
            if constexpr (requires { self.policy_.before(self,*frame); }) return self.policy_.before(self,*frame);
            return 0;
        }
        static auto not_sent(h2::nghttp2_session*,h2::nghttp2_frame const* frame,int code,void* context) noexcept -> int {
            auto& self=*static_cast<SessionCore*>(context);
            if constexpr (requires { self.policy_.not_sent(self,*frame,code); }) return self.policy_.not_sent(self,*frame,code);
            return 0;
        }
        static auto data(h2::nghttp2_session*,std::uint8_t flags,std::int32_t stream,std::uint8_t const* bytes,std::size_t size,void* context) noexcept -> int {
            auto& self=*static_cast<SessionCore*>(context); return self.policy_.data(self,flags,stream,{bytes,size});
        }
        static auto closed(h2::nghttp2_session*,std::int32_t stream,std::uint32_t code,void* context) noexcept -> int {
            auto& self=*static_cast<SessionCore*>(context);
            if (self.headers_.stream()==stream) self.headers_.discard();
            return self.policy_.closed(self,stream,code);
        }
        static auto provide(h2::nghttp2_session*,std::int32_t stream,std::uint8_t* output,std::size_t size,
                            std::uint32_t* flags,h2::nghttp2_data_source* source,void* context) noexcept -> h2::nghttp2_ssize {
            auto& self=*static_cast<SessionCore*>(context); return self.policy_.provide(self,stream,output,size,flags,source);
        }
    public:
        template<class...Args>
        SessionCore(CoreLimits limits,Accounting memory,Args&&...args)
            : policy_(std::forward<Args>(args)...),memory_(std::move(memory)),headers_(limits.header_fields,limits.header_bytes) {}
        SessionCore(SessionCore const&)=delete;
        auto operator=(SessionCore const&) -> SessionCore& = delete;
        ~SessionCore() {
            // Providers and allocator context remain alive until nghttp2 dies.
            if (session_) h2::nghttp2_session_del(session_);
            policy_.cleanup(); headers_.discard();
            if constexpr (Accounting::shared) if (attached_) memory_.detach(this);
        }
        auto policy() noexcept -> Policy& { return policy_; }
        auto policy() const noexcept -> Policy const& { return policy_; }
        auto native() const noexcept -> h2::nghttp2_session* { return session_; }
        // Stop invoking providers before their caller-owned storage is released.
        // Call only outside a native callback, after any required final frame
        // has been copied and actually written by the transport owner.
        auto abort_native() noexcept -> void {
            if (auto session=std::exchange(session_,nullptr)) h2::nghttp2_session_del(session);
            output_=nullptr; output_left_=0;
        }
        auto headers() const noexcept -> HeaderBlock const& { return headers_; }
        auto usable() const noexcept -> bool { return !active_ && !policy_.failure(); }
        auto active() const noexcept -> bool { return active_; }
        auto fragment_pending() const noexcept -> bool { return output_left_!=0; }
        auto failure() const noexcept -> std::optional<Failure> { return policy_.failure(); }
        auto library_used() const noexcept -> std::size_t { return memory_.used(); }
        auto library_peak() const noexcept -> std::size_t { return memory_.peak(); }
        auto memory_charge() const noexcept -> std::size_t {
            auto extra=Accounting::shared ? sizeof(SessionCore) : 0;
            if constexpr (Accounting::shared) extra+=field_charge_;
            return extra+memory_.used()+headers_.memory_charge()+policy_.memory_charge();
        }
        auto available() const noexcept -> std::size_t {
            if constexpr (Accounting::shared) return memory_.available(); else return std::numeric_limits<std::size_t>::max();
        }
        static auto nv(std::string_view name,std::string_view value) noexcept -> h2::nghttp2_nv {
            return {reinterpret_cast<std::uint8_t*>(const_cast<char*>(name.data())),reinterpret_cast<std::uint8_t*>(const_cast<char*>(value.data())),name.size(),value.size(),0};
        }
        auto provider(void* source=nullptr) noexcept -> h2::nghttp2_data_provider2 {
            h2::nghttp2_data_provider2 result{}; result.source.ptr=source; result.read_callback=provide; return result;
        }
        auto start(Role role,CoreLimits const& limits) noexcept -> std::expected<void,Failure> {
            if (session_) return std::unexpected(Policy::core_error(CoreError::state));
            if constexpr (Accounting::shared) {
                if (!memory_.attach(this,[](void* self) noexcept { return static_cast<SessionCore*>(self)->memory_charge(); }))
                    return std::unexpected(Policy::core_error(CoreError::limit));
                attached_=true;
            }
            h2::nghttp2_session_callbacks* callbacks=nullptr; h2::nghttp2_option* option=nullptr;
            auto rc=h2::nghttp2_session_callbacks_new(&callbacks);
            if (!rc) {
                h2::nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks,begin);
                h2::nghttp2_session_callbacks_set_on_header_callback(callbacks,header);
                h2::nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,frame);
                h2::nghttp2_session_callbacks_set_on_frame_send_callback(callbacks,sent);
                if constexpr(requires(Policy& p,SessionCore& s,h2::nghttp2_frame const& f){p.before(s,f);})
                    h2::nghttp2_session_callbacks_set_before_frame_send_callback(callbacks,before);
                if constexpr(requires(Policy& p,SessionCore& s,h2::nghttp2_frame const& f){p.not_sent(s,f,0);})
                    h2::nghttp2_session_callbacks_set_on_frame_not_send_callback(callbacks,not_sent);
                h2::nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks,data);
                h2::nghttp2_session_callbacks_set_on_stream_close_callback(callbacks,closed);
                rc=h2::nghttp2_option_new(&option);
            }
            if (!rc) {
                h2::nghttp2_option_set_no_auto_window_update(option,1);
                h2::nghttp2_option_set_max_outbound_ack(option,limits.outbound_ack);
                h2::nghttp2_option_set_max_outbound_queue_size(option,limits.outbound_queue_limit);
                h2::nghttp2_option_set_max_deflate_dynamic_table_size(option,limits.encoder_table);
                h2::nghttp2_mem memory{this,allocate,deallocate,allocate_zero,resize};
                rc=role==Role::client ? h2::nghttp2_session_client_new3(&session_,callbacks,this,option,&memory) :
                    h2::nghttp2_session_server_new3(&session_,callbacks,this,option,&memory);
            }
            h2::nghttp2_option_del(option); h2::nghttp2_session_callbacks_del(callbacks);
            if (!rc) rc=h2::nghttp2_session_set_local_window_size(session_,0,0,static_cast<std::int32_t>(limits.connection_window));
            constexpr std::int32_t kSettingsMaxFrameSize = 0x5; // RFC 9113 §6.5.2
            auto const clamped_frame=std::clamp(limits.max_frame_size,std::uint32_t{16384},std::uint32_t{16777215});
            std::array<h2::nghttp2_settings_entry,5> settings{{
                {h2::NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,limits.concurrent_streams},
                {h2::NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,static_cast<std::uint32_t>(limits.stream_window)},
                {h2::NGHTTP2_SETTINGS_HEADER_TABLE_SIZE,limits.decoder_table},
                {kSettingsMaxFrameSize,clamped_frame},
                {h2::NGHTTP2_SETTINGS_ENABLE_PUSH,0}}};
            if (!rc) rc=h2::nghttp2_submit_settings(session_,0,settings.data(),role==Role::client ? 5 : 4);
            if (rc) { policy_.core_fail(CoreError::http2,rc); return std::unexpected(*failure()); }
            return {};
        }
        auto write_pending() const noexcept -> bool { return output_left_ || (session_ && h2::nghttp2_session_want_write(session_)); }
        [[nodiscard]] auto outbound_queue_size() const noexcept -> std::size_t {
            return session_ ? h2::nghttp2_session_get_outbound_queue_size(session_) : 0;
        }
        auto receive(std::span<std::uint8_t const> bytes) noexcept -> std::expected<std::size_t,Failure> {
            if (!usable() || !session_) return std::unexpected(failure().value_or(Policy::core_error(CoreError::state)));
            active_=true; auto rc=h2::nghttp2_session_mem_recv2(session_,bytes.data(),bytes.size()); active_=false;
            if (rc<0 && !failure()) policy_.core_fail(CoreError::http2,static_cast<int>(rc));
            if (failure()) return std::unexpected(*failure()); return static_cast<std::size_t>(rc);
        }
        auto output(std::span<std::uint8_t> bytes) noexcept -> std::expected<std::size_t,Failure> {
            if (!usable() || !session_) return std::unexpected(failure().value_or(Policy::core_error(CoreError::state)));
            if (bytes.empty()) return 0;
            active_=true;
            if (!output_left_) {
                auto rc=h2::nghttp2_session_mem_send2(session_,&output_);
                if (rc<0 && !failure()) policy_.core_fail(CoreError::http2,static_cast<int>(rc));
                if (rc>=0) output_left_=static_cast<std::size_t>(rc);
            }
            active_=false;
            if (failure()) return std::unexpected(*failure());
            auto count=std::min(bytes.size(),output_left_);
            if (count) { std::memcpy(bytes.data(),output_,count); output_+=count; output_left_-=count; }
            return count;
        }
    };
}
