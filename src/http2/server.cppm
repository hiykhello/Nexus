export module nexus.http2.server;
import std;
export import nexus.http2.headers;
import nexus.thirdparty.nghttp2;
export namespace nexus::http2 {
    namespace h2 = nex::nghttp2;
    // Views are valid only during the callback. All callbacks run synchronously
    // on the caller's thread and must not reenter the session.
    enum class DataDisposition { accepted, pause, failure };
    struct ServerEvents {
        void* context;
        bool (*headers)(void*, std::int32_t, std::span<Header const>, bool trailers, bool end_stream) noexcept;
        DataDisposition (*data)(void*, std::int32_t, std::span<std::byte const>) noexcept;
        bool (*end_stream)(void*, std::int32_t) noexcept;
        void (*closed)(void*, std::int32_t, std::uint32_t) noexcept;
    };
    struct ServerLimits {
        std::uint32_t concurrent_streams;
        std::size_t header_fields;
        std::size_t header_bytes;
        std::size_t response_bytes;
        std::size_t total_response_bytes;
        // Maximum amount of unacknowledged DATA per connection and stream.
        // The value is also the receive window restored by acknowledge/resume.
        std::size_t input_window = 65535;
        // Bound automatically generated PING and SETTINGS acknowledgements
        // when the transport cannot drain output.
        std::size_t outbound_ack_frames = 64;
        // HPACK decoder limit advertised to the peer, and local encoder cap.
        // The decoder starts at the protocol default until SETTINGS applies.
        std::uint32_t decoder_table_bytes = 4096;
        std::size_t encoder_table_bytes = 4096;
        // nghttp2 live allocations, including accounting headers; excludes
        // application buffers, TLS, transport, allocator overhead and transient realloc copies.
        std::size_t library_memory_bytes = 4 * 1024 * 1024;
        // Limits for application response headers, excluding :status.
        std::size_t response_header_fields = 32;
        std::size_t response_header_bytes = 8192;
        // Shared cap for nghttp2 live allocations, retained response bodies,
        // and logical charges for stream objects, request headers, temporary response fields
        // and the TLS driver's input, ciphertext, output and step scratch reservations.
        // Actual header capacities, other TLS buffers, transport, allocator
        // overhead and transient copies are excluded; this is not a complete budget.
        std::size_t shared_memory_bytes = std::numeric_limits<std::size_t>::max();
    };
    enum class ServerErrorKind { invalid_argument, invalid_state, allocation, library, reentrant, failed, budget_exceeded };
    struct ServerError { ServerErrorKind kind; int library_code = 0; };
    class ServerSession {
        h2::nghttp2_session* session_ = nullptr;
        struct alignas(std::max_align_t) Allocation { std::size_t size; };
        std::size_t library_limit_, shared_limit_, library_used_=0, library_peak_=0;
        static auto allocate(std::size_t size, void* context) noexcept -> void* {
            auto& self=*static_cast<ServerSession*>(context);
            if (size>std::numeric_limits<std::size_t>::max()-sizeof(Allocation)) return nullptr;
            auto total=size+sizeof(Allocation);
            if (total>self.library_limit_-self.library_used_ ||
                total>self.shared_limit_-self.response_reserved_-self.library_used_-self.stream_reserved_-self.headers_.memory_charge()-self.fields_reserved_-self.input_reserved_-self.output_reserved_-self.ciphertext_reserved_-self.scratch_reserved_) return nullptr;
            auto p=static_cast<Allocation*>(std::malloc(total));
            if (!p) return nullptr;
            p->size=total; self.library_used_+=total; self.library_peak_=std::max(self.library_peak_,self.library_used_);
            return p+1;
        }
        static void deallocate(void* ptr, void* context) noexcept {
            if (!ptr) return;
            auto& self=*static_cast<ServerSession*>(context);
            auto p=static_cast<Allocation*>(ptr)-1;
            self.library_used_-=p->size; std::free(p);
        }
        static auto allocate_zero(std::size_t count,std::size_t size,void* context) noexcept -> void* {
            if (size && count>std::numeric_limits<std::size_t>::max()/size) return nullptr;
            auto total=count*size; auto p=allocate(total,context);
            if (p) std::memset(p,0,total);
            return p;
        }
        static auto resize(void* ptr,std::size_t size,void* context) noexcept -> void* {
            if (!ptr) return allocate(size,context);
            if (!size) { deallocate(ptr,context); return nullptr; }
            auto& self=*static_cast<ServerSession*>(context);
            if (size>std::numeric_limits<std::size_t>::max()-sizeof(Allocation)) return nullptr;
            auto p=static_cast<Allocation*>(ptr)-1; auto old=p->size; auto total=size+sizeof(Allocation);
            if (total>self.library_limit_-(self.library_used_-old) ||
                total>self.shared_limit_-self.response_reserved_-(self.library_used_-old)-self.stream_reserved_-self.headers_.memory_charge()-self.fields_reserved_-self.input_reserved_-self.output_reserved_-self.ciphertext_reserved_-self.scratch_reserved_) return nullptr;
            auto replacement=static_cast<Allocation*>(std::realloc(p,total));
            if (!replacement) return nullptr;
            replacement->size=total; self.library_used_=self.library_used_-old+total;
            self.library_peak_=std::max(self.library_peak_,self.library_used_); return replacement+1;
        }
        struct Stream {
            std::int32_t id;
            bool responded = false;
            bool head_request = false;
            bool headers_received = false;
            bool reset_pending = false;
            std::unique_ptr<std::byte[]> response;
            std::size_t response_size = 0;
            std::size_t response_offset = 0;
        };
        HeaderBlock headers_;
        std::size_t max_streams_;
        std::size_t response_limit_;
        std::size_t total_response_limit_;
        std::size_t response_header_fields_, response_header_bytes_;
        std::size_t input_window_;
        std::size_t response_reserved_ = 0, stream_reserved_ = 0, fields_reserved_ = 0, input_reserved_ = 0, output_reserved_ = 0, ciphertext_reserved_ = 0, scratch_reserved_ = 0;
    public:
        auto claim_transport() noexcept -> bool { if (active_ || failed_ || transport_claimed_) return false; return transport_claimed_=true; }
        // One transport owner serializes and releases the allowance after processing borrowed input.
        auto reserve_input(std::size_t size) noexcept -> bool {
            if (active_ || failed_ || !size || input_reserved_ || size>shared_limit_-shared_memory_used()) return false;
            input_reserved_=size; return true; }
        void release_input() noexcept { input_reserved_=0; }
        // The transport owns this reservation until its asynchronous write completes.
        auto reserve_output(std::size_t size) noexcept -> bool {
            if (active_ || failed_ || !size || output_reserved_ || size>shared_limit_-shared_memory_used()) return false;
            output_reserved_=size; return true; }
        void release_output() noexcept { output_reserved_=0; }
        auto reserve_ciphertext(std::size_t size) noexcept -> bool {
            if (active_ || failed_ || !size || ciphertext_reserved_ || size>shared_limit_-shared_memory_used()) return false;
            ciphertext_reserved_=size; return true; }
        void release_ciphertext() noexcept { ciphertext_reserved_=0; }
        auto reserve_scratch(std::size_t size) noexcept -> bool {
            if (active_ || failed_ || !size || scratch_reserved_ || size>shared_limit_-shared_memory_used()) return false;
            scratch_reserved_=size; return true; }
        void release_scratch() noexcept { scratch_reserved_=0; }
        void fail_transport(bool release=true) noexcept { if (release) input_reserved_=0; failed_=true; ++revision_; }
    private:
        struct FieldsReservation { ServerSession& owner;
            ~FieldsReservation() { owner.fields_reserved_=0; }
        };
        // nghttp2 retains Stream pointers in data providers until completion.
        // Erasing a different stream must not relocate those objects.
        std::list<Stream> streams_;
        ServerEvents events_;
        std::uint8_t const* output_ = nullptr;
        std::size_t output_left_ = 0;
        std::uint64_t revision_ = 0;
        bool active_ = false;
        bool failed_ = false, transport_claimed_ = false;
        enum class Shutdown { running, notice, draining };
        Shutdown shutdown_ = Shutdown::running;
        std::int32_t paused_stream_ = 0;
        std::size_t paused_bytes_ = 0;
        ServerSession(ServerLimits limits, ServerEvents events)
            : library_limit_(limits.library_memory_bytes), shared_limit_(limits.shared_memory_bytes), headers_(limits.header_fields, limits.header_bytes), max_streams_(limits.concurrent_streams), response_limit_(limits.response_bytes), total_response_limit_(limits.total_response_bytes), response_header_fields_(limits.response_header_fields), response_header_bytes_(limits.response_header_bytes), input_window_(limits.input_window), events_(events) {
        }
        auto library_error(int rc) noexcept -> std::unexpected<ServerError> {
            if (h2::nghttp2_is_fatal(rc)) { failed_=true; ++revision_; }
            return std::unexpected(ServerError{ServerErrorKind::library, rc});
        }
        auto response_fields(unsigned status, bool head_request, std::size_t body_size, std::span<Header const> headers,
                             std::array<std::uint8_t,3>& value,
                             std::array<std::uint8_t,7>& name) noexcept
            -> std::expected<std::vector<h2::nghttp2_nv>,ServerError> {
            if (headers.size()>response_header_fields_) return std::unexpected(ServerError{ServerErrorKind::invalid_argument});
            std::size_t bytes=0;
            bool length_seen=false;
            for (auto const& header:headers) {
                if (header.name.empty() || header.name.front()==':' || header.name.size()>response_header_bytes_-bytes ||
                    header.value.size()>response_header_bytes_-bytes-header.name.size())
                    return std::unexpected(ServerError{ServerErrorKind::invalid_argument});
                bytes+=header.name.size()+header.value.size();
                if (header.name=="connection" || header.name=="proxy-connection" || header.name=="keep-alive" ||
                    header.name=="transfer-encoding" || header.name=="upgrade" || header.name=="te" ||
                    !h2::nghttp2_check_header_name(reinterpret_cast<std::uint8_t const*>(header.name.data()),header.name.size()) ||
                    !h2::nghttp2_check_header_value_rfc9113(reinterpret_cast<std::uint8_t const*>(header.value.data()),header.value.size()))
                    return std::unexpected(ServerError{ServerErrorKind::invalid_argument});
                if (header.name=="content-length") {
                    std::size_t length=0;
                    auto begin=header.value.data(), end=begin+header.value.size();
                    auto [last,error]=std::from_chars(begin,end,length);
                    if (length_seen || status==204 || begin==end || error!=std::errc{} || last!=end ||
                        (status==205 && length!=0) || (!head_request && status!=304 && length!=body_size))
                        return std::unexpected(ServerError{ServerErrorKind::invalid_argument});
                    length_seen=true;
                }
            }
            value={static_cast<std::uint8_t>('0'+status/100),static_cast<std::uint8_t>('0'+status/10%10),static_cast<std::uint8_t>('0'+status%10)};
            name={':','s','t','a','t','u','s'};
            auto available=shared_limit_-response_reserved_-library_used_-stream_reserved_-headers_.memory_charge()-input_reserved_-output_reserved_-ciphertext_reserved_-scratch_reserved_;
            if (headers.size()>=std::numeric_limits<std::size_t>::max()/sizeof(h2::nghttp2_nv) ||
                (headers.size()+1)*sizeof(h2::nghttp2_nv)>available)
                return std::unexpected(ServerError{ServerErrorKind::budget_exceeded});
            fields_reserved_=(headers.size()+1)*sizeof(h2::nghttp2_nv);
            try {
                std::vector<h2::nghttp2_nv> result;
                result.reserve(headers.size()+1);
                result.push_back({name.data(),value.data(),name.size(),value.size(),0});
                for (auto const& header:headers)
                    result.push_back({reinterpret_cast<std::uint8_t*>(const_cast<char*>(header.name.data())),
                                      reinterpret_cast<std::uint8_t*>(const_cast<char*>(header.value.data())),
                                      header.name.size(),header.value.size(),0});
                return result;
            } catch (...) { return std::unexpected(ServerError{ServerErrorKind::allocation}); }
        }
        static auto begin(h2::nghttp2_session* session, h2::nghttp2_frame const* frame, void* p) noexcept -> int {
            auto& self = *static_cast<ServerSession*>(p);
            if (frame->headers.cat == h2::NGHTTP2_HCAT_REQUEST) {
                if (self.streams_.size() >= self.max_streams_ ||
                    sizeof(Stream)>self.shared_limit_-self.response_reserved_-self.library_used_-self.stream_reserved_-self.headers_.memory_charge()-self.fields_reserved_-self.input_reserved_-self.output_reserved_-self.ciphertext_reserved_-self.scratch_reserved_) {
                    if (h2::nghttp2_submit_rst_stream(session, 0, frame->hd.stream_id, h2::NGHTTP2_REFUSED_STREAM) != 0)
                        return h2::NGHTTP2_ERR_CALLBACK_FAILURE;
                    return h2::NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
                }
                try { self.streams_.push_back({frame->hd.stream_id}); }
                catch (...) { return h2::NGHTTP2_ERR_CALLBACK_FAILURE; }
                self.stream_reserved_ += sizeof(Stream);
                if (h2::nghttp2_session_set_local_window_size(session, 0, frame->hd.stream_id,
                                                              static_cast<std::int32_t>(self.input_window_)) != 0)
                    return h2::NGHTTP2_ERR_CALLBACK_FAILURE;
            }
            self.headers_.begin(frame->hd.stream_id);
            return 0;
        }
        static auto header(h2::nghttp2_session*, h2::nghttp2_frame const* frame,
                           std::uint8_t const* name, std::size_t n,
                           std::uint8_t const* value, std::size_t v,
                           std::uint8_t, void* p) noexcept -> int {
            auto& self = *static_cast<ServerSession*>(p);
            auto available=self.shared_limit_-self.response_reserved_-self.library_used_-self.stream_reserved_-self.headers_.memory_charge()-self.fields_reserved_-self.input_reserved_-self.output_reserved_-self.ciphertext_reserved_-self.scratch_reserved_;
            if (sizeof(Header)>available || n>available-sizeof(Header) || v>available-sizeof(Header)-n) {
                self.headers_.discard();
                return h2::NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
            }
            auto result = self.headers_.add(frame->hd.stream_id,
                {reinterpret_cast<char const*>(name), n}, {reinterpret_cast<char const*>(value), v});
            if (result == HeaderResult::accepted) return 0;
            self.headers_.discard();
            return result == HeaderResult::limit_exceeded ? h2::NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE
                                                          : h2::NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        static auto frame(h2::nghttp2_session*, h2::nghttp2_frame const* f, void* p) noexcept -> int {
            auto& self = *static_cast<ServerSession*>(p);
            auto end = (f->hd.flags & h2::NGHTTP2_FLAG_END_STREAM) != 0;
            if (f->hd.type == h2::NGHTTP2_HEADERS) {
                if (self.headers_.stream() != f->hd.stream_id) return h2::NGHTTP2_ERR_CALLBACK_FAILURE;
                if (f->headers.cat==h2::NGHTTP2_HCAT_REQUEST) {
                    auto stream=std::ranges::find(self.streams_,f->hd.stream_id,&Stream::id);
                    if (stream==self.streams_.end()) return h2::NGHTTP2_ERR_CALLBACK_FAILURE;
                    auto method=std::ranges::find(self.headers_.fields(),std::string_view{":method"},&Header::name);
                    stream->head_request=method!=self.headers_.fields().end() && method->value=="HEAD";
                    stream->headers_received=true;
                }
                auto ok = self.events_.headers(self.events_.context, f->hd.stream_id, self.headers_.fields(),
                                               f->headers.cat != h2::NGHTTP2_HCAT_REQUEST, end);
                self.headers_.discard();
                return ok ? 0 : h2::NGHTTP2_ERR_CALLBACK_FAILURE;
            }
            if (f->hd.type == h2::NGHTTP2_DATA && end &&
                !self.events_.end_stream(self.events_.context, f->hd.stream_id)) return h2::NGHTTP2_ERR_CALLBACK_FAILURE;
            return 0;
        }
        static auto data(h2::nghttp2_session* session, std::uint8_t, std::int32_t id,
                         std::uint8_t const* bytes, std::size_t length, void* p) noexcept -> int {
            auto& self = *static_cast<ServerSession*>(p);
            auto disposition = self.events_.data(self.events_.context, id,
                {reinterpret_cast<std::byte const*>(bytes), length});
            if (disposition == DataDisposition::accepted) {
                // Automatic WINDOW_UPDATE is disabled.  A synchronous
                // callback has consumed the view, so acknowledge exactly the
                // bytes it accepted.  A paused callback is acknowledged by
                // resume_input after its owner has finished with the view.
                return h2::nghttp2_session_consume(session, id, length) == 0
                    ? 0 : h2::NGHTTP2_ERR_CALLBACK_FAILURE;
            }
            if (disposition == DataDisposition::pause) {
                self.paused_stream_ = id;
                self.paused_bytes_ = length;
                return h2::NGHTTP2_ERR_PAUSE;
            }
            return h2::NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        static auto read_response(h2::nghttp2_session*, std::int32_t, std::uint8_t* out,
                                  std::size_t length, std::uint32_t* flags,
                                  h2::nghttp2_data_source* source, void*) noexcept -> h2::nghttp2_ssize {
            auto& stream = *static_cast<Stream*>(source->ptr);
            auto remaining = stream.response_size - stream.response_offset;
            auto count = std::min(length, remaining);
            if (count) {
                std::memcpy(out, stream.response.get() + stream.response_offset, count);
                stream.response_offset += count;
            }
            if (stream.response_offset == stream.response_size) *flags |= h2::NGHTTP2_DATA_FLAG_EOF;
            return static_cast<h2::nghttp2_ssize>(count);
        }
        static auto closed(h2::nghttp2_session*, std::int32_t id, std::uint32_t code, void* p) noexcept -> int {
            auto& self = *static_cast<ServerSession*>(p);
            if (auto stream = std::ranges::find(self.streams_, id, &Stream::id); stream != self.streams_.end()) {
                self.response_reserved_ -= stream->response_size;
                self.stream_reserved_ -= sizeof(Stream);
                self.streams_.erase(stream);
            }
            self.events_.closed(self.events_.context, id, code);
            return 0;
        }
    public:
        ServerSession(ServerSession const&) = delete;
        auto operator=(ServerSession const&) -> ServerSession& = delete;
        ~ServerSession() { if (session_) h2::nghttp2_session_del(session_); }
        static auto create(ServerLimits limits, ServerEvents events)
            -> std::expected<std::unique_ptr<ServerSession>, ServerError> {
            if (!limits.concurrent_streams || !limits.header_fields || !limits.header_bytes || !limits.response_bytes || !limits.total_response_bytes ||
                !limits.input_window || limits.input_window > static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max()) ||
                !limits.outbound_ack_frames || !limits.library_memory_bytes || !limits.shared_memory_bytes ||
                !events.headers || !events.data || !events.end_stream || !events.closed)
                return std::unexpected(ServerError{ServerErrorKind::invalid_argument});
            std::unique_ptr<ServerSession> self;
            try { self.reset(new ServerSession(limits, events)); }
            catch (std::bad_alloc const&) { return std::unexpected(ServerError{ServerErrorKind::allocation}); }
            h2::nghttp2_session_callbacks* callbacks = nullptr;
            int rc = h2::nghttp2_session_callbacks_new(&callbacks);
            if (rc != 0) return std::unexpected(ServerError{ServerErrorKind::library, rc});
            h2::nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, begin);
            h2::nghttp2_session_callbacks_set_on_header_callback(callbacks, header);
            h2::nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, frame);
            h2::nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, data);
            h2::nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, closed);
            h2::nghttp2_option* option = nullptr;
            rc = h2::nghttp2_option_new(&option);
            if (rc == 0) {
                h2::nghttp2_option_set_no_auto_window_update(option, 1);
                h2::nghttp2_option_set_max_outbound_ack(option, limits.outbound_ack_frames);
                h2::nghttp2_option_set_max_deflate_dynamic_table_size(option, limits.encoder_table_bytes);
            }
            h2::nghttp2_mem memory{self.get(),allocate,deallocate,allocate_zero,resize};
            if (rc == 0)
                rc = h2::nghttp2_session_server_new3(&self->session_, callbacks, self.get(), option, &memory);
            h2::nghttp2_option_del(option);
            h2::nghttp2_session_callbacks_del(callbacks);
            if (rc != 0) return std::unexpected(ServerError{ServerErrorKind::library, rc});
            rc = h2::nghttp2_session_set_local_window_size(
                self->session_, 0, 0, static_cast<std::int32_t>(self->input_window_));
            if (rc != 0) return std::unexpected(ServerError{ServerErrorKind::library, rc});
            std::array<h2::nghttp2_settings_entry, 3> settings{
                h2::nghttp2_settings_entry{h2::NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, limits.concurrent_streams},
                h2::nghttp2_settings_entry{h2::NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
                                            static_cast<std::uint32_t>(limits.input_window)},
                h2::nghttp2_settings_entry{h2::NGHTTP2_SETTINGS_HEADER_TABLE_SIZE, limits.decoder_table_bytes}};
            rc = h2::nghttp2_submit_settings(self->session_, 0, settings.data(), settings.size());
            if (rc != 0) return std::unexpected(ServerError{ServerErrorKind::library, rc});
            return self;
        }
        // The caller must deliver this notice and allow time for in-flight
        // requests (normally at least one RTT) before calling finish_shutdown.
        auto start_shutdown() noexcept -> std::expected<void, ServerError> {
            if (active_) return std::unexpected(ServerError{ServerErrorKind::reentrant});
            if (failed_) return std::unexpected(ServerError{ServerErrorKind::failed});
            if (shutdown_ != Shutdown::running) return std::unexpected(ServerError{ServerErrorKind::invalid_state});
            auto rc = h2::nghttp2_submit_shutdown_notice(session_);
            if (rc != 0) return library_error(rc);
            ++revision_;
            shutdown_ = Shutdown::notice;
            return {};
        }
        // Queue the final GOAWAY without aborting accepted streams. Continue
        // receiving and draining output until shutdown_complete is true.
        auto finish_shutdown() noexcept -> std::expected<void, ServerError> {
            if (active_) return std::unexpected(ServerError{ServerErrorKind::reentrant});
            if (failed_) return std::unexpected(ServerError{ServerErrorKind::failed});
            if (shutdown_ != Shutdown::notice) return std::unexpected(ServerError{ServerErrorKind::invalid_state});
            auto last = h2::nghttp2_session_get_last_proc_stream_id(session_);
            auto rc = h2::nghttp2_submit_goaway(session_, 0, last, h2::NGHTTP2_NO_ERROR, nullptr, 0);
            if (rc != 0) return library_error(rc);
            ++revision_;
            shutdown_ = Shutdown::draining;
            return {};
        }
        auto shutdown_complete() const noexcept -> bool {
            return !active_ && !failed_ && shutdown_ == Shutdown::draining && output_left_ == 0 &&
                !h2::nghttp2_session_want_read(session_) && !h2::nghttp2_session_want_write(session_);
        }
        // Queue a stream reset. A paused DATA callback must be resumed first;
        // the close event and response-budget release occur during output.
        auto reset_stream(std::int32_t id, std::uint32_t code) noexcept -> std::expected<void, ServerError> {
            if (active_) return std::unexpected(ServerError{ServerErrorKind::reentrant});
            if (failed_) return std::unexpected(ServerError{ServerErrorKind::failed});
            if (id <= 0) return std::unexpected(ServerError{ServerErrorKind::invalid_argument});
            auto stream = std::ranges::find(streams_, id, &Stream::id);
            if (stream == streams_.end() || stream->reset_pending || paused_stream_ == id)
                return std::unexpected(ServerError{ServerErrorKind::invalid_state});
            auto rc = h2::nghttp2_submit_rst_stream(session_, 0, id, code);
            if (rc != 0) return library_error(rc);
            ++revision_;
            stream->reset_pending = true;
            return {};
        }
        // Header names must be lowercase HTTP field names. Pseudo headers,
        // connection-specific fields are not accepted. Content-Length must
        // match the body; for HEAD/304 the caller supplies the selected representation length.
        // nghttp2 copies the fields during submission.
        auto respond_body(std::int32_t id, unsigned status, std::span<std::byte const> body,
                          std::span<Header const> headers = {}) noexcept
            -> std::expected<void, ServerError> {
            if (active_) return std::unexpected(ServerError{ServerErrorKind::reentrant});
            if (failed_) return std::unexpected(ServerError{ServerErrorKind::failed});
            if (id <= 0 || status < 200 || status > 599)
                return std::unexpected(ServerError{ServerErrorKind::invalid_argument});
            auto stream = std::ranges::find(streams_, id, &Stream::id);
            if (stream == streams_.end() || !stream->headers_received || stream->responded || stream->reset_pending)
                return std::unexpected(ServerError{ServerErrorKind::invalid_state});
            if (body.size() > response_limit_ || body.size() > total_response_limit_ - response_reserved_ ||
                (body.size() != 0 && (stream->head_request || status == 204 || status == 205 || status == 304)))
                return std::unexpected(ServerError{ServerErrorKind::invalid_argument});
            if (stream->head_request || status==204 || status==205 || status==304)
                return respond_empty(id,status,headers);
            std::array<std::uint8_t,3> value{}; std::array<std::uint8_t,7> name{};
            FieldsReservation reservation{*this};
            auto fields=response_fields(status,stream->head_request,body.size(),headers,value,name);
            if (!fields) return std::unexpected(fields.error());
            if (body.size()>shared_limit_-response_reserved_-library_used_-stream_reserved_-headers_.memory_charge()-fields_reserved_-input_reserved_-output_reserved_-ciphertext_reserved_-scratch_reserved_)
                return std::unexpected(ServerError{ServerErrorKind::budget_exceeded});
            if (!body.empty()) {
                try { stream->response=std::make_unique_for_overwrite<std::byte[]>(body.size()); }
                catch (std::bad_alloc const&) { return std::unexpected(ServerError{ServerErrorKind::allocation}); }
                std::memcpy(stream->response.get(),body.data(),body.size());
            }
            stream->response_size=body.size();
            response_reserved_ += body.size();
            h2::nghttp2_data_provider2 provider{};
            provider.source.ptr = &*stream;
            provider.read_callback = read_response;
            active_ = true;
            auto rc = h2::nghttp2_submit_response2(session_, id, fields->data(), fields->size(), &provider);
            active_ = false;
            if (rc != 0) {
                response_reserved_ -= body.size();
                stream->response.reset();
                stream->response_size = 0;
                stream->response_offset = 0;
                return library_error(rc);
            }
            ++revision_;
            stream->responded = true;
            return {};
        }
        // A final response with no body. Submission is separate from transport
        // delivery; the caller must continue draining output in order.
        auto respond_empty(std::int32_t id, unsigned status, std::span<Header const> headers = {}) noexcept -> std::expected<void, ServerError> {
            if (active_) return std::unexpected(ServerError{ServerErrorKind::reentrant});
            if (failed_) return std::unexpected(ServerError{ServerErrorKind::failed});
            if (id <= 0 || status < 200 || status > 599)
                return std::unexpected(ServerError{ServerErrorKind::invalid_argument});
            auto stream = std::ranges::find(streams_, id, &Stream::id);
            if (stream == streams_.end() || !stream->headers_received || stream->responded || stream->reset_pending)
                return std::unexpected(ServerError{ServerErrorKind::invalid_state});
            std::array<std::uint8_t,3> value{}; std::array<std::uint8_t,7> name{};
            FieldsReservation reservation{*this};
            auto fields=response_fields(status,stream->head_request,0,headers,value,name);
            if (!fields) return std::unexpected(fields.error());
            active_ = true;
            auto rc = h2::nghttp2_submit_response2(session_, id, fields->data(), fields->size(), nullptr);
            active_ = false;
            if (rc != 0) return library_error(rc);
            ++revision_;
            stream->responded = true;
            return {};
        }
        [[nodiscard]] auto response_memory_used() const noexcept -> std::size_t { return response_reserved_; }
        [[nodiscard]] auto library_memory_used() const noexcept -> std::size_t { return library_used_; }
        [[nodiscard]] auto header_memory_charge() const noexcept -> std::size_t { return headers_.memory_charge(); }
        [[nodiscard]] auto stream_memory_charge() const noexcept -> std::size_t { return stream_reserved_; }
        [[nodiscard]] auto input_memory_charge() const noexcept -> std::size_t { return input_reserved_; }
        [[nodiscard]] auto output_memory_charge() const noexcept -> std::size_t { return output_reserved_; }
        [[nodiscard]] auto ciphertext_memory_charge() const noexcept -> std::size_t { return ciphertext_reserved_; }
        [[nodiscard]] auto scratch_memory_charge() const noexcept -> std::size_t { return scratch_reserved_; }
        [[nodiscard]] auto shared_memory_used() const noexcept -> std::size_t { return library_used_ + response_reserved_ + stream_reserved_ + headers_.memory_charge() + fields_reserved_ + input_reserved_ + output_reserved_ + ciphertext_reserved_ + scratch_reserved_; }
        [[nodiscard]] auto library_memory_peak() const noexcept -> std::size_t { return library_peak_; }
        [[nodiscard]] auto revision() const noexcept -> std::uint64_t { return revision_; }
        [[nodiscard]] auto paused_stream() const noexcept -> std::int32_t { return paused_stream_; }
        // A paused input callback has already consumed the bytes that produced
        // its view. The caller retains any unconsumed input and explicitly
        // releases the guard before feeding subsequent bytes.
        auto resume_input(std::int32_t id) noexcept -> std::expected<void, ServerError> {
            if (active_) return std::unexpected(ServerError{ServerErrorKind::reentrant});
            if (failed_) return std::unexpected(ServerError{ServerErrorKind::failed});
            if (id <= 0 || paused_stream_ != id)
                return std::unexpected(ServerError{ServerErrorKind::invalid_state});
            ++revision_;
            auto rc = h2::nghttp2_session_consume(session_, id, paused_bytes_);
            if (rc != 0) {
                failed_ = true;
                return library_error(rc);
            }
            paused_stream_ = 0;
            paused_bytes_ = 0;
            return {};
        }
        auto receive(std::span<std::byte const> input) noexcept -> std::expected<std::size_t, ServerError> {
            if (active_) return std::unexpected(ServerError{ServerErrorKind::reentrant});
            if (failed_) return std::unexpected(ServerError{ServerErrorKind::failed});
            if (paused_stream_ != 0) return std::unexpected(ServerError{ServerErrorKind::invalid_state});
            ++revision_;
            active_ = true;
            auto rc = h2::nghttp2_session_mem_recv2(session_, reinterpret_cast<std::uint8_t const*>(input.data()), input.size());
            active_ = false;
            if (rc < 0) { failed_ = true; return std::unexpected(ServerError{ServerErrorKind::library, static_cast<int>(rc)}); }
            return static_cast<std::size_t>(rc);
        }
        // Output is copied before returning; an incomplete nghttp2 chunk stays
        // borrowed internally until later calls finish copying it.
        auto output(std::span<std::byte> destination) noexcept -> std::expected<std::size_t, ServerError> {
            if (active_) return std::unexpected(ServerError{ServerErrorKind::reentrant});
            if (failed_) return std::unexpected(ServerError{ServerErrorKind::failed});
            if (destination.empty()) return std::size_t{0};
            ++revision_;
            active_ = true;
            if (output_left_ == 0) {
                auto rc = h2::nghttp2_session_mem_send2(session_, &output_);
                if (rc < 0) { active_ = false; failed_ = true; return std::unexpected(ServerError{ServerErrorKind::library, static_cast<int>(rc)}); }
                output_left_ = static_cast<std::size_t>(rc);
            }
            auto count = std::min(destination.size(), output_left_);
            if (count) { std::memcpy(destination.data(), output_, count); output_ += count; output_left_ -= count; }
            active_ = false;
            return count;
        }
    };
}
