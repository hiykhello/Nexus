module http2.server;
import std;
import nghttp2;

#ifdef NEXUS_TEST_HTTP2_ALLOCATOR
extern "C" auto nexus_test_http2_fail_realloc() noexcept -> bool;
#endif

namespace http2 {
    auto ServerSession::allocate(std::size_t size, void* context) noexcept -> void* {
        auto& self = *static_cast<ServerSession*>(context);
        if (size > std::numeric_limits<std::size_t>::max() - sizeof(Allocation)) return nullptr;
        auto total = size + sizeof(Allocation);
        if (total > self.library_limit_ - self.library_used_ ||
            total > self.shared_limit_ - self.shared_memory_used()) return nullptr;
        auto p = static_cast<Allocation*>(std::malloc(total));
        if (!p) return nullptr;
        p->size = total;
        self.library_used_ += total;
        self.library_peak_ = std::max(self.library_peak_, self.library_used_);
        return p + 1;
    }

    void ServerSession::deallocate(void* ptr, void* context) noexcept {
        if (!ptr) return;
        auto& self = *static_cast<ServerSession*>(context);
        auto p = static_cast<Allocation*>(ptr) - 1;
        auto size = p->size;
        std::free(p);
        self.library_used_ -= size;
    }

    auto ServerSession::allocate_zero(std::size_t count, std::size_t size, void* context) noexcept -> void* {
        if (size && count > std::numeric_limits<std::size_t>::max() / size) return nullptr;
        auto total = count * size;
        auto p = allocate(total, context);
        if (p) std::memset(p, 0, total);
        return p;
    }

    auto ServerSession::resize(void* ptr, std::size_t size, void* context) noexcept -> void* {
        if (!ptr) return allocate(size, context);
        if (!size) { deallocate(ptr, context); return nullptr; }
        auto& self = *static_cast<ServerSession*>(context);
        if (size > std::numeric_limits<std::size_t>::max() - sizeof(Allocation)) return nullptr;
        auto p = static_cast<Allocation*>(ptr) - 1;
        auto old = p->size;
        auto total = size + sizeof(Allocation);
        // realloc may allocate the replacement before releasing the old block.
        // Reserve both requested sizes even when the allocator can resize in place.
        if (total > self.library_limit_ - self.library_used_ ||
            total > self.shared_limit_ - self.shared_memory_used()) return nullptr;
#ifdef NEXUS_TEST_HTTP2_ALLOCATOR
        if (nexus_test_http2_fail_realloc()) return nullptr;
#endif
        auto replacement = static_cast<Allocation*>(std::realloc(p, total));
        if (!replacement) return nullptr;
        self.library_peak_ = std::max(self.library_peak_, self.library_used_ + total);
        replacement->size = total;
        self.library_used_ = self.library_used_ - old + total;
        self.library_peak_ = std::max(self.library_peak_, self.library_used_);
        return replacement + 1;
    }

    ServerSession::ServerSession(ServerLimits limits, ServerEvents events, std::shared_ptr<memory::Budget> budget)
        : library_limit_(limits.library_memory_bytes), shared_limit_(limits.shared_memory_bytes),
          budget_(std::move(budget)), headers_(limits.header_fields, limits.header_bytes),
          max_streams_(limits.concurrent_streams), response_limit_(limits.response_bytes),
          total_response_limit_(limits.total_response_bytes), response_header_fields_(limits.response_header_fields),
          response_header_bytes_(limits.response_header_bytes), input_window_(limits.input_window),
          stream_slots_(limits.concurrent_streams), events_(events) {}

    ServerSession::~ServerSession() {
        if (session_) h2::nghttp2_session_del(session_);
        clear_streams();
        headers_.discard();
        response_reserved_ = stream_reserved_ = 0;
        if (budget_attached_) budget_->detach(this);
    }

    auto ServerSession::library_error(int rc) noexcept -> std::unexpected<ServerError> {
        if (h2::nghttp2_is_fatal(rc)) { if (!active_) headers_.discard(); failed_ = true; ++revision_; }
        return std::unexpected(ServerError{ServerErrorKind::library, rc});
    }

    auto ServerSession::response_fields(unsigned status, bool head_request, std::size_t body_size,
                                        std::span<Header const> headers,
                                        std::array<std::uint8_t, 3>& value,
                                        std::array<std::uint8_t, 7>& name) noexcept
        -> std::expected<std::vector<h2::nghttp2_nv>, ServerError> {
        if (headers.size() > response_header_fields_) return std::unexpected(ServerError{ServerErrorKind::invalid_argument});
        std::size_t bytes = 0;
        bool length_seen = false;
        for (auto const& header : headers) {
            if (header.name.empty() || header.name.front() == ':' || header.name.size() > response_header_bytes_ - bytes ||
                header.value.size() > response_header_bytes_ - bytes - header.name.size())
                return std::unexpected(ServerError{ServerErrorKind::invalid_argument});
            bytes += header.name.size() + header.value.size();
            if (header.name == "connection" || header.name == "proxy-connection" || header.name == "keep-alive" ||
                header.name == "transfer-encoding" || header.name == "upgrade" || header.name == "te" ||
                std::ranges::any_of(header.name, [](char c) { return c >= 'A' && c <= 'Z'; }) ||
                !h2::nghttp2_check_header_name(reinterpret_cast<std::uint8_t const*>(header.name.data()), header.name.size()) ||
                !h2::nghttp2_check_header_value_rfc9113(reinterpret_cast<std::uint8_t const*>(header.value.data()), header.value.size()))
                return std::unexpected(ServerError{ServerErrorKind::invalid_argument});
            if (header.name == "content-length") {
                std::size_t length = 0;
                auto begin = header.value.data(), end = begin + header.value.size();
                auto [last, error] = std::from_chars(begin, end, length);
                if (length_seen || status == 204 || begin == end || error != std::errc{} || last != end ||
                    (status == 205 && length != 0) || (!head_request && status != 304 && length != body_size))
                    return std::unexpected(ServerError{ServerErrorKind::invalid_argument});
                length_seen = true;
            }
        }
        value = {static_cast<std::uint8_t>('0' + status / 100), static_cast<std::uint8_t>('0' + status / 10 % 10),
                 static_cast<std::uint8_t>('0' + status % 10)};
        name = {':', 's', 't', 'a', 't', 'u', 's'};
        auto available = shared_limit_ - shared_memory_used();
        if (headers.size() >= std::numeric_limits<std::size_t>::max() / sizeof(h2::nghttp2_nv) ||
            (headers.size() + 1) * sizeof(h2::nghttp2_nv) > available)
            return std::unexpected(ServerError{ServerErrorKind::budget_exceeded});
        fields_reserved_ = (headers.size() + 1) * sizeof(h2::nghttp2_nv);
        try {
            std::vector<h2::nghttp2_nv> result;
            result.reserve(headers.size() + 1);
            result.push_back({name.data(), value.data(), name.size(), value.size(), 0});
            for (auto const& header : headers)
                result.push_back({reinterpret_cast<std::uint8_t*>(const_cast<char*>(header.name.data())),
                                  reinterpret_cast<std::uint8_t*>(const_cast<char*>(header.value.data())),
                                  header.name.size(), header.value.size(), 0});
            return result;
        } catch (...) { return std::unexpected(ServerError{ServerErrorKind::allocation}); }
    }

    auto ServerSession::begin(h2::nghttp2_session* session, h2::nghttp2_frame const* frame, void* p) noexcept -> int {
        auto& self = *static_cast<ServerSession*>(p);
        if (frame->headers.cat == h2::NGHTTP2_HCAT_REQUEST) {
            if (self.find_slot(session, frame->hd.stream_id)) return h2::NGHTTP2_ERR_CALLBACK_FAILURE;
            if (self.active_streams_ >= self.max_streams_ ||
                sizeof(Stream) > self.shared_limit_ - self.shared_memory_used()) {
                if (h2::nghttp2_submit_rst_stream(session, 0, frame->hd.stream_id, h2::NGHTTP2_REFUSED_STREAM) != 0)
                    return h2::NGHTTP2_ERR_CALLBACK_FAILURE;
                return h2::NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
            }
            auto* slot = self.acquire_slot(frame->hd.stream_id);
            if (!slot) return h2::NGHTTP2_ERR_CALLBACK_FAILURE;
            if (h2::nghttp2_session_set_stream_user_data(session, frame->hd.stream_id, slot) != 0) {
                self.release_slot(slot);
                return h2::NGHTTP2_ERR_CALLBACK_FAILURE;
            }
            self.stream_reserved_ += sizeof(Stream);
            // INITIAL_WINDOW_SIZE applies to every stream when the peer
            // acknowledges SETTINGS. Setting it here as well would apply
            // that delta twice to streams opened before the ACK.
        }
        self.headers_.begin(frame->hd.stream_id);
        return 0;
    }

    auto ServerSession::header(h2::nghttp2_session*, h2::nghttp2_frame const* frame,
                               std::uint8_t const* name, std::size_t n,
                               std::uint8_t const* value, std::size_t v,
                               std::uint8_t, void* p) noexcept -> int {
        auto& self = *static_cast<ServerSession*>(p);
        auto available = self.shared_limit_ - self.shared_memory_used();
        if (sizeof(Header) > available || n > available - sizeof(Header) || v > available - sizeof(Header) - n) {
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

    auto ServerSession::frame(h2::nghttp2_session* session, h2::nghttp2_frame const* f, void* p) noexcept -> int {
        auto& self = *static_cast<ServerSession*>(p);
        auto end = (f->hd.flags & h2::NGHTTP2_FLAG_END_STREAM) != 0;
        if (f->hd.type == h2::NGHTTP2_HEADERS) {
            if (self.headers_.stream() != f->hd.stream_id) return h2::NGHTTP2_ERR_CALLBACK_FAILURE;
            if (f->headers.cat == h2::NGHTTP2_HCAT_REQUEST) {
                auto* slot = self.find_slot(session, f->hd.stream_id);
                if (!slot) return h2::NGHTTP2_ERR_CALLBACK_FAILURE;
                auto method = std::ranges::find(self.headers_.fields(), std::string_view{":method"}, &Header::name);
                slot->stream.head_request = method != self.headers_.fields().end() && method->value == "HEAD";
                slot->stream.headers_received = true;
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

    auto ServerSession::sent(h2::nghttp2_session*, h2::nghttp2_frame const* frame, void* p) noexcept -> int {
        if (frame->hd.type == h2::NGHTTP2_GOAWAY && frame->goaway.error_code != h2::NGHTTP2_NO_ERROR)
            static_cast<ServerSession*>(p)->error_goaway_ = true;
        return 0;
    }

    auto ServerSession::data(h2::nghttp2_session* session, std::uint8_t, std::int32_t id,
                             std::uint8_t const* bytes, std::size_t length, void* p) noexcept -> int {
        auto& self = *static_cast<ServerSession*>(p);
        auto disposition = self.events_.data(self.events_.context, id,
            {reinterpret_cast<std::byte const*>(bytes), length});
        if (disposition == DataDisposition::accepted) {
            // Automatic WINDOW_UPDATE is disabled. A synchronous callback has
            // consumed the view, so acknowledge exactly the bytes it accepted.
            // A paused callback is acknowledged by resume_input after its owner
            // has finished with the view.
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

    auto ServerSession::read_response(h2::nghttp2_session*, std::int32_t, std::uint8_t* out,
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

    auto ServerSession::closed(h2::nghttp2_session* session, std::int32_t id, std::uint32_t code, void* p) noexcept -> int {
        auto& self = *static_cast<ServerSession*>(p);
        if (self.headers_.stream() == id) self.headers_.discard();
        if (auto* slot = self.find_slot(session, id)) {
            auto size = slot->stream.response_size;
            (void)h2::nghttp2_session_set_stream_user_data(session, id, nullptr);
            self.release_slot(slot);
            self.response_reserved_ -= size;
            self.stream_reserved_ -= sizeof(Stream);
        }
        int consume_rc = 0;
        if (self.paused_stream_ == id) {
            auto bytes = std::exchange(self.paused_bytes_, 0);
            self.paused_stream_ = 0;
            if (bytes) consume_rc = h2::nghttp2_session_consume_connection(session, bytes);
        }
        self.events_.closed(self.events_.context, id, code);
        if (consume_rc != 0) { self.failed_ = true; return h2::NGHTTP2_ERR_CALLBACK_FAILURE; }
        return 0;
    }

    auto ServerSession::create(ServerLimits limits, ServerEvents events, std::shared_ptr<memory::Budget> budget)
        -> std::expected<std::unique_ptr<ServerSession>, ServerError> {
        if (!limits.concurrent_streams || limits.concurrent_streams == kNoSlot || !limits.header_fields ||
            !limits.header_bytes || !limits.response_bytes ||
            !limits.total_response_bytes || !limits.input_window ||
            limits.input_window > static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max()) ||
            !limits.outbound_ack_frames || !limits.outbound_queue_frames || !limits.library_memory_bytes ||
            !limits.shared_memory_bytes || !events.headers || !events.data || !events.end_stream || !events.closed)
            return std::unexpected(ServerError{ServerErrorKind::invalid_argument});
        if (budget && budget->limit() != limits.shared_memory_bytes)
            return std::unexpected(ServerError{ServerErrorKind::invalid_argument});
        std::unique_ptr<ServerSession> self;
        try {
            if (!budget) budget = std::make_shared<memory::Budget>(limits.shared_memory_bytes);
            self.reset(new ServerSession(limits, events, std::move(budget)));
        } catch (std::bad_alloc const&) {
            return std::unexpected(ServerError{ServerErrorKind::allocation});
        }
        if (!self->budget_->attach(self.get(), [](void* p) noexcept { return static_cast<ServerSession*>(p)->local_memory_used(); }))
            return std::unexpected(ServerError{ServerErrorKind::invalid_state});
        self->budget_attached_ = true;
        h2::nghttp2_session_callbacks* callbacks = nullptr;
        int rc = h2::nghttp2_session_callbacks_new(&callbacks);
        if (rc != 0) return std::unexpected(ServerError{ServerErrorKind::library, rc});
        h2::nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, begin);
        h2::nghttp2_session_callbacks_set_on_header_callback(callbacks, header);
        h2::nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, frame);
        h2::nghttp2_session_callbacks_set_on_frame_send_callback(callbacks, sent);
        h2::nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, data);
        h2::nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, closed);
        h2::nghttp2_option* option = nullptr;
        rc = h2::nghttp2_option_new(&option);
        if (rc == 0) {
            h2::nghttp2_option_set_no_auto_window_update(option, 1);
            h2::nghttp2_option_set_max_outbound_ack(option, limits.outbound_ack_frames);
            h2::nghttp2_option_set_max_outbound_queue_size(option, limits.outbound_queue_frames);
            h2::nghttp2_option_set_max_deflate_dynamic_table_size(option, limits.encoder_table_bytes);
        }
        h2::nghttp2_mem memory{self.get(), allocate, deallocate, allocate_zero, resize};
        if (rc == 0)
            rc = h2::nghttp2_session_server_new3(&self->session_, callbacks, self.get(), option, &memory);
        h2::nghttp2_option_del(option);
        h2::nghttp2_session_callbacks_del(callbacks);
        if (rc != 0) return std::unexpected(ServerError{ServerErrorKind::library, rc});
        rc = h2::nghttp2_session_set_local_window_size(
            self->session_, 0, 0, static_cast<std::int32_t>(self->input_window_));
        if (rc != 0) return std::unexpected(ServerError{ServerErrorKind::library, rc});
        constexpr std::int32_t kSettingsMaxFrameSize = 0x5; // RFC 9113 §6.5.2
        auto const clamped_frame = std::clamp(limits.max_frame_size, std::uint32_t{16384}, std::uint32_t{16777215});
        std::array<h2::nghttp2_settings_entry, 4> settings{
            h2::nghttp2_settings_entry{h2::NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, limits.concurrent_streams},
            h2::nghttp2_settings_entry{h2::NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, static_cast<std::uint32_t>(limits.input_window)},
            h2::nghttp2_settings_entry{h2::NGHTTP2_SETTINGS_HEADER_TABLE_SIZE, limits.decoder_table_bytes},
            h2::nghttp2_settings_entry{kSettingsMaxFrameSize, clamped_frame}};
        rc = h2::nghttp2_submit_settings(self->session_, 0, settings.data(), settings.size());
        if (rc != 0) return std::unexpected(ServerError{ServerErrorKind::library, rc});
        return self;
    }

    auto ServerSession::start_shutdown() noexcept -> std::expected<void, ServerError> {
        if (active_) return std::unexpected(ServerError{ServerErrorKind::reentrant});
        if (failed_) return std::unexpected(ServerError{ServerErrorKind::failed});
        if (terminated_) return std::unexpected(ServerError{ServerErrorKind::invalid_state});
        if (shutdown_ != Shutdown::running) return std::unexpected(ServerError{ServerErrorKind::invalid_state});
        auto rc = h2::nghttp2_submit_shutdown_notice(session_);
        if (rc != 0) return library_error(rc);
        ++revision_;
        shutdown_ = Shutdown::notice;
        return {};
    }

    auto ServerSession::finish_shutdown() noexcept -> std::expected<void, ServerError> {
        if (active_) return std::unexpected(ServerError{ServerErrorKind::reentrant});
        if (failed_) return std::unexpected(ServerError{ServerErrorKind::failed});
        if (terminated_) return std::unexpected(ServerError{ServerErrorKind::invalid_state});
        if (shutdown_ != Shutdown::notice) return std::unexpected(ServerError{ServerErrorKind::invalid_state});
        auto last = h2::nghttp2_session_get_last_proc_stream_id(session_);
        auto rc = h2::nghttp2_submit_goaway(session_, 0, last, h2::NGHTTP2_NO_ERROR, nullptr, 0);
        if (rc != 0) return library_error(rc);
        ++revision_;
        shutdown_ = Shutdown::draining;
        return {};
    }

    auto ServerSession::shutdown_complete() const noexcept -> bool {
        return !active_ && !failed_ && shutdown_ == Shutdown::draining && output_left_ == 0 &&
            (terminated_ || (!h2::nghttp2_session_want_read(session_) && !h2::nghttp2_session_want_write(session_)));
    }

    auto ServerSession::reset_stream(std::int32_t id, std::uint32_t code) noexcept -> std::expected<void, ServerError> {
        if (active_) return std::unexpected(ServerError{ServerErrorKind::reentrant});
        if (failed_) return std::unexpected(ServerError{ServerErrorKind::failed});
        if (terminated_) return std::unexpected(ServerError{ServerErrorKind::invalid_state});
        if (id <= 0) return std::unexpected(ServerError{ServerErrorKind::invalid_argument});
        auto* slot = find_slot(id);
        if (!slot || slot->stream.reset_pending || paused_stream_ == id)
            return std::unexpected(ServerError{ServerErrorKind::invalid_state});
        auto rc = h2::nghttp2_submit_rst_stream(session_, 0, id, code);
        if (rc != 0) return library_error(rc);
        ++revision_;
        slot->stream.reset_pending = true;
        return {};
    }

    auto ServerSession::respond_body(std::int32_t id, unsigned status, std::span<std::byte const> body,
                                     std::span<Header const> headers) noexcept -> std::expected<void, ServerError> {
        if (active_) return std::unexpected(ServerError{ServerErrorKind::reentrant});
        if (failed_) return std::unexpected(ServerError{ServerErrorKind::failed});
        if (terminated_) return std::unexpected(ServerError{ServerErrorKind::invalid_state});
        if (id <= 0 || status < 200 || status > 599)
            return std::unexpected(ServerError{ServerErrorKind::invalid_argument});
        auto* slot = find_slot(id);
        if (!slot || !slot->stream.headers_received || slot->stream.responded || slot->stream.reset_pending)
            return std::unexpected(ServerError{ServerErrorKind::invalid_state});
        auto& stream = slot->stream;
        if (body.size() > response_limit_ || body.size() > total_response_limit_ - response_reserved_ ||
            (body.size() != 0 && (stream.head_request || status == 204 || status == 205 || status == 304)))
            return std::unexpected(ServerError{ServerErrorKind::invalid_argument});
        if (stream.head_request || status == 204 || status == 205 || status == 304)
            return respond_empty(id, status, headers);
        std::array<std::uint8_t, 3> value{};
        std::array<std::uint8_t, 7> name{};
        FieldsReservation reservation{*this};
        auto fields = response_fields(status, stream.head_request, body.size(), headers, value, name);
        if (!fields) return std::unexpected(fields.error());
        if (body.size() > shared_limit_ - shared_memory_used())
            return std::unexpected(ServerError{ServerErrorKind::budget_exceeded});
        if (!body.empty()) {
            try { stream.response = std::make_unique_for_overwrite<std::byte[]>(body.size()); }
            catch (std::bad_alloc const&) { return std::unexpected(ServerError{ServerErrorKind::allocation}); }
            std::memcpy(stream.response.get(), body.data(), body.size());
        }
        stream.response_size = body.size();
        response_reserved_ += body.size();
        h2::nghttp2_data_provider2 provider{};
        provider.source.ptr = &stream;
        provider.read_callback = read_response;
        active_ = true;
        auto rc = h2::nghttp2_submit_response2(session_, id, fields->data(), fields->size(), &provider);
        active_ = false;
        if (rc != 0) {
            stream.response.reset();
            response_reserved_ -= body.size();
            stream.response_size = 0;
            stream.response_offset = 0;
            return library_error(rc);
        }
        ++revision_;
        stream.responded = true;
        return {};
    }

    auto ServerSession::respond_empty(std::int32_t id, unsigned status, std::span<Header const> headers) noexcept
        -> std::expected<void, ServerError> {
        if (active_) return std::unexpected(ServerError{ServerErrorKind::reentrant});
        if (failed_) return std::unexpected(ServerError{ServerErrorKind::failed});
        if (terminated_) return std::unexpected(ServerError{ServerErrorKind::invalid_state});
        if (id <= 0 || status < 200 || status > 599)
            return std::unexpected(ServerError{ServerErrorKind::invalid_argument});
        auto* slot = find_slot(id);
        if (!slot || !slot->stream.headers_received || slot->stream.responded || slot->stream.reset_pending)
            return std::unexpected(ServerError{ServerErrorKind::invalid_state});
        std::array<std::uint8_t, 3> value{};
        std::array<std::uint8_t, 7> name{};
        FieldsReservation reservation{*this};
        auto fields = response_fields(status, slot->stream.head_request, 0, headers, value, name);
        if (!fields) return std::unexpected(fields.error());
        active_ = true;
        auto rc = h2::nghttp2_submit_response2(session_, id, fields->data(), fields->size(), nullptr);
        active_ = false;
        if (rc != 0) return library_error(rc);
        ++revision_;
        slot->stream.responded = true;
        return {};
    }

    auto ServerSession::outbound_queue_size() const noexcept -> std::size_t {
        return session_ ? h2::nghttp2_session_get_outbound_queue_size(session_) : 0;
    }

    auto ServerSession::resume_input(std::int32_t id) noexcept -> std::expected<void, ServerError> {
        if (active_) return std::unexpected(ServerError{ServerErrorKind::reentrant});
        if (failed_) return std::unexpected(ServerError{ServerErrorKind::failed});
        if (terminated_) return std::unexpected(ServerError{ServerErrorKind::invalid_state});
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

    auto ServerSession::receive(std::span<std::byte const> input) noexcept -> std::expected<std::size_t, ServerError> {
        if (active_) return std::unexpected(ServerError{ServerErrorKind::reentrant});
        if (failed_) return std::unexpected(ServerError{ServerErrorKind::failed});
        if (terminated_) return std::unexpected(ServerError{ServerErrorKind::invalid_state});
        if (paused_stream_ != 0) return std::unexpected(ServerError{ServerErrorKind::invalid_state});
        ++revision_;
        active_ = true;
        auto rc = h2::nghttp2_session_mem_recv2(session_, reinterpret_cast<std::uint8_t const*>(input.data()), input.size());
        active_ = false;
        if (failed_) headers_.discard();
        if (rc < 0) { headers_.discard(); failed_ = true; return std::unexpected(ServerError{ServerErrorKind::library, static_cast<int>(rc)}); }
        return static_cast<std::size_t>(rc);
    }

    auto ServerSession::output(std::span<std::byte> destination) noexcept -> std::expected<std::size_t, ServerError> {
        if (active_) return std::unexpected(ServerError{ServerErrorKind::reentrant});
        if (failed_) return std::unexpected(ServerError{ServerErrorKind::failed});
        if (terminated_) return std::size_t{0};
        if (destination.empty()) return std::size_t{0};
        ++revision_;
        active_ = true;
        if (output_left_ == 0) {
            auto rc = h2::nghttp2_session_mem_send2(session_, &output_);
            if (rc < 0) { active_ = false; headers_.discard(); failed_ = true; return std::unexpected(ServerError{ServerErrorKind::library, static_cast<int>(rc)}); }
            output_left_ = static_cast<std::size_t>(rc);
        }
        auto count = std::min(destination.size(), output_left_);
        if (count) { std::memcpy(destination.data(), output_, count); output_ += count; output_left_ -= count; }
        active_ = false;
        // Once nghttp2 wants neither input nor output, the connection
        // cannot complete an unfinished header block.
        if (failed_) headers_.discard();
        else if (!output_left_ && !h2::nghttp2_session_want_read(session_) && !h2::nghttp2_session_want_write(session_)) {
            // nghttp2 may still borrow response providers. Destroy it first,
            // after copying its last output chunk, then release our streams.
            h2::nghttp2_session_del(session_); session_ = nullptr; output_ = nullptr;
            clear_streams(); headers_.discard();
            response_reserved_ = stream_reserved_ = 0; paused_stream_ = 0; paused_bytes_ = 0; terminated_ = true;
        }
        return count;
    }
}
