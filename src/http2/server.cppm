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
    };
    enum class ServerErrorKind { invalid_argument, invalid_state, allocation, library, reentrant, failed };
    struct ServerError { ServerErrorKind kind; int library_code = 0; };

    class ServerSession {
        h2::nghttp2_session* session_ = nullptr;
        struct Stream {
            std::int32_t id;
            bool responded = false;
            std::vector<std::byte> response;
            std::size_t response_offset = 0;
        };
        HeaderBlock headers_;
        std::size_t max_streams_;
        std::size_t response_limit_;
        std::size_t total_response_limit_;
        std::size_t input_window_;
        std::size_t response_reserved_ = 0;
        // nghttp2 retains Stream pointers in data providers until completion.
        // Erasing a different stream must not relocate those objects.
        std::list<Stream> streams_;
        ServerEvents events_;
        std::uint8_t const* output_ = nullptr;
        std::size_t output_left_ = 0;
        bool active_ = false;
        bool failed_ = false;
        std::int32_t paused_stream_ = 0;
        std::size_t paused_bytes_ = 0;

        ServerSession(ServerLimits limits, ServerEvents events)
            : headers_(limits.header_fields, limits.header_bytes), max_streams_(limits.concurrent_streams), response_limit_(limits.response_bytes), total_response_limit_(limits.total_response_bytes), input_window_(limits.input_window), events_(events) {
        }
        static auto begin(h2::nghttp2_session* session, h2::nghttp2_frame const* frame, void* p) noexcept -> int {
            auto& self = *static_cast<ServerSession*>(p);
            if (frame->headers.cat == h2::NGHTTP2_HCAT_REQUEST) {
                if (self.streams_.size() >= self.max_streams_) {
                    if (h2::nghttp2_submit_rst_stream(session, 0, frame->hd.stream_id, h2::NGHTTP2_REFUSED_STREAM) != 0)
                        return h2::NGHTTP2_ERR_CALLBACK_FAILURE;
                    return h2::NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
                }
                try { self.streams_.push_back({frame->hd.stream_id}); }
                catch (...) { return h2::NGHTTP2_ERR_CALLBACK_FAILURE; }
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
            auto remaining = stream.response.size() - stream.response_offset;
            auto count = std::min(length, remaining);
            if (count) {
                std::memcpy(out, stream.response.data() + stream.response_offset, count);
                stream.response_offset += count;
            }
            if (stream.response_offset == stream.response.size()) *flags |= h2::NGHTTP2_DATA_FLAG_EOF;
            return static_cast<h2::nghttp2_ssize>(count);
        }

        static auto closed(h2::nghttp2_session*, std::int32_t id, std::uint32_t code, void* p) noexcept -> int {
            auto& self = *static_cast<ServerSession*>(p);
            if (auto stream = std::ranges::find(self.streams_, id, &Stream::id); stream != self.streams_.end()) {
                self.response_reserved_ -= stream->response.size();
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
                !limits.outbound_ack_frames ||
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
            if (rc == 0)
                rc = h2::nghttp2_session_server_new2(&self->session_, callbacks, self.get(), option);
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
        auto respond_body(std::int32_t id, unsigned status, std::span<std::byte const> body) noexcept
            -> std::expected<void, ServerError> {
            if (active_) return std::unexpected(ServerError{ServerErrorKind::reentrant});
            if (failed_) return std::unexpected(ServerError{ServerErrorKind::failed});
            if (id <= 0 || status < 200 || status > 599)
                return std::unexpected(ServerError{ServerErrorKind::invalid_argument});
            auto stream = std::ranges::find(streams_, id, &Stream::id);
            if (stream == streams_.end() || stream->responded)
                return std::unexpected(ServerError{ServerErrorKind::invalid_state});
            if (body.size() > response_limit_ || body.size() > total_response_limit_ - response_reserved_ ||
                (body.size() != 0 && (status == 204 || status == 205 || status == 304)))
                return std::unexpected(ServerError{ServerErrorKind::invalid_argument});
            try { stream->response.assign(body.begin(), body.end()); }
            catch (std::bad_alloc const&) { return std::unexpected(ServerError{ServerErrorKind::allocation}); }
            response_reserved_ += body.size();
            std::array<std::uint8_t, 3> value{
                static_cast<std::uint8_t>('0' + status / 100),
                static_cast<std::uint8_t>('0' + status / 10 % 10),
                static_cast<std::uint8_t>('0' + status % 10)};
            std::array<std::uint8_t, 7> name{':', 's', 't', 'a', 't', 'u', 's'};
            h2::nghttp2_nv field{name.data(), value.data(), name.size(), value.size(), 0};
            h2::nghttp2_data_provider2 provider{};
            provider.source.ptr = &*stream;
            provider.read_callback = read_response;
            active_ = true;
            auto rc = h2::nghttp2_submit_response2(session_, id, &field, 1, &provider);
            active_ = false;
            if (rc != 0) {
                response_reserved_ -= body.size();
                stream->response.clear();
                stream->response_offset = 0;
                return std::unexpected(ServerError{ServerErrorKind::library, rc});
            }
            stream->responded = true;
            return {};
        }

        // A final response with no body. Submission is separate from transport
        // delivery; the caller must continue draining output in order.
        auto respond_empty(std::int32_t id, unsigned status) noexcept -> std::expected<void, ServerError> {
            if (active_) return std::unexpected(ServerError{ServerErrorKind::reentrant});
            if (failed_) return std::unexpected(ServerError{ServerErrorKind::failed});
            if (id <= 0 || status < 200 || status > 599)
                return std::unexpected(ServerError{ServerErrorKind::invalid_argument});
            auto stream = std::ranges::find(streams_, id, &Stream::id);
            if (stream == streams_.end() || stream->responded)
                return std::unexpected(ServerError{ServerErrorKind::invalid_state});
            std::array<std::uint8_t, 3> value{
                static_cast<std::uint8_t>('0' + status / 100),
                static_cast<std::uint8_t>('0' + status / 10 % 10),
                static_cast<std::uint8_t>('0' + status % 10)};
            std::array<std::uint8_t, 7> name{':', 's', 't', 'a', 't', 'u', 's'};
            h2::nghttp2_nv field{name.data(), value.data(), name.size(), value.size(), 0};
            active_ = true;
            auto rc = h2::nghttp2_submit_response2(session_, id, &field, 1, nullptr);
            active_ = false;
            if (rc != 0) return std::unexpected(ServerError{ServerErrorKind::library, rc});
            stream->responded = true;
            return {};
        }
        // A paused input callback has already consumed the bytes that produced
        // its view. The caller retains any unconsumed input and explicitly
        // releases the guard before feeding subsequent bytes.
        auto resume_input(std::int32_t id) noexcept -> std::expected<void, ServerError> {
            if (active_) return std::unexpected(ServerError{ServerErrorKind::reentrant});
            if (failed_) return std::unexpected(ServerError{ServerErrorKind::failed});
            if (id <= 0 || paused_stream_ != id)
                return std::unexpected(ServerError{ServerErrorKind::invalid_state});
            auto rc = h2::nghttp2_session_consume(session_, id, paused_bytes_);
            if (rc != 0) {
                failed_ = true;
                return std::unexpected(ServerError{ServerErrorKind::library, rc});
            }
            paused_stream_ = 0;
            paused_bytes_ = 0;
            return {};
        }

        auto receive(std::span<std::byte const> input) noexcept -> std::expected<std::size_t, ServerError> {
            if (active_) return std::unexpected(ServerError{ServerErrorKind::reentrant});
            if (failed_) return std::unexpected(ServerError{ServerErrorKind::failed});
            if (paused_stream_ != 0) return std::unexpected(ServerError{ServerErrorKind::invalid_state});
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
