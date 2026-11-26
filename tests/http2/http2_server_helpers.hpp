#pragma once
// Shared test helpers for HTTP/2 server session unit tests.
namespace h2 = ::nghttp2;
namespace nh = http2;

struct Observed {
    nh::ServerSession* session = nullptr;
    std::vector<std::int32_t> headers;
    std::string body;
    std::int32_t ended = 0;
    bool reentrant = false;
    bool response_reentrant = false;
    bool reset_reentrant = false;
    std::int32_t closed_id = 0;
    std::uint32_t closed_code = 0;
    bool header_ended = false;
    bool fail_data = false;
    bool pause_data = false;
    bool did_pause = false;
};

inline auto on_headers(void* p, std::int32_t id, std::span<nh::Header const> fields, bool trailers, bool end) noexcept -> bool {
    auto& o = *static_cast<Observed*>(p);
    auto nested = o.session->receive({});
    o.reentrant = !nested && nested.error().kind == nh::ServerErrorKind::reentrant;
    auto nested_response = o.session->respond_empty(id, 204);
    o.response_reentrant = !nested_response && nested_response.error().kind == nh::ServerErrorKind::reentrant;
    auto nested_reset = o.session->reset_stream(id, h2::NGHTTP2_CANCEL);
    o.reset_reentrant = !nested_reset && nested_reset.error().kind == nh::ServerErrorKind::reentrant;
    if (trailers || fields.size() != 4 || fields.back().name != ":path") return false;
    try { o.headers.push_back(id); } catch (...) { return false; }
    o.header_ended = end;
    return true;
}

inline auto on_data(void* p, std::int32_t, std::span<std::byte const> data) noexcept -> nh::DataDisposition {
    auto& o = *static_cast<Observed*>(p);
    if (o.fail_data) return nh::DataDisposition::failure;
    try {
        o.body.append(reinterpret_cast<char const*>(data.data()), data.size());
        if (o.pause_data) { o.pause_data = false; o.did_pause = true; return nh::DataDisposition::pause; }
        return nh::DataDisposition::accepted;
    } catch (...) { return nh::DataDisposition::failure; }
}

inline auto on_end(void* p, std::int32_t id) noexcept -> bool { static_cast<Observed*>(p)->ended = id; return true; }
inline void on_closed(void* p, std::int32_t id, std::uint32_t code) noexcept {
    auto& o = *static_cast<Observed*>(p); o.closed_id = id; o.closed_code = code;
}

struct Client {
    std::int32_t reset_id = 0;
    std::uint32_t reset_code = 0;
    std::int32_t response_id = 0;
    std::vector<std::int32_t> response_ids;
    bool status_204 = false;
    std::string content_type;
    std::string extra_header;
    std::string content_length;
    std::string body;
    std::vector<std::int32_t> window_update_ids;
    std::vector<std::int32_t> goaway_ids;
};

inline auto on_client_close(h2::nghttp2_session*, std::int32_t id, std::uint32_t code, void* p) noexcept -> int {
    auto& c = *static_cast<Client*>(p); c.reset_id = id; c.reset_code = code; return 0;
}

inline auto on_client_data(h2::nghttp2_session*, std::uint8_t, std::int32_t,
                           std::uint8_t const* data, std::size_t length, void* p) noexcept -> int {
    auto& c = *static_cast<Client*>(p);
    try { c.body.append(reinterpret_cast<char const*>(data), length); return 0; } catch (...) { return -1; }
}

inline auto on_client_frame(h2::nghttp2_session*, h2::nghttp2_frame const* frame, void* p) noexcept -> int {
    auto& c = *static_cast<Client*>(p);
    if (frame->hd.type == h2::NGHTTP2_WINDOW_UPDATE) c.window_update_ids.push_back(frame->hd.stream_id);
    if (frame->hd.type == h2::NGHTTP2_GOAWAY) {
        try { c.goaway_ids.push_back(frame->goaway.last_stream_id); } catch (...) { return -1; }
    }
    return 0;
}

inline auto on_client_header(h2::nghttp2_session*, h2::nghttp2_frame const* frame,
                             std::uint8_t const* name, std::size_t n,
                             std::uint8_t const* value, std::size_t v, std::uint8_t, void* p) noexcept -> int {
    auto& c = *static_cast<Client*>(p);
    auto key = std::string_view(reinterpret_cast<char const*>(name), n);
    if (key == "content-type" || key == "x-test" || key == "content-length") {
        try {
            (key == "content-type" ? c.content_type : key == "x-test" ? c.extra_header : c.content_length)
                .assign(reinterpret_cast<char const*>(value), v);
        } catch (...) { return -1; }
    }
    if (key == ":status") {
        c.response_id = frame->hd.stream_id;
        try { c.response_ids.push_back(frame->hd.stream_id); } catch (...) { return -1; }
        c.status_204 = std::string_view(reinterpret_cast<char const*>(value), v) == "204";
    }
    return 0;
}

inline auto nv(std::string_view n, std::string_view v) -> h2::nghttp2_nv {
    return {reinterpret_cast<std::uint8_t*>(const_cast<char*>(n.data())),
            reinterpret_cast<std::uint8_t*>(const_cast<char*>(v.data())), n.size(), v.size(), 0};
}

struct BodySource { std::string_view body = "body data"; std::size_t offset = 0; };
inline auto read_body(h2::nghttp2_session*, std::int32_t, std::uint8_t* out, std::size_t size, std::uint32_t* flags,
                      h2::nghttp2_data_source* source, void*) noexcept -> h2::nghttp2_ssize {
    auto& body = *static_cast<BodySource*>(source->ptr);
    auto count = std::min(size, body.body.size() - body.offset);
    if (count) std::memcpy(out, body.body.data() + body.offset, count);
    body.offset += count;
    if (body.offset == body.body.size()) *flags |= h2::NGHTTP2_DATA_FLAG_EOF;
    return static_cast<h2::nghttp2_ssize>(count);
}

inline auto to_server(h2::nghttp2_session* client, nh::ServerSession& server) -> bool {
    for (;;) {
        std::uint8_t const* bytes = nullptr;
        auto size = h2::nghttp2_session_mem_send2(client, &bytes);
        if (size < 0) return false;
        if (size == 0) return true;
        for (std::size_t i = 0; i < static_cast<std::size_t>(size); ++i) {
            auto r = server.receive({reinterpret_cast<std::byte const*>(bytes + i), 1});
            if (!r || *r != 1) return false;
        }
    }
}

inline auto to_server_resuming(h2::nghttp2_session* client, nh::ServerSession& server,
                               Observed& observed, std::int32_t stream_id) -> bool {
    for (;;) {
        std::uint8_t const* bytes = nullptr;
        auto size = h2::nghttp2_session_mem_send2(client, &bytes);
        if (size < 0) return false;
        if (size == 0) return true;
        std::size_t offset = 0;
        while (offset < static_cast<std::size_t>(size)) {
            auto r = server.receive({reinterpret_cast<std::byte const*>(bytes + offset), 1});
            if (!r || *r != 1) return false;
            ++offset;
            if (observed.did_pause) {
                observed.did_pause = false;
                auto reset = server.reset_stream(stream_id, h2::NGHTTP2_CANCEL);
                if (reset || reset.error().kind != nh::ServerErrorKind::invalid_state) return false;
                if (!server.resume_input(stream_id)) return false;
            }
        }
    }
}

inline auto to_client(nh::ServerSession& server, h2::nghttp2_session* client) -> bool {
    for (;;) {
        std::array<std::byte, 1> bytes;
        auto n = server.output(bytes);
        if (!n) return false;
        if (!*n) return true;
        if (h2::nghttp2_session_mem_recv2(client, reinterpret_cast<std::uint8_t const*>(bytes.data()), *n) != static_cast<std::ptrdiff_t>(*n)) return false;
    }
}
