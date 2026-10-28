import std;
import nexus.http2.server;
import nexus.thirdparty.nghttp2;
namespace h2 = nex::nghttp2;
namespace nh = nexus::http2;

struct Observed {
    nh::ServerSession* session = nullptr;
    std::vector<std::int32_t> headers;
    std::string body;
    std::int32_t ended = 0;
    bool reentrant = false;
    bool response_reentrant = false;
    std::int32_t closed_id = 0;
    std::uint32_t closed_code = 0;
    bool header_ended = false;
    bool fail_data = false;
    bool pause_data = false;
    bool did_pause = false;
};
auto on_headers(void* p, std::int32_t id, std::span<nh::Header const> fields, bool trailers, bool end) noexcept -> bool {
    auto& o = *static_cast<Observed*>(p);
    auto nested = o.session->receive({});
    o.reentrant = !nested && nested.error().kind == nh::ServerErrorKind::reentrant;
    auto nested_response = o.session->respond_empty(id, 204);
    o.response_reentrant = !nested_response && nested_response.error().kind == nh::ServerErrorKind::reentrant;
    if (trailers || fields.size() != 4 || fields.back().name != ":path") return false;
    try { o.headers.push_back(id); } catch (...) { return false; }
    o.header_ended = end;
    return true;
}
auto on_data(void* p, std::int32_t, std::span<std::byte const> data) noexcept -> nh::DataDisposition {
    auto& o = *static_cast<Observed*>(p);
    if (o.fail_data) return nh::DataDisposition::failure;
    try { o.body.append(reinterpret_cast<char const*>(data.data()), data.size());
          if (o.pause_data) { o.pause_data = false; o.did_pause = true; return nh::DataDisposition::pause; }
          return nh::DataDisposition::accepted; }
    catch (...) { return nh::DataDisposition::failure; }
}
auto on_end(void* p, std::int32_t id) noexcept -> bool { static_cast<Observed*>(p)->ended = id; return true; }
void on_closed(void* p, std::int32_t id, std::uint32_t code) noexcept {
    auto& o = *static_cast<Observed*>(p); o.closed_id = id; o.closed_code = code;
}
struct Client { std::int32_t reset_id = 0; std::uint32_t reset_code = 0; std::int32_t response_id = 0; std::vector<std::int32_t> response_ids; bool status_204 = false; std::string body; std::vector<std::int32_t> window_update_ids; };
auto on_client_close(h2::nghttp2_session*, std::int32_t id, std::uint32_t code, void* p) noexcept -> int {
    auto& c = *static_cast<Client*>(p); c.reset_id = id; c.reset_code = code; return 0;
}
auto on_client_data(h2::nghttp2_session*, std::uint8_t, std::int32_t,
                    std::uint8_t const* data, std::size_t length, void* p) noexcept -> int {
    auto& c = *static_cast<Client*>(p);
    try { c.body.append(reinterpret_cast<char const*>(data), length); return 0; } catch (...) { return -1; }
}
auto on_client_frame(h2::nghttp2_session*, h2::nghttp2_frame const* frame, void* p) noexcept -> int {
    auto& c = *static_cast<Client*>(p);
    if (frame->hd.type == h2::NGHTTP2_WINDOW_UPDATE) c.window_update_ids.push_back(frame->hd.stream_id);
    return 0;
}
auto on_client_header(h2::nghttp2_session*, h2::nghttp2_frame const* frame,
                      std::uint8_t const* name, std::size_t n,
                      std::uint8_t const* value, std::size_t v, std::uint8_t, void* p) noexcept -> int {
    auto& c = *static_cast<Client*>(p);
    if (std::string_view(reinterpret_cast<char const*>(name), n) == ":status") {
        c.response_id = frame->hd.stream_id;
        try { c.response_ids.push_back(frame->hd.stream_id); } catch (...) { return -1; }
        c.status_204 = std::string_view(reinterpret_cast<char const*>(value), v) == "204";
    }
    return 0;
}
auto nv(std::string_view n, std::string_view v) -> h2::nghttp2_nv {
    return {reinterpret_cast<std::uint8_t*>(const_cast<char*>(n.data())), reinterpret_cast<std::uint8_t*>(const_cast<char*>(v.data())), n.size(), v.size(), 0};
}
struct BodySource { std::string_view body = "body data"; std::size_t offset = 0; };
auto read_body(h2::nghttp2_session*, std::int32_t, std::uint8_t* out, std::size_t size, std::uint32_t* flags,
               h2::nghttp2_data_source* source, void*) noexcept -> h2::nghttp2_ssize {
    auto& body = *static_cast<BodySource*>(source->ptr);
    auto count = std::min(size, body.body.size() - body.offset);
    if (count) std::memcpy(out, body.body.data() + body.offset, count);
    body.offset += count;
    if (body.offset == body.body.size()) *flags |= h2::NGHTTP2_DATA_FLAG_EOF;
    return static_cast<h2::nghttp2_ssize>(count);
}
auto to_server(h2::nghttp2_session* client, nh::ServerSession& server) -> bool {
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
auto to_server_resuming(h2::nghttp2_session* client, nh::ServerSession& server,
                       Observed& observed, std::int32_t stream_id) -> bool {
    for (;;) {
        std::uint8_t const* bytes = nullptr;
        auto size = h2::nghttp2_session_mem_send2(client, &bytes);
        if (size < 0) return false;
        if (size == 0) return true;
        std::size_t offset = 0;
        while (offset < static_cast<std::size_t>(size)) {
            auto r = server.receive({reinterpret_cast<std::byte const*>(bytes + offset), 1});
            if (!r) return false;
            if (*r != 1) return false;
            ++offset;
            if (observed.did_pause) {
                observed.did_pause = false;
                if (!server.resume_input(stream_id)) return false;
            }
        }
    }
}

auto to_client(nh::ServerSession& server, h2::nghttp2_session* client) -> bool {
    for (;;) {
        std::array<std::byte, 1> bytes;
        auto n = server.output(bytes);
        if (!n) return false;
        if (!*n) return true;
        if (h2::nghttp2_session_mem_recv2(client, reinterpret_cast<std::uint8_t const*>(bytes.data()), *n) != static_cast<std::ptrdiff_t>(*n)) return false;
    }
}
int main() {
    Observed observed;
    nh::ServerEvents events{&observed, on_headers, on_data, on_end, on_closed};
    if (nh::ServerSession::create({0, 4, 128, 64, 16}, events)) return 1;
    auto session = nh::ServerSession::create({8, 4, 128, 64, 16}, events);
    if (!session) return 2;
    observed.session = session->get();
    h2::nghttp2_session_callbacks* callbacks = nullptr;
    if (h2::nghttp2_session_callbacks_new(&callbacks)) return 3;
    h2::nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_client_close);
    h2::nghttp2_session_callbacks_set_on_header_callback(callbacks, on_client_header);
    h2::nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_client_data);
    Client client_events;
    h2::nghttp2_session* client = nullptr;
    auto rc = h2::nghttp2_session_client_new(&client, callbacks, &client_events);
    h2::nghttp2_session_callbacks_del(callbacks);
    if (rc) return 4;
    std::unique_ptr<h2::nghttp2_session, decltype(&h2::nghttp2_session_del)> client_owner(client, h2::nghttp2_session_del);
    if (h2::nghttp2_submit_settings(client, 0, nullptr, 0)) return 5;
    auto bad_resume = (**session).resume_input(777);
    if (bad_resume || bad_resume.error().kind != nh::ServerErrorKind::invalid_state) return 18;
    observed.pause_data = true;
    std::array large{nv(":method", "GET"), nv(":scheme", "https"), nv(":authority", "example.test"), nv(":path", "/"), nv("extra", "value")};
    std::array good{nv(":method", "POST"), nv(":scheme", "https"), nv(":authority", "example.test"), nv(":path", "/ok")};
    auto first = h2::nghttp2_submit_request2(client, nullptr, large.data(), large.size(), nullptr, nullptr);
    BodySource request_body;
    h2::nghttp2_data_provider2 provider{}; provider.source.ptr = &request_body; provider.read_callback = read_body;
    auto second = h2::nghttp2_submit_request2(client, nullptr, good.data(), good.size(), &provider, nullptr);
    std::array<std::byte, 1> first_output;
    auto first_size = (**session).output(first_output);
    if (!first_size || *first_size != 1 ||
        h2::nghttp2_session_mem_recv2(client, reinterpret_cast<std::uint8_t const*>(first_output.data()), 1) != 1 ||
        first <= 0 || second <= first) return 6;
    auto sent = to_server_resuming(client, **session, observed, second);
    auto returned = to_client(**session, client);
    if (!sent || !returned) return 6;
    if (observed.headers != std::vector<std::int32_t>{second} || !observed.reentrant || !observed.response_reentrant || observed.header_ended ||
        observed.body != "body data" || observed.ended != second || client_events.reset_id != first ||
        client_events.reset_code != h2::NGHTTP2_INTERNAL_ERROR) return 7;
    auto bad_status = (**session).respond_empty(second, 199);
    auto unknown = (**session).respond_empty(999, 204);
    if (bad_status || bad_status.error().kind != nh::ServerErrorKind::invalid_argument ||
        unknown || unknown.error().kind != nh::ServerErrorKind::invalid_state) return 12;
    std::array<std::byte, 65> too_large{};
    auto oversized = (**session).respond_body(second, 200, too_large);
    constexpr std::array<std::byte, 1> forbidden_body{std::byte{'x'}};
    auto forbidden = (**session).respond_body(second, 204, forbidden_body);
    if (oversized || oversized.error().kind != nh::ServerErrorKind::invalid_argument ||
        forbidden || forbidden.error().kind != nh::ServerErrorKind::invalid_argument) return 17;
    constexpr std::string_view response = "response body";
    if (!(**session).respond_body(second, 200,
        {reinterpret_cast<std::byte const*>(response.data()), response.size()})) return 13;
    auto duplicate = (**session).respond_empty(second, 204);
    if (duplicate || duplicate.error().kind != nh::ServerErrorKind::invalid_state) return 14;
    auto third = h2::nghttp2_submit_request2(client, nullptr, good.data(), good.size(), nullptr, nullptr);
    if (third <= second || !to_server(client, **session)) return 19;
    std::array<std::byte, 8> second_body{};
    auto total_over = (**session).respond_body(third, 200, second_body);
    if (total_over || total_over.error().kind != nh::ServerErrorKind::invalid_argument ||
        !(**session).respond_empty(third, 204)) return 20;
    if (!to_client(**session, client) || client_events.response_ids != std::vector<std::int32_t>{second, third} ||
        !client_events.status_204 || client_events.body != "response body") return 15;
    auto closed = (**session).respond_empty(second, 204);
    if (closed || closed.error().kind != nh::ServerErrorKind::invalid_state) return 16;
    auto empty = (**session).output({});
    if (!empty || *empty != 0) return 8;
    observed.fail_data = true;
    request_body.offset = 0;
    auto failure_stream = h2::nghttp2_submit_request2(client, nullptr, good.data(), good.size(), &provider, nullptr);
    if (failure_stream <= third || to_server(client, **session)) return 9;
    auto failed = (**session).receive({});
    if (failed || failed.error().kind != nh::ServerErrorKind::failed) return 10;
    auto failed_output = (**session).output({});
    if (failed_output || failed_output.error().kind != nh::ServerErrorKind::failed) return 11;

    // With automatic WINDOW_UPDATE disabled, an accepted DATA callback must
    // explicitly replenish both the stream and connection receive windows.
    // Deliver the server SETTINGS before submitting the request so the client
    // also observes the deliberately small eight-byte stream window.
    Observed flow_observed;
    nh::ServerEvents flow_events{&flow_observed, on_headers, on_data, on_end, on_closed};
    auto flow_session = nh::ServerSession::create({8, 4, 128, 64, 16, 8}, flow_events);
    if (!flow_session) return 21;
    flow_observed.session = flow_session->get();
    h2::nghttp2_session_callbacks* flow_callbacks = nullptr;
    if (h2::nghttp2_session_callbacks_new(&flow_callbacks)) return 22;
    h2::nghttp2_session_callbacks_set_on_frame_recv_callback(flow_callbacks, on_client_frame);
    h2::nghttp2_session_callbacks_set_on_data_chunk_recv_callback(flow_callbacks, on_client_data);
    Client flow_client_events;
    h2::nghttp2_session* flow_client = nullptr;
    auto flow_rc = h2::nghttp2_session_client_new(&flow_client, flow_callbacks, &flow_client_events);
    h2::nghttp2_session_callbacks_del(flow_callbacks);
    if (flow_rc) return 23;
    std::unique_ptr<h2::nghttp2_session, decltype(&h2::nghttp2_session_del)> flow_client_owner(flow_client, h2::nghttp2_session_del);
    if (h2::nghttp2_submit_settings(flow_client, 0, nullptr, 0) || !to_server(flow_client, **flow_session) ||
        !to_client(**flow_session, flow_client)) return 24;
    BodySource flow_body;
    h2::nghttp2_data_provider2 flow_provider{};
    flow_provider.source.ptr = &flow_body;
    flow_provider.read_callback = read_body;
    auto flow_stream = h2::nghttp2_submit_request2(flow_client, nullptr, good.data(), good.size(), &flow_provider, nullptr);
    if (flow_stream <= 0) return 25;
    for (;;) {
        std::uint8_t const* bytes = nullptr;
        auto size = h2::nghttp2_session_mem_send2(flow_client, &bytes);
        if (size < 0) return 26;
        if (size == 0) break;
        auto received = (**flow_session).receive({reinterpret_cast<std::byte const*>(bytes), static_cast<std::size_t>(size)});
        if (!received || *received != static_cast<std::size_t>(size) || !to_client(**flow_session, flow_client)) return 27;
    }
    if (flow_observed.body != "body data" || flow_client_events.window_update_ids.empty()) {
        std::println("flow body='{}' updates={} ids={} stream={} server={}", flow_observed.body,
                     flow_client_events.window_update_ids.size(), flow_client_events.window_update_ids,
                     flow_stream, flow_observed.headers.size());
        return 28;
    }
    std::println("HTTP/2 server session response, fragmentation, limits, DATA and reentrancy passed");
}
