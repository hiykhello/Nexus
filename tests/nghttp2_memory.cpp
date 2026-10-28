import std;
import nexus.thirdparty.nghttp2;
import nexus.http2.headers;

namespace h2 = nex::nghttp2;

struct Observed {
    std::vector<std::pair<std::string, std::string>> headers;
    std::int32_t stream = 0;
    bool failed = false;
};

auto header_callback(h2::nghttp2_session*, h2::nghttp2_frame const* frame,
                     std::uint8_t const* name, std::size_t name_size,
                     std::uint8_t const* value, std::size_t value_size,
                     std::uint8_t, void* data) noexcept -> int {
    auto& observed = *static_cast<Observed*>(data);
    try {
        observed.stream = frame->hd.stream_id;
        observed.headers.emplace_back(std::string(reinterpret_cast<char const*>(name), name_size),
                                      std::string(reinterpret_cast<char const*>(value), value_size));
        return 0;
    } catch (...) { observed.failed = true; return -1; }
}

struct BoundedObserved {
    nexus::http2::HeaderBlock block{4, 128};
    std::vector<std::int32_t> completed;
    std::vector<nexus::http2::Header> last;
    unsigned rejected = 0;
};

auto begin_bounded(h2::nghttp2_session*, h2::nghttp2_frame const* frame, void* data) noexcept -> int {
    static_cast<BoundedObserved*>(data)->block.begin(frame->hd.stream_id);
    return 0;
}
auto header_bounded(h2::nghttp2_session*, h2::nghttp2_frame const* frame,
                    std::uint8_t const* name, std::size_t name_size,
                    std::uint8_t const* value, std::size_t value_size,
                    std::uint8_t, void* data) noexcept -> int {
    auto& observed = *static_cast<BoundedObserved*>(data);
    auto result = observed.block.add(frame->hd.stream_id,
        {reinterpret_cast<char const*>(name), name_size},
        {reinterpret_cast<char const*>(value), value_size});
    if (result == nexus::http2::HeaderResult::accepted) return 0;
    observed.block.discard();
    if (result == nexus::http2::HeaderResult::limit_exceeded) {
        ++observed.rejected;
        return h2::NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    return h2::NGHTTP2_ERR_CALLBACK_FAILURE;
}
auto frame_bounded(h2::nghttp2_session*, h2::nghttp2_frame const* frame, void* data) noexcept -> int {
    if (frame->hd.type != h2::NGHTTP2_HEADERS) return 0;
    auto& observed = *static_cast<BoundedObserved*>(data);
    try {
        if (observed.block.stream() != frame->hd.stream_id) return h2::NGHTTP2_ERR_CALLBACK_FAILURE;
        auto fields = observed.block.fields();
        observed.last.assign(fields.begin(), fields.end());
        observed.completed.push_back(frame->hd.stream_id);
        observed.block.discard();
        return 0;
    } catch (...) { return h2::NGHTTP2_ERR_CALLBACK_FAILURE; }
}

struct ClosedStream { std::int32_t id = 0; std::uint32_t error = 0; };
auto closed_stream(h2::nghttp2_session*, std::int32_t id, std::uint32_t error, void* data) noexcept -> int {
    *static_cast<ClosedStream*>(data) = {id, error};
    return 0;
}

auto nv(std::string_view name, std::string_view value) -> h2::nghttp2_nv {
    return {reinterpret_cast<std::uint8_t*>(const_cast<char*>(name.data())),
            reinterpret_cast<std::uint8_t*>(const_cast<char*>(value.data())),
            name.size(), value.size(), 0};
}

auto pump(h2::nghttp2_session* from, h2::nghttp2_session* to) -> std::expected<std::size_t, int> {
    std::size_t total = 0;
    for (unsigned round = 0; round != 32; ++round) {
        auto const* data = static_cast<std::uint8_t const*>(nullptr);
        auto length = h2::nghttp2_session_mem_send2(from, &data);
        if (length < 0) return std::unexpected(static_cast<int>(length));
        if (length == 0) return total;
        // Deliberately fragment input; data remains valid until the next send.
        for (std::size_t offset = 0; offset < static_cast<std::size_t>(length); ++offset) {
            auto consumed = h2::nghttp2_session_mem_recv2(to, data + offset, 1);
            if (consumed != 1) return std::unexpected(static_cast<int>(consumed));
        }
        total += static_cast<std::size_t>(length);
    }
    return std::unexpected(-1);
}

auto bounded_test() -> bool {
    using namespace nexus::http2;
    HeaderBlock block{2, 3};
    block.begin(1);
    if (block.add(1, "a", "bc") != HeaderResult::accepted ||
        block.add(1, "", "x") != HeaderResult::limit_exceeded ||
        block.add(3, "", "") != HeaderResult::invalid_state) return false;
    block.begin(3);
    if (block.add(3, "", "") != HeaderResult::accepted ||
        block.add(3, "", "") != HeaderResult::accepted ||
        block.add(3, "", "") != HeaderResult::limit_exceeded) return false;
    block.discard();
    if (block.stream() != 0 || !block.fields().empty()) return false;

    h2::nghttp2_session_callbacks* callbacks = nullptr;
    if (h2::nghttp2_session_callbacks_new(&callbacks) != 0) return false;
    h2::nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, begin_bounded);
    h2::nghttp2_session_callbacks_set_on_header_callback(callbacks, header_bounded);
    h2::nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, frame_bounded);
    BoundedObserved observed;
    ClosedStream closed;
    h2::nghttp2_session_callbacks* client_callbacks = nullptr;
    if (h2::nghttp2_session_callbacks_new(&client_callbacks) != 0) {
        h2::nghttp2_session_callbacks_del(callbacks); return false;
    }
    h2::nghttp2_session_callbacks_set_on_stream_close_callback(client_callbacks, closed_stream);
    h2::nghttp2_session *client = nullptr, *server = nullptr;
    auto error = h2::nghttp2_session_client_new(&client, client_callbacks, &closed);
    h2::nghttp2_session_callbacks_del(client_callbacks);
    if (error == 0) error = h2::nghttp2_session_server_new(&server, callbacks, &observed);
    h2::nghttp2_session_callbacks_del(callbacks);
    if (error != 0) { if (client) h2::nghttp2_session_del(client); return false; }
    auto cleanup = [&] { h2::nghttp2_session_del(client); h2::nghttp2_session_del(server); };
    std::array large{nv(":method", "GET"), nv(":scheme", "https"),
                     nv(":authority", "example.test"), nv(":path", "/"), nv("extra", "value")};
    std::array good{nv(":method", "GET"), nv(":scheme", "https"),
                    nv(":authority", "example.test"), nv(":path", "/ok")};
    auto first = h2::nghttp2_submit_request2(client, nullptr, large.data(), large.size(), nullptr, nullptr);
    auto second = h2::nghttp2_submit_request2(client, nullptr, good.data(), good.size(), nullptr, nullptr);
    bool ok = h2::nghttp2_submit_settings(client, 0, nullptr, 0) == 0 &&
              h2::nghttp2_submit_settings(server, 0, nullptr, 0) == 0 &&
              first > 0 && second > first && pump(client, server).has_value() &&
              pump(server, client).has_value() && observed.rejected == 1 &&
              observed.completed == std::vector<std::int32_t>{second} &&
              observed.last.size() == 4 && observed.last.back() == Header{":path", "/ok"} &&
              observed.block.stream() == 0 && closed.id == first && closed.error == h2::NGHTTP2_INTERNAL_ERROR;
    cleanup();
    return ok;
}

int main() {
    h2::nghttp2_session_callbacks* callbacks = nullptr;
    if (h2::nghttp2_session_callbacks_new(&callbacks) != 0) return 1;
    h2::nghttp2_session_callbacks_set_on_header_callback(callbacks, header_callback);
    Observed client_observed, server_observed;
    h2::nghttp2_session *client = nullptr, *server = nullptr;
    auto error = h2::nghttp2_session_client_new(&client, callbacks, &client_observed);
    if (error == 0) error = h2::nghttp2_session_server_new(&server, callbacks, &server_observed);
    h2::nghttp2_session_callbacks_del(callbacks);
    if (error != 0 || !client || !server) return 2;
    auto cleanup = [&] { h2::nghttp2_session_del(client); h2::nghttp2_session_del(server); };
    if (h2::nghttp2_submit_settings(client, 0, nullptr, 0) != 0 ||
        h2::nghttp2_submit_settings(server, 0, nullptr, 0) != 0) { cleanup(); return 3; }
    std::array request{nv(":method", "GET"), nv(":scheme", "https"),
                       nv(":authority", "example.test"), nv(":path", "/probe")};
    auto stream = h2::nghttp2_submit_request2(client, nullptr, request.data(), request.size(), nullptr, nullptr);
    if (stream <= 0) { cleanup(); return 4; }
    if (!pump(client, server) || !pump(server, client) || server_observed.failed ||
        server_observed.stream != stream || server_observed.headers.size() != 4 ||
        server_observed.headers[3] != std::pair<std::string, std::string>{":path", "/probe"}) { cleanup(); return 5; }
    std::array response{nv(":status", "204")};
    if (h2::nghttp2_submit_response2(server, stream, response.data(), response.size(), nullptr) != 0 ||
        !pump(server, client) || client_observed.failed || client_observed.stream != stream ||
        client_observed.headers != std::vector<std::pair<std::string, std::string>>{{":status", "204"}}) { cleanup(); return 6; }
    cleanup();
    if (!bounded_test()) return 7;
    std::println("nghttp2 fragmented memory request, response, and bounded headers passed");
}
