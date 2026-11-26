import std;
import http2.server;
import nghttp2;
#include "http2_server_helpers.hpp"

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
    if (observed.headers != std::vector<std::int32_t>{second} || !observed.reentrant || !observed.response_reentrant || !observed.reset_reentrant || observed.header_ended ||
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
    for (auto const& field : std::array<nh::Header, 5>{{{"Content-Type", "text/plain"}, {":status", "200"},
             {"connection", "close"}, {"content-length", "12"}, {"x-test", "bad\r\nvalue"}}}) {
        auto invalid = (**session).respond_body(second, 200,
            {reinterpret_cast<std::byte const*>(response.data()), response.size()}, std::span{&field, 1});
        if (invalid || invalid.error().kind != nh::ServerErrorKind::invalid_argument) return 82;
    }
    for (auto const& length : std::array<std::string_view, 4>{"", "+13", "13x", "999999999999999999999999999"}) {
        std::array<nh::Header, 1> invalid_length{{{"content-length", std::string(length)}}};
        if ((**session).respond_body(second, 200,
            {reinterpret_cast<std::byte const*>(response.data()), response.size()}, invalid_length)) return 91;
    }
    std::vector<nh::Header> excessive(33, nh::Header{"x-test", "a"});
    if ((**session).respond_empty(second, 200, excessive)) return 83;
    std::array<nh::Header, 1> oversized_header{{{"x-test", std::string(8192, 'x')}}};
    auto too_many_bytes = (**session).respond_empty(second, 200, oversized_header);
    if (too_many_bytes || too_many_bytes.error().kind != nh::ServerErrorKind::invalid_argument) return 84;
    std::array<nh::Header, 2> response_headers{{{"content-type", "text/plain"}, {"content-length", "13"}}};
    if (!(**session).respond_body(second, 200,
        {reinterpret_cast<std::byte const*>(response.data()), response.size()}, response_headers)) return 13;
    if ((**session).response_memory_used() != response.size()) return 97;
    response_headers[0].value = "changed after submission";
    auto duplicate = (**session).respond_empty(second, 204);
    if (duplicate || duplicate.error().kind != nh::ServerErrorKind::invalid_state) return 14;
    auto third = h2::nghttp2_submit_request2(client, nullptr, good.data(), good.size(), nullptr, nullptr);
    if (third <= second || !to_server(client, **session)) return 19;
    std::array<std::byte, 8> second_body{};
    auto total_over = (**session).respond_body(third, 200, second_body);
    if (total_over || total_over.error().kind != nh::ServerErrorKind::invalid_argument ||
        !(**session).respond_empty(third, 204, std::array<nh::Header, 1>{{{"x-test", "yes"}}})) return 20;
    if (!to_client(**session, client) || client_events.response_ids != std::vector<std::int32_t>{second, third} ||
        !client_events.status_204 || client_events.body != "response body" ||
        client_events.content_type != "text/plain" || client_events.extra_header != "yes" || client_events.content_length != "13") return 15;
    if ((**session).response_memory_used() != 0) return 98;
    auto closed = (**session).respond_empty(second, 204);
    if (closed || closed.error().kind != nh::ServerErrorKind::invalid_state) return 16;
    auto empty = (**session).output({});
    if (!empty || *empty != 0) return 8;

    auto earlier = h2::nghttp2_submit_request2(client, nullptr, good.data(), good.size(), nullptr, nullptr);
    auto later = h2::nghttp2_submit_request2(client, nullptr, good.data(), good.size(), nullptr, nullptr);
    if (earlier <= third || later <= earlier || !to_server(client, **session)) return 29;
    constexpr std::string_view later_body = "later response";
    if (!(**session).respond_body(earlier, 200, forbidden_body) ||
        !(**session).respond_body(later, 200, {reinterpret_cast<std::byte const*>(later_body.data()), later_body.size()})) return 30;
    if (h2::nghttp2_submit_rst_stream(client, 0, earlier, h2::NGHTTP2_INTERNAL_ERROR) || !to_server(client, **session)) return 31;
    client_events.body.clear();
    if (!to_client(**session, client) || client_events.body != later_body) return 32;
    auto canceled = h2::nghttp2_submit_request2(client, nullptr, good.data(), good.size(), nullptr, nullptr);
    auto survivor = h2::nghttp2_submit_request2(client, nullptr, good.data(), good.size(), nullptr, nullptr);
    if (canceled <= later || survivor <= canceled || !to_server(client, **session)) return 53;
    if (!(**session).respond_body(canceled, 200, {reinterpret_cast<std::byte const*>(later_body.data()), later_body.size()}) ||
        (**session).response_memory_used() != later_body.size()) return 54;
    if ((**session).reset_stream(0, h2::NGHTTP2_CANCEL) || (**session).reset_stream(999, h2::NGHTTP2_CANCEL) ||
        !(**session).reset_stream(canceled, h2::NGHTTP2_CANCEL) || (**session).reset_stream(canceled, h2::NGHTTP2_CANCEL) ||
        (**session).respond_empty(canceled, 204) || (**session).respond_body(survivor, 200, second_body)) return 55;
    client_events.body.clear();
    if (!to_client(**session, client) || client_events.reset_id != canceled || client_events.reset_code != h2::NGHTTP2_CANCEL ||
        observed.closed_id != canceled || observed.closed_code != h2::NGHTTP2_CANCEL || !client_events.body.empty() ||
        (**session).response_memory_used() != 0) return 56;
    if (!(**session).respond_body(survivor, 200, second_body) || !to_client(**session, client) ||
        client_events.body.size() != second_body.size()) return 57;

    auto partial = h2::nghttp2_submit_request2(client, nullptr, good.data(), good.size(), nullptr, nullptr);
    auto concurrent = h2::nghttp2_submit_request2(client, nullptr, good.data(), good.size(), nullptr, nullptr);
    if (partial <= survivor || concurrent <= partial || !to_server(client, **session) ||
        !(**session).respond_body(partial, 200, {reinterpret_cast<std::byte const*>(later_body.data()), later_body.size()})) return 100;
    std::array<std::byte, 9> frame_header{};
    std::array<std::byte, 1> byte{};
    for (;;) {
        for (auto& item : frame_header) {
            auto n = (**session).output(byte);
            if (!n || *n != 1 || h2::nghttp2_session_mem_recv2(client, reinterpret_cast<std::uint8_t const*>(byte.data()), 1) != 1) return 101;
            item = byte[0];
        }
        auto length = (std::to_integer<std::size_t>(frame_header[0]) << 16) |
                      (std::to_integer<std::size_t>(frame_header[1]) << 8) | std::to_integer<std::size_t>(frame_header[2]);
        if (std::to_integer<unsigned>(frame_header[3]) == h2::NGHTTP2_DATA) {
            if (length != later_body.size()) return 102;
            break;
        }
        for (std::size_t i = 0; i < length; ++i) {
            auto n = (**session).output(byte);
            if (!n || *n != 1 || h2::nghttp2_session_mem_recv2(client, reinterpret_cast<std::uint8_t const*>(byte.data()), 1) != 1) return 103;
        }
    }
    auto n = (**session).output(byte);
    if (!n || *n != 1 || byte[0] != static_cast<std::byte>(later_body[0]) ||
        h2::nghttp2_session_mem_recv2(client, reinterpret_cast<std::uint8_t const*>(byte.data()), 1) != 1 ||
        h2::nghttp2_submit_rst_stream(client, 0, partial, h2::NGHTTP2_CANCEL) || !to_server(client, **session) ||
        !(**session).respond_empty(concurrent, 204)) return 104;
    for (std::size_t i = 1; i < later_body.size(); ++i) {
        n = (**session).output(byte);
        if (!n || *n != 1 || byte[0] != static_cast<std::byte>(later_body[i]) ||
            h2::nghttp2_session_mem_recv2(client, reinterpret_cast<std::uint8_t const*>(byte.data()), 1) != 1) return 105;
    }
    if (!to_client(**session, client) || client_events.response_id != concurrent || !client_events.status_204 ||
        (**session).response_memory_used() != 0) return 106;

    std::array head_request{nv(":method", "HEAD"), nv(":scheme", "https"), nv(":authority", "example.test"), nv(":path", "/head")};
    auto head = h2::nghttp2_submit_request2(client, nullptr, head_request.data(), head_request.size(), nullptr, nullptr);
    if (head <= survivor) return 85;
    bool saw_partial_headers = false;
    for (;;) {
        std::uint8_t const* bytes = nullptr;
        auto size = h2::nghttp2_session_mem_send2(client, &bytes);
        if (size < 0) return 92;
        if (!size) break;
        auto count = static_cast<std::size_t>(size);
        if (count > 9 && bytes[3] == h2::NGHTTP2_HEADERS) {
            auto prefix = (**session).receive({reinterpret_cast<std::byte const*>(bytes), 9});
            if (!prefix || *prefix != 9 || (**session).respond_empty(head, 200)) return 93;
            auto rest = (**session).receive({reinterpret_cast<std::byte const*>(bytes + 9), count - 9});
            if (!rest || *rest != count - 9) return 94;
            saw_partial_headers = true;
        } else {
            auto received = (**session).receive({reinterpret_cast<std::byte const*>(bytes), count});
            if (!received || *received != count) return 95;
        }
    }
    if (!saw_partial_headers) return 96;
    std::array<nh::Header, 1> representation_length{{{"content-length", "123"}}};
    if ((**session).respond_body(head, 200, forbidden_body, representation_length) ||
        (**session).respond_empty(head, 204, representation_length)) return 86;
    std::array<nh::Header, 2> duplicate_length{{{"content-length", "123"}, {"content-length", "123"}}};
    if ((**session).respond_empty(head, 200, duplicate_length)) return 87;
    client_events.body.clear(); client_events.content_length.clear();
    if (!(**session).respond_empty(head, 200, representation_length) || !to_client(**session, client) ||
        !client_events.body.empty() || client_events.content_length != "123") return 88;
    auto not_modified = h2::nghttp2_submit_request2(client, nullptr, good.data(), good.size(), nullptr, nullptr);
    if (not_modified <= head || !to_server(client, **session)) return 89;
    client_events.content_length.clear();
    if (!(**session).respond_empty(not_modified, 304, representation_length) || !to_client(**session, client) ||
        client_events.content_length != "123") return 90;
    observed.fail_data = true;
    request_body.offset = 0;
    auto failure_stream = h2::nghttp2_submit_request2(client, nullptr, good.data(), good.size(), &provider, nullptr);
    if (failure_stream <= third || to_server(client, **session)) return 9;
    auto failed = (**session).receive({});
    if (failed || failed.error().kind != nh::ServerErrorKind::failed) return 10;
    auto failed_output = (**session).output({});
    if (failed_output || failed_output.error().kind != nh::ServerErrorKind::failed) return 11;
    std::println("HTTP/2 server session response, fragmentation, limits, DATA and reentrancy passed");
}
