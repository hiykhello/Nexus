// HTTP/2 server flow control, mid-frame cancel, GOAWAY shutdown and flood bounds (split from http2_server.cpp).
import std;
import http2.server;
import nghttp2;
#include "http2_server_helpers.hpp"

int main() {
    std::array good{nv(":method", "POST"), nv(":scheme", "https"), nv(":authority", "example.test"), nv(":path", "/ok")};
    constexpr std::string_view later_body = "later response";

    // Explicit WINDOW_UPDATE replenishment on small 8-byte stream window.
    Observed flow_observed;
    nh::ServerEvents flow_events{&flow_observed, on_headers, on_data, on_end, on_closed};
    auto flow_session = nh::ServerSession::create({8, 4, 128, 64, 16, 8, 64, 0, 0}, flow_events);
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
    if (h2::nghttp2_session_get_remote_settings(flow_client, h2::NGHTTP2_SETTINGS_HEADER_TABLE_SIZE) != 0) return 42;
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

    // Mid-frame DATA pause + cancel + survivor upload > connection window.
    Observed cancel_observed;
    nh::ServerEvents cancel_events{&cancel_observed, on_headers, on_data, on_end, on_closed};
    auto cancel_session = nh::ServerSession::create({8, 4, 128, 64, 16, 65535}, cancel_events);
    if (!cancel_session) return 58;
    cancel_observed.session = cancel_session->get();
    h2::nghttp2_session_callbacks* cancel_callbacks = nullptr;
    if (h2::nghttp2_session_callbacks_new(&cancel_callbacks)) return 59;
    h2::nghttp2_session_callbacks_set_on_frame_recv_callback(cancel_callbacks, on_client_frame);
    h2::nghttp2_session_callbacks_set_on_stream_close_callback(cancel_callbacks, on_client_close);
    Client cancel_client_events;
    h2::nghttp2_session* cancel_client = nullptr;
    auto cancel_rc = h2::nghttp2_session_client_new(&cancel_client, cancel_callbacks, &cancel_client_events);
    h2::nghttp2_session_callbacks_del(cancel_callbacks);
    if (cancel_rc) return 60;
    std::unique_ptr<h2::nghttp2_session, decltype(&h2::nghttp2_session_del)> cancel_owner(cancel_client, h2::nghttp2_session_del);
    if (h2::nghttp2_submit_settings(cancel_client, 0, nullptr, 0) ||
        !to_server(cancel_client, **cancel_session) || !to_client(**cancel_session, cancel_client)) return 61;
    std::string canceled_body(32768, 'x');
    BodySource cancel_body{canceled_body};
    h2::nghttp2_data_provider2 cancel_provider{};
    cancel_provider.source.ptr = &cancel_body;
    cancel_provider.read_callback = read_body;
    auto canceled_upload = h2::nghttp2_submit_request2(cancel_client, nullptr, good.data(), good.size(), &cancel_provider, nullptr);
    cancel_observed.pause_data = true;
    bool canceled_paused = false;
    while (!canceled_paused) {
        std::uint8_t const* bytes = nullptr;
        auto size = h2::nghttp2_session_mem_send2(cancel_client, &bytes);
        if (size <= 0) return 62;
        auto total = static_cast<std::size_t>(size);
        auto first = total > 10 && bytes[3] == h2::NGHTTP2_DATA ? std::size_t{10} : total;
        auto received = (**cancel_session).receive({reinterpret_cast<std::byte const*>(bytes), first});
        if (!received || *received != first) return 63;
        canceled_paused = cancel_observed.did_pause;
        if (canceled_paused) {
            if (first == total || cancel_observed.body != "x" || (**cancel_session).receive({}) ||
                (**cancel_session).reset_stream(canceled_upload, h2::NGHTTP2_CANCEL) ||
                !(**cancel_session).resume_input(canceled_upload) ||
                !(**cancel_session).reset_stream(canceled_upload, h2::NGHTTP2_CANCEL)) return 64;
            auto remaining = (**cancel_session).receive({reinterpret_cast<std::byte const*>(bytes + first), total - first});
            if (!remaining || *remaining != total - first) return 68;
        } else if (first != total) return 69;
    }
    if (!to_client(**cancel_session, cancel_client) || cancel_client_events.reset_id != canceled_upload ||
        cancel_client_events.reset_code != h2::NGHTTP2_CANCEL) return 64;
    cancel_observed.body.clear();
    std::string survivor_body(80000, 'y');
    BodySource survivor_source{survivor_body};
    h2::nghttp2_data_provider2 survivor_provider{};
    survivor_provider.source.ptr = &survivor_source;
    survivor_provider.read_callback = read_body;
    auto survivor_upload = h2::nghttp2_submit_request2(cancel_client, nullptr, good.data(), good.size(), &survivor_provider, nullptr);
    if (survivor_upload <= canceled_upload) return 65;
    for (int i = 0; i < 100 && cancel_observed.ended != survivor_upload; ++i)
        if (!to_server(cancel_client, **cancel_session) || !to_client(**cancel_session, cancel_client)) return 66;
    if (cancel_observed.ended != survivor_upload || cancel_observed.body != survivor_body ||
        std::ranges::find(cancel_client_events.window_update_ids, 0) == cancel_client_events.window_update_ids.end()) return 67;

    // Graceful two-phase GOAWAY shutdown.
    Observed shutdown_observed;
    nh::ServerEvents shutdown_events{&shutdown_observed, on_headers, on_data, on_end, on_closed};
    auto shutdown_session = nh::ServerSession::create({8, 4, 128, 64, 16}, shutdown_events);
    if (!shutdown_session) return 43;
    shutdown_observed.session = shutdown_session->get();
    h2::nghttp2_session_callbacks* shutdown_callbacks = nullptr;
    if (h2::nghttp2_session_callbacks_new(&shutdown_callbacks)) return 44;
    h2::nghttp2_session_callbacks_set_on_frame_recv_callback(shutdown_callbacks, on_client_frame);
    h2::nghttp2_session_callbacks_set_on_data_chunk_recv_callback(shutdown_callbacks, on_client_data);
    Client shutdown_client_events;
    h2::nghttp2_session* shutdown_client = nullptr;
    auto shutdown_rc = h2::nghttp2_session_client_new(&shutdown_client, shutdown_callbacks, &shutdown_client_events);
    h2::nghttp2_session_callbacks_del(shutdown_callbacks);
    if (shutdown_rc) return 45;
    std::unique_ptr<h2::nghttp2_session, decltype(&h2::nghttp2_session_del)> shutdown_owner(shutdown_client, h2::nghttp2_session_del);
    if (h2::nghttp2_submit_settings(shutdown_client, 0, nullptr, 0) ||
        !to_server(shutdown_client, **shutdown_session) || !to_client(**shutdown_session, shutdown_client)) return 46;
    auto shutdown_stream = h2::nghttp2_submit_request2(shutdown_client, nullptr, good.data(), good.size(), nullptr, nullptr);
    if (shutdown_stream <= 0 || !to_server(shutdown_client, **shutdown_session)) return 47;
    if ((**shutdown_session).finish_shutdown() || !(**shutdown_session).start_shutdown() ||
        (**shutdown_session).start_shutdown() || (**shutdown_session).shutdown_complete()) return 48;
    if (!to_client(**shutdown_session, shutdown_client) || shutdown_client_events.goaway_ids != std::vector<std::int32_t>{0x7fffffff}) return 49;
    if (!(**shutdown_session).finish_shutdown() || (**shutdown_session).finish_shutdown() ||
        (**shutdown_session).shutdown_complete()) return 50;
    if (!(**shutdown_session).respond_body(shutdown_stream, 200,
        {reinterpret_cast<std::byte const*>(later_body.data()), later_body.size()})) return 51;
    if (!to_client(**shutdown_session, shutdown_client) || shutdown_client_events.body != later_body ||
        shutdown_client_events.goaway_ids != std::vector<std::int32_t>{0x7fffffff, shutdown_stream} ||
        !(**shutdown_session).shutdown_complete()) return 52;

    // Peer ACK flood bounds and outbound_queue_frames cap.
    Observed flood_observed;
    nh::ServerEvents flood_events{&flood_observed, on_headers, on_data, on_end, on_closed};
    if (nh::ServerSession::create({8, 4, 128, 64, 16, 8, 0}, flood_events)) return 33;
    auto flood_session = nh::ServerSession::create({8, 4, 128, 64, 16, 8, 2}, flood_events);
    if (!flood_session) return 34;
    flood_observed.session = flood_session->get();
    h2::nghttp2_session_callbacks* flood_callbacks = nullptr;
    if (h2::nghttp2_session_callbacks_new(&flood_callbacks)) return 35;
    h2::nghttp2_session* flood_client = nullptr;
    auto flood_rc = h2::nghttp2_session_client_new(&flood_client, flood_callbacks, nullptr);
    h2::nghttp2_session_callbacks_del(flood_callbacks);
    if (flood_rc) return 36;
    std::unique_ptr<h2::nghttp2_session, decltype(&h2::nghttp2_session_del)> flood_owner(flood_client, h2::nghttp2_session_del);
    if (h2::nghttp2_submit_settings(flood_client, 0, nullptr, 0) || !to_server(flood_client, **flood_session)) return 37;
    std::array<std::uint8_t, 8> opaque{};
    for (int i = 0; i < 4; ++i) if (h2::nghttp2_submit_ping(flood_client, 0, opaque.data())) return 38;
    bool flooded = false;
    for (;;) {
        std::uint8_t const* bytes = nullptr;
        auto size = h2::nghttp2_session_mem_send2(flood_client, &bytes);
        if (size < 0) return 39;
        if (!size) break;
        auto received = (**flood_session).receive({reinterpret_cast<std::byte const*>(bytes), static_cast<std::size_t>(size)});
        if (!received) {
            flooded = received.error().kind == nh::ServerErrorKind::library && received.error().library_code == h2::NGHTTP2_ERR_FLOODED;
            break;
        }
    }
    if (!flooded) return 40;
    auto flood_after = (**flood_session).receive({});
    if (flood_after || flood_after.error().kind != nh::ServerErrorKind::failed) return 41;

    nh::ServerLimits zero_obq{8, 4, 128, 64, 16}; zero_obq.outbound_queue_frames = 0;
    if (nh::ServerSession::create(zero_obq, flood_events)) return 68;
    nh::ServerLimits bounded_obq{8, 4, 128, 64, 16, 8, 64}; bounded_obq.outbound_queue_frames = 2;
    auto obq_session = nh::ServerSession::create(bounded_obq, flood_events);
    if (!obq_session) return 69;
    flood_observed.session = obq_session->get();
    h2::nghttp2_session_callbacks* obq_callbacks = nullptr;
    if (h2::nghttp2_session_callbacks_new(&obq_callbacks)) return 70;
    h2::nghttp2_session* obq_client = nullptr;
    auto obq_rc = h2::nghttp2_session_client_new(&obq_client, obq_callbacks, nullptr);
    h2::nghttp2_session_callbacks_del(obq_callbacks);
    if (obq_rc) return 71;
    std::unique_ptr<h2::nghttp2_session, decltype(&h2::nghttp2_session_del)> obq_owner(obq_client, h2::nghttp2_session_del);
    if (h2::nghttp2_submit_settings(obq_client, 0, nullptr, 0) || !to_server(obq_client, **obq_session)) return 72;
    if ((**obq_session).outbound_queue_size() == 0) return 73;
    for (int i = 0; i < 4; ++i) if (h2::nghttp2_submit_ping(obq_client, 0, opaque.data())) return 74;
    bool obq_flooded = false;
    for (;;) {
        std::uint8_t const* bytes = nullptr;
        auto size = h2::nghttp2_session_mem_send2(obq_client, &bytes);
        if (size < 0) return 75;
        if (!size) break;
        auto received = (**obq_session).receive({reinterpret_cast<std::byte const*>(bytes), static_cast<std::size_t>(size)});
        if (!received) {
            obq_flooded = received.error().kind == nh::ServerErrorKind::library && received.error().library_code == h2::NGHTTP2_ERR_FLOODED;
            break;
        }
    }
    if (!obq_flooded) return 76;
    std::println("HTTP/2 server flow control, cancellation, GOAWAY shutdown and flood bounds passed");
}
