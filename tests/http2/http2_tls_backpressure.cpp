#include <boost/corosio/backend.hpp>
#include <errno.h>
#include <sys/socket.h>
import std;
import http2.tls_server;
import tls.application_io;
import nghttp2;
import capy;
import corosio;

namespace h = http2;
static thread_local std::size_t watched_size = 0;
static thread_local void* watched_allocation = nullptr;
static thread_local h::ServerSession* watched_session = nullptr;
static thread_local bool released_with_input_charge = false;
static thread_local bool watch_output = false, released_with_output_charge = false;

void* operator new(std::size_t size) {
    if (auto p = std::malloc(size ? size : 1)) {
        if (watched_size && size == watched_size) { watched_allocation = p; if (!watch_output) watched_size = 0; }
        return p;
    }
    throw std::bad_alloc{};
}
void operator delete(void* p) noexcept {
    if (p && p == watched_allocation) {
        if (watch_output) released_with_output_charge = watched_session && watched_session->output_memory_charge() == 183;
        else released_with_input_charge = watched_session && watched_session->input_memory_charge() == 16640;
        watched_allocation = nullptr;
    }
    std::free(p);
}
void operator delete(void* p, std::size_t) noexcept { ::operator delete(p); }

#include "http2_tls_backpressure_fixture.hpp"

template<class Backend> auto input_budget(Backend backend, bool enough) -> bool {
    h::ServerEvents events{nullptr, headers, data, end, closed}; h::ServerLimits limits{8, 16, 4096, 1024, 4096};
    auto reference = h::ServerSession::create(limits, events); if (!reference) return false;
    std::array<std::byte, 4096> sink{};
    for (;;) { auto n = (**reference).output(sink); if (!n) return false; if (!*n) break; }
    auto baseline = (**reference).shared_memory_used(); reference->reset();
    limits.shared_memory_bytes = baseline + (enough ? 53953 : 53952);
    auto session = h::ServerSession::create(limits, events); if (!session) return false;
    for (;;) { auto n = (**session).output(sink); if (!n) return false; if (!*n) break; }
    io::io_context context(backend); io::local_stream_socket a(context), b(context); if (io::connect_pair(a, b)) return false;
    Connection connection(a, **session, records(), c::Bytes{}); bool done = false; std::optional<h::TlsServerError> error;
    if (enough) {
        constexpr std::array<std::uint8_t, 8> partial{23, 3, 3, 0, 30, 1, 2, 3};
        if (::send(b.native_handle(), partial.data(), partial.size(), MSG_NOSIGNAL) != static_cast<ssize_t>(partial.size())) return false;
    }
    capy::run_async(context.get_executor())(read_step(connection, done, error)); context.restart(); (void)context.run_for(20ms);
    if (enough) {
        if (done || (**session).shared_memory_used() != baseline + 53953 || (**session).ciphertext_memory_charge() != 16650 || (**session).scratch_memory_charge() != 16384) return false;
        connection.cancel(); context.restart(); (void)context.run_for(1s);
        auto output = (**session).output(sink);
        return done && error == h::TlsServerError::tls && context.stopped() && (**session).shared_memory_used() == baseline + 4096 &&
            (**session).transport_memory_charge() == 4096 && !(**session).ciphertext_memory_charge() && !(**session).scratch_memory_charge() &&
            !output && output.error().kind == h::ServerErrorKind::failed;
    }
    auto output = (**session).output(sink);
    return done && error == h::TlsServerError::budget_exceeded && context.stopped() && (**session).shared_memory_used() == baseline + 4096 &&
        (**session).transport_memory_charge() == 4096 && !output && output.error().kind == h::ServerErrorKind::failed;
}

template<class Backend> auto invalid_max_record(Backend backend) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context), b(context); if (io::connect_pair(a, b)) return false;
    h::ServerLimits limits{8, 16, 4096, 262144, 262144}; limits.shared_memory_bytes = 262144;
    auto session = h::ServerSession::create(limits, {nullptr, headers, data, end, closed}); if (!session) return false;
    std::array<std::byte, 4096> sink{};
    for (;;) { auto n = (**session).output(sink); if (!n) return false; if (!*n) break; }
    Connection connection(a, **session, records(), c::Bytes{});
    c::Bytes wire(16645, 0); wire[0] = 23; wire[1] = 3; wire[2] = 3; wire[3] = 65; wire[4] = 0;
    if (::send(b.native_handle(), wire.data(), wire.size(), MSG_NOSIGNAL) != static_cast<ssize_t>(wire.size())) return false;
    bool done = false; std::optional<h::TlsServerError> error;
    capy::run_async(context.get_executor())(read_step(connection, done, error)); context.restart(); (void)context.run_for(1s);
    return context.stopped() && done && error == h::TlsServerError::tls && !(**session).input_memory_charge() &&
        !(**session).ciphertext_memory_charge() && !(**session).scratch_memory_charge();
}

template<class Backend> auto control_budget(Backend backend, int mode) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context), b(context); if (io::connect_pair(a, b)) return false;
    auto session = h::ServerSession::create({8, 16, 4096, 1024, 4096}, {nullptr, headers, data, end, closed}); if (!session) return false;
    std::array<std::byte, 4096> sink{};
    for (;;) { auto n = (**session).output(sink); if (!n) return false; if (!*n) break; }
    auto peer = layer(t::RecordDirection::send, 2); c::Bytes update{24, 0, 0, 1, 1};
    auto wire = peer.seal(t::ContentType::handshake, update); if (!wire) return false;
    auto connection = std::make_unique<Connection>(a, **session, records(), std::move(*wire));
    bool done = false, progress = false;
    if (mode == 1 || mode == 3) { watched_session = session->get(); watched_size = 27; watch_output = true; released_with_output_charge = false; }
    capy::run_async(context.get_executor())(progress_step(*connection, done, progress)); context.restart(); (void)context.run_for(1s);
    watched_size = 0;
    if (!context.stopped() || !done || !progress || (**session).output_memory_charge() != 183 || (**session).input_memory_charge()) return false;
    if (mode == 1 || mode == 3) {
        if (!watched_allocation) return false;
        if (mode == 1) connection->cancel(); else connection.reset();
        auto ok = !watched_allocation && released_with_output_charge && (**session).output_memory_charge() == 0;
        watched_session = nullptr; watch_output = false; return ok;
    }
    if (mode == 2) {
        std::array<char, 4096> filler{};
        for (;;) {
            auto n = ::send(a.native_handle(), filler.data(), filler.size(), MSG_DONTWAIT | MSG_NOSIGNAL);
            if (n > 0 || (n < 0 && errno == EINTR)) continue;
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            return false;
        }
    }
    done = false; std::optional<h::TlsServerError> error;
    capy::run_async(context.get_executor())(read_step(*connection, done, error)); context.restart(); (void)context.run_for(20ms);
    if (mode == 2) {
        if (done || (**session).output_memory_charge() != 183) return false;
        connection->cancel(); if ((**session).output_memory_charge() != 183) return false;
        context.restart(); (void)context.run_for(1s);
        return context.stopped() && done && error == h::TlsServerError::tls && !(**session).output_memory_charge();
    }
    std::array<std::uint8_t, 27> response{}; auto n = ::recv(b.native_handle(), response.data(), response.size(), MSG_DONTWAIT);
    return context.stopped() && done && !error && !(**session).output_memory_charge() && n == 27 && response[0] == 23;
}

template<class Backend> auto terminal_write(Backend backend, bool cancel) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context), b(context);
    if (io::connect_pair(a, b)) return false;
    auto session = h::ServerSession::create({8, 16, 4096, 1024, 4096}, {nullptr, headers, data, end, closed});
    if (!session) return false;
    constexpr std::string_view preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    constexpr std::array<std::byte, 15> settings{std::byte{0}, std::byte{0}, std::byte{6}, std::byte{4},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{4}};
    constexpr std::array<std::byte, 15> request{std::byte{0}, std::byte{0}, std::byte{6}, std::byte{1}, std::byte{5},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1}, std::byte{0x82}, std::byte{0x87},
        std::byte{0x01}, std::byte{0x01}, std::byte{'x'}, std::byte{0x84}};
    constexpr std::array<std::byte, 10> unfinished{std::byte{0}, std::byte{0}, std::byte{1}, std::byte{1},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{3}, std::byte{0x82}};
    constexpr std::array<std::byte, 17> ping{std::byte{0}, std::byte{0}, std::byte{8}, std::byte{6}};
    std::array<std::byte, 512> body{};
    if (!(**session).receive(std::as_bytes(std::span{preface})) || !(**session).receive(settings) ||
        !(**session).receive(request) || !(**session).respond_body(1, 200, body)) return false;
    std::array<std::byte, 4096> sink{};
    for (;;) { auto n = (**session).output(sink); if (!n) return false; if (!*n) break; }
    if (!(**session).receive(unfinished) || !(**session).receive(ping)) return false;
    Connection connection(a, **session, records(), c::Bytes{});
    std::array<char, 4096> filler{};
    for (;;) {
        auto n = ::send(a.native_handle(), filler.data(), filler.size(), MSG_DONTWAIT | MSG_NOSIGNAL);
        if (n > 0 || (n < 0 && errno == EINTR)) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        return false;
    }
    bool done = false; std::optional<h::TlsServerError> error;
    capy::run_async(context.get_executor())(partial_step(connection, done, error));
    context.restart(); (void)context.run_for(20ms);
    auto charge = (**session).output_memory_charge();
    if (done || !charge || !(**session).terminated_by_error() || (**session).response_memory_used()) {
        std::cerr << "terminal parked: " << done << ' ' << charge << ' ' << (**session).terminated_by_error() << ' ' << (**session).response_memory_used() << '\n';
        return false;
    }
    if (cancel) connection.cancel(); else b.close();
    if ((**session).output_memory_charge() != charge) return false;
    context.restart(); (void)context.run_for(1s);
    return context.stopped() && done && error == h::TlsServerError::tls &&
        !(**session).output_memory_charge() && !(**session).scratch_memory_charge() &&
        !(**session).response_memory_used() && (**session).transport_memory_charge() == 4096;
}

template<class Socket> auto close_step(h::TlsServerConnection<Socket>& connection, bool& done, std::optional<h::TlsServerError>& error) -> capy::task<> {
    auto result = co_await connection.close_notify(); if (!result) error = result.error(); done = true;
}

template<class Backend> auto control_allocation_failure(Backend backend, bool closing) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context), b(context); if (io::connect_pair(a, b)) return false;
    auto session = h::ServerSession::create({8, 16, 4096, 1024, 4096}, {nullptr, headers, data, end, closed}); if (!session) return false;
    std::array<std::byte, 4096> sink{};
    for (;;) { auto n = (**session).output(sink); if (!n) return false; if (!*n) break; }
    auto peer = layer(t::RecordDirection::send, 2); auto message = closing ? c::Bytes{1, 0} : c::Bytes{24, 0, 0, 1, 1};
    auto wire = peer.seal(closing ? t::ContentType::alert : t::ContentType::handshake, message); if (!wire) return false;
    ThrowSocket socket{a, false, false}; h::TlsServerConnection connection(socket, **session, records(), std::move(*wire));
    bool done = false; std::optional<h::TlsServerError> error;
    capy::run_async(context.get_executor())(partial_step(connection, done, error)); context.restart(); (void)context.run_for(1s);
    if (!done || error || (**session).output_memory_charge() != (closing ? 0u : 183u)) return false;
    if (closing) {
        done = false; capy::run_async(context.get_executor())(partial_step(connection, done, error)); context.restart(); (void)context.run_for(1s);
        if (!done || error) return false;
    }
    socket.enabled = true; done = false;
    if (closing) capy::run_async(context.get_executor())(close_step(connection, done, error));
    else capy::run_async(context.get_executor())(partial_step(connection, done, error));
    context.restart(); (void)context.run_for(1s);
    auto output = (**session).output(sink); std::uint8_t byte{}; auto n = ::recv(b.native_handle(), &byte, 1, MSG_DONTWAIT);
    return context.stopped() && done && error == h::TlsServerError::allocation && n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) &&
        !(**session).input_memory_charge() && !(**session).output_memory_charge() && !(**session).ciphertext_memory_charge() &&
        !(**session).scratch_memory_charge() && (**session).transport_memory_charge() == 4096 && !output && output.error().kind == h::ServerErrorKind::failed;
}

template<class Backend> auto close_budget(Backend backend, bool blocked) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context), b(context); if (io::connect_pair(a, b)) return false;
    h::ServerLimits limits{8, 16, 4096, 1024, 4096}; limits.shared_memory_bytes = 131072;
    auto session = h::ServerSession::create(limits, {nullptr, headers, data, end, closed}); if (!session) return false;
    std::array<std::byte, 4096> sink{};
    for (;;) { auto n = (**session).output(sink); if (!n) return false; if (!*n) break; }
    auto peer = layer(t::RecordDirection::send, 2); auto wire = peer.seal(t::ContentType::alert, c::Bytes{1, 0}); if (!wire) return false;
    Connection connection(a, **session, records(), std::move(*wire)); bool done = false, progress = false;
    capy::run_async(context.get_executor())(progress_step(connection, done, progress)); context.restart(); (void)context.run_for(1s);
    if (!done || !progress || (**session).output_memory_charge()) return false;
    done = false; std::optional<h::TlsServerError> error;
    capy::run_async(context.get_executor())(read_step(connection, done, error)); context.restart(); (void)context.run_for(1s);
    if (!done || error) return false;
    if (blocked) {
        auto available = limits.shared_memory_bytes - (**session).shared_memory_used();
        if (available < 48 || !(**session).reserve_input(available - 47)) return false;
    }
    done = false; capy::run_async(context.get_executor())(close_step(connection, done, error)); context.restart(); (void)context.run_for(1s);
    std::array<std::uint8_t, 32> response{}; auto n = ::recv(b.native_handle(), response.data(), response.size(), MSG_DONTWAIT); auto read_error = errno;
    if (blocked) return context.stopped() && done && error == h::TlsServerError::budget_exceeded &&
        !(**session).output_memory_charge() && n < 0 && (read_error == EAGAIN || read_error == EWOULDBLOCK);
    return context.stopped() && done && !error && !(**session).output_memory_charge() && n == 24 && response[0] == 23;
}

template<class Backend> auto truncated_input(Backend backend) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context), b(context); if (io::connect_pair(a, b)) return false;
    auto session = h::ServerSession::create({8, 16, 4096, 1024, 4096}, {nullptr, headers, data, end, closed}); if (!session) return false;
    std::array<std::byte, 4096> sink{};
    for (;;) { auto n = (**session).output(sink); if (!n) return false; if (!*n) break; }
    constexpr std::array<std::uint8_t, 8> partial{23, 3, 3, 0, 30, 1, 2, 3};
    if (::send(b.native_handle(), partial.data(), partial.size(), MSG_NOSIGNAL) != static_cast<ssize_t>(partial.size())) return false;
    b.close(); Connection connection(a, **session, records(), c::Bytes{}); bool done = false; std::optional<h::TlsServerError> error;
    capy::run_async(context.get_executor())(read_step(connection, done, error)); context.restart(); (void)context.run_for(1s);
    auto output = (**session).output(sink);
    return context.stopped() && done && error == h::TlsServerError::tls && (**session).input_memory_charge() == 0 &&
        !output && output.error().kind == h::ServerErrorKind::failed;
}

auto pause_data(void*, std::int32_t, std::span<std::byte const>) noexcept -> h::DataDisposition { return h::DataDisposition::pause; }
auto until_paused(Connection& connection, bool& paused) -> capy::task<> {
    for (int i = 0; i < 20; ++i) {
        auto result = co_await connection.step();
        if (!result) co_return;
        if (*result == h::TlsServerStep::paused) { paused = true; co_return; }
    }
}
auto until_released(Connection& connection, h::ServerSession& session, bool& released) -> capy::task<> {
    for (int i = 0; i < 20; ++i) {
        auto result = co_await connection.step(); if (!result) co_return;
        if (!session.input_memory_charge()) { released = true; co_return; }
    }
}

template<class Backend> auto abandon_paused(Backend backend, int mode) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context), b(context); if (io::connect_pair(a, b)) return false;
    h::ServerLimits limits{8, 16, 4096, 262144, 262144}; limits.shared_memory_bytes = 262144;
    auto session = h::ServerSession::create(limits, {nullptr, headers, pause_data, end, closed}); if (!session) return false;
    constexpr std::string_view preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    c::Bytes input(preface.begin(), preface.end());
    constexpr std::array<std::uint8_t, 49> frames{0, 0, 0, 4, 0, 0, 0, 0, 0,
        0, 0, 6, 1, 5, 0, 0, 0, 1, 0x82, 0x87, 0x01, 0x01, 'x', 0x84,
        0, 0, 6, 1, 4, 0, 0, 0, 3, 0x82, 0x87, 0x01, 0x01, 'x', 0x84,
        0, 0, 1, 0, 1, 0, 0, 0, 3, 'x'};
    input.insert(input.end(), frames.begin(), frames.end());
    auto peer = layer(t::RecordDirection::send, 2); auto wire = peer.seal(t::ContentType::application_data, input); if (!wire) return false;
    auto connection = std::make_unique<Connection>(a, **session, records(), std::move(*wire)); bool paused = false;
    if (mode == 0 || mode == 2) { watched_session = session->get(); watched_size = input.size() + 1; released_with_input_charge = false; }
    capy::run_async(context.get_executor())(until_paused(*connection, paused)); context.restart(); (void)context.run_for(1s);
    watched_size = 0;
    if (!context.stopped() || !paused || (**session).paused_stream() != 3 || (**session).input_memory_charge() != 16640) return false;
    if (mode == 1) {
        auto available = limits.shared_memory_bytes - (**session).shared_memory_used();
        if (available < sizeof(nghttp2::nghttp2_nv)) return false;
        std::vector<std::byte> body(available);
        auto blocked = (**session).respond_body(1, 200, body);
        if (blocked || blocked.error().kind != h::ServerErrorKind::budget_exceeded || (**session).response_memory_used() ||
            (**session).input_memory_charge() != 16640 || (**session).shared_memory_used() > limits.shared_memory_bytes) return false;
        if (!(**session).resume_input(3)) return false;
        bool released = false; capy::run_async(context.get_executor())(until_released(*connection, **session, released));
        context.restart(); (void)context.run_for(1s);
        if (!context.stopped() || !released || (**session).input_memory_charge() || !(**session).respond_body(1, 200, body)) return false;
        return (**session).response_memory_used() == body.size() && (**session).shared_memory_used() <= limits.shared_memory_bytes;
    }
    if (mode == 3) {
        if (!(**session).respond_empty(1, 204)) return false;
        std::array<char, 4096> filler{};
        for (;;) {
            auto n = ::send(a.native_handle(), filler.data(), filler.size(), MSG_DONTWAIT | MSG_NOSIGNAL);
            if (n > 0 || (n < 0 && errno == EINTR)) continue;
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            return false;
        }
        bool done = false; std::optional<h::TlsServerError> error;
        capy::run_async(context.get_executor())(read_step(*connection, done, error)); context.restart(); (void)context.run_for(20ms);
        if (done) return false;
        connection->cancel();
        if ((**session).input_memory_charge() != 16640) return false;
        context.restart(); (void)context.run_for(1s);
        if (!done || error != h::TlsServerError::tls || !context.stopped()) return false;
    } else if (mode == 2) {
        if (!watched_allocation) return false;
        connection->cancel();
        if (watched_allocation || !released_with_input_charge) return false;
        watched_session = nullptr;
    } else {
        if (!watched_allocation) return false;
        connection.reset();
        if (watched_allocation || !released_with_input_charge) return false;
        watched_session = nullptr;
    }
    auto resumed = (**session).resume_input(3); auto output = (**session).output(std::span<std::byte>{});
    return !resumed && resumed.error().kind == h::ServerErrorKind::failed && !output &&
        output.error().kind == h::ServerErrorKind::failed && (**session).input_memory_charge() == 0;
}

template<class Backend> auto run_backend(Backend backend, std::string_view label, int fail_code) -> int {
    if (!terminal_write(backend, true) || !terminal_write(backend, false)) { std::cerr << "terminal_write(" << label << ") failed\n"; return fail_code; }
    if (!transport_budget(backend, true) || !transport_budget(backend, false)) return fail_code;
    for (int mode = 0; mode < 8; ++mode) if (!unready_records(backend, mode)) return fail_code;
    if (!allocation_failure(backend, false) || !allocation_failure(backend, true)) return fail_code;
    if (!control_allocation_failure(backend, false) || !control_allocation_failure(backend, true)) return fail_code;
    if (!wrong_role(backend)) return fail_code;
    if (!oversized_unread(backend)) { std::cerr << "oversized_unread(" << label << ") failed\n"; return fail_code; }
    if (!duplicate_owner(backend)) { std::cerr << "duplicate_owner(" << label << ") failed\n"; return fail_code; }
    if (!drop_idle_driver(backend)) { std::cerr << "drop_idle_driver(" << label << ") failed\n"; return fail_code; }
    if (!sealing_charge(backend)) { std::cerr << "sealing_charge(" << label << ") failed\n"; return fail_code; }
    if (!partial_failure(backend)) { std::cerr << "partial_failure(" << label << ") failed\n"; return fail_code; }
    if (!output_budget(backend)) { std::cerr << "output_budget(" << label << ") failed\n"; return fail_code; }
    for (int m : {0, 1, 3, 2})
        if (!control_budget(backend, m)) { std::cerr << "control_budget(" << label << "," << m << ") failed\n"; return fail_code; }
    if (!close_budget(backend, false) || !close_budget(backend, true)) { std::cerr << "close_budget(" << label << ") failed\n"; return fail_code; }
    if (!truncated_input(backend)) { std::cerr << "truncated_input(" << label << ") failed\n"; return fail_code; }
    if (!exercise(backend, false) || !exercise(backend, true)) { std::cerr << "exercise(" << label << ") failed\n"; return fail_code; }
    if (!invalid_max_record(backend)) { std::cerr << "invalid_max_record(" << label << ") failed\n"; return fail_code; }
    if (!input_budget(backend, true) || !input_budget(backend, false)) { std::cerr << "input_budget(" << label << ") failed\n"; return fail_code; }
    for (int m = 0; m < 4; ++m)
        if (!abandon_paused(backend, m)) { std::cerr << "abandon_paused(" << label << "," << m << ") failed\n"; return fail_code; }
    return 0;
}

int main() {
    for (int i = 0; i < 5; ++i) {
        if (auto rc = run_backend(io::epoll, "io::epoll", 1)) return rc;
#if BOOST_COROSIO_HAVE_LIBURING
        if (auto rc = run_backend(io::uring, "io::uring", 2)) return rc;
#endif
    }
    std::cout << "HTTP/2 TLS output and input budgets, cancellation and deadlines passed\n";
}
