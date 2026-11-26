#pragma once
// Shared fixture and core backpressure/ownership cases for HTTP/2 TLS backpressure tests.
namespace h = http2;
namespace t = tls;
namespace c = ::crypto;
namespace io = ::corosio;
using namespace std::chrono_literals;

inline auto secret(int n) -> t::Secret { return t::Secret(c::Bytes(32, static_cast<std::uint8_t>(n))); }
inline auto layer(t::RecordDirection direction, int n, std::uint64_t limit = 1u << 24) -> t::RecordLayer {
    auto s = secret(n);
    auto key = t::expand_label(c::Hash::sha256, s.view(), "key", {}, 16);
    auto iv = t::expand_label(c::Hash::sha256, s.view(), "iv", {}, 12);
    if (!key || !iv) std::abort();
    auto result = t::RecordLayer::create(direction, c::Aead::aes_128_gcm, key->view(), iv->view(), limit);
    if (!result) std::abort();
    return std::move(*result);
}
inline auto records(t::ApplicationRole role = t::ApplicationRole::server) -> t::ApplicationRecords {
    return {layer(t::RecordDirection::send, 1), layer(t::RecordDirection::receive, 2), 16385, 16385,
            c::Hash::sha256, c::Aead::aes_128_gcm, 16, secret(1), secret(2), role};
}
inline auto headers(void*, std::int32_t, std::span<h::Header const>, bool, bool) noexcept -> bool { return true; }
inline auto data(void*, std::int32_t, std::span<std::byte const>) noexcept -> h::DataDisposition { return h::DataDisposition::accepted; }
inline auto end(void*, std::int32_t) noexcept -> bool { return true; }
inline void closed(void*, std::int32_t, std::uint32_t) noexcept {}
using Connection = h::TlsServerConnection<io::local_stream_socket>;

struct Fixture {
    io::io_context context;
    io::local_stream_socket socket{context}, peer{context};
    std::unique_ptr<h::ServerSession> session;
    std::optional<Connection> connection;
    bool done = false, duplicate = false;
    std::optional<h::TlsServerError> error;
    template<class Backend>
    explicit Fixture(Backend backend, bool bind = true, std::size_t budget = std::numeric_limits<std::size_t>::max()) : context(backend) {
        h::ServerLimits limits{8, 16, 4096, 1024, 4096}; limits.shared_memory_bytes = budget;
        auto created = h::ServerSession::create(limits, {nullptr, headers, data, end, closed});
        if (!created || io::connect_pair(socket, peer)) std::abort();
        session = std::move(*created);
        constexpr std::string_view preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        constexpr std::array<std::byte, 9> settings{std::byte{0}, std::byte{0}, std::byte{0}, std::byte{4}};
        constexpr std::array<std::byte, 15> request{
            std::byte{0}, std::byte{0}, std::byte{6}, std::byte{1}, std::byte{5}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1},
            std::byte{0x82}, std::byte{0x87}, std::byte{0x01}, std::byte{0x01}, std::byte{'x'}, std::byte{0x84}};
        if (!session->receive(std::as_bytes(std::span{preface})) || !session->receive(settings)) std::abort();
        std::array<std::byte, 4096> sink{};
        for (;;) { auto n = session->output(sink); if (!n) std::abort(); if (!*n) break; }
        std::array<std::byte, 512> body{};
        if (!session->receive(request) || !session->respond_body(1, 200, body) || session->response_memory_used() != body.size()) std::abort();
        if (bind) connection.emplace(socket, *session, records(), c::Bytes{});
    }
    ~Fixture() {
        if (connection) connection->cancel();
        socket.close(); peer.close(); context.restart();
        (void)context.run_for(1s);
        if (!context.stopped()) std::_Exit(90);
    }
};

inline auto step(Fixture& f, bool timeout) -> capy::task<> {
    auto deadline = timeout ? std::optional{std::chrono::steady_clock::now() + 100ms} : std::nullopt;
    auto result = co_await f.connection->step(deadline);
    if (!result) f.error = result.error();
    f.done = true;
}
inline auto duplicate(Fixture& f) -> capy::task<> {
    auto result = co_await f.connection->step();
    f.duplicate = !result && result.error() == h::TlsServerError::invalid_state;
}
struct PartialSocket {
    io::local_stream_socket& socket; io::local_stream_socket& peer;
    unsigned writes = 0; std::array<std::uint8_t, 5> observed{}; ssize_t observed_size = -1;
    auto read_some(capy::mutable_buffer buffer) { return socket.read_some(buffer); }
    auto write_some(capy::const_buffer buffer) {
        if (++writes == 1) return socket.write_some(capy::const_buffer(buffer.data(), std::min(buffer.size(), observed.size())));
        observed_size = ::recv(peer.native_handle(), observed.data(), observed.size(), MSG_PEEK | MSG_DONTWAIT);
        peer.close(); return socket.write_some(buffer);
    }
    void cancel() { socket.cancel(); }
};
struct ChargeSocket {
    io::local_stream_socket& socket; h::ServerSession& session;
    std::size_t size = 0, charge = 0;
    auto read_some(capy::mutable_buffer buffer) { return socket.read_some(buffer); }
    auto write_some(capy::const_buffer buffer) {
        size = buffer.size(); charge = session.output_memory_charge(); return socket.write_some(buffer);
    }
    void cancel() { socket.cancel(); }
};
struct ThrowSocket {
    io::local_stream_socket& socket; bool throw_read; bool enabled = true;
    auto read_some(capy::mutable_buffer buffer) { if (enabled && throw_read) throw std::bad_alloc{}; return socket.read_some(buffer); }
    auto write_some(capy::const_buffer buffer) { if (enabled && !throw_read) throw std::bad_alloc{}; return socket.write_some(buffer); }
    void cancel() { socket.cancel(); }
};
template<class Socket>
auto partial_step(h::TlsServerConnection<Socket>& connection, bool& done, std::optional<h::TlsServerError>& error) -> capy::task<> {
    auto result = co_await connection.step(); if (!result) error = result.error(); done = true;
}
inline auto read_step(Connection& connection, bool& done, std::optional<h::TlsServerError>& error) -> capy::task<> {
    auto result = co_await connection.step(); if (!result) error = result.error(); done = true;
}
inline auto progress_step(Connection& connection, bool& done, bool& progress) -> capy::task<> {
    auto result = co_await connection.step(); progress = result && *result == h::TlsServerStep::progress; done = true;
}

template<class Backend> auto partial_failure(Backend backend) -> bool {
    Fixture f(backend, false); PartialSocket socket{f.socket, f.peer};
    h::TlsServerConnection connection(socket, *f.session, records(), c::Bytes{});
    bool done = false; std::optional<h::TlsServerError> error;
    capy::run_async(f.context.get_executor())(partial_step(connection, done, error)); f.context.restart(); (void)f.context.run_for(1s);
    std::array<std::byte, 64> sink{}; auto output = f.session->output(sink);
    return f.context.stopped() && done && error == h::TlsServerError::tls && socket.writes == 2 &&
        f.session->output_memory_charge() == 0 && socket.observed_size == 5 && socket.observed[0] == 23 && socket.observed[1] == 3 && socket.observed[2] == 3 &&
        (socket.observed[3] != 0 || socket.observed[4] > 16) && !output && output.error().kind == h::ServerErrorKind::failed;
}
template<class Backend> auto sealing_charge(Backend backend) -> bool {
    Fixture f(backend, false); ChargeSocket socket{f.socket, *f.session};
    h::TlsServerConnection connection(socket, *f.session, records(), c::Bytes{});
    bool done = false; std::optional<h::TlsServerError> error;
    capy::run_async(f.context.get_executor())(partial_step(connection, done, error)); f.context.restart(); (void)f.context.run_for(1s);
    if (!f.context.stopped() || !done || error || socket.size <= 27) return false;
    auto plaintext = socket.size - 22;
    return socket.charge == std::max({3 * plaintext + 40, 2 * socket.size, std::size_t{55}}) + 128 && !f.session->output_memory_charge();
}
template<class Backend> auto allocation_failure(Backend backend, bool reading) -> bool {
    Fixture f(backend, false);
    if (reading) {
        std::array<std::byte, 4096> sink{};
        for (;;) { auto n = f.session->output(sink); if (!n) return false; if (!*n) break; }
    }
    ThrowSocket socket{f.socket, reading}; h::TlsServerConnection connection(socket, *f.session, records(), c::Bytes{});
    bool done = false; std::optional<h::TlsServerError> error;
    capy::run_async(f.context.get_executor())(partial_step(connection, done, error)); f.context.restart(); (void)f.context.run_for(1s);
    std::array<std::byte, 64> sink{}; auto output = f.session->output(sink);
    return f.context.stopped() && done && error == h::TlsServerError::allocation &&
        !f.session->input_memory_charge() && !f.session->output_memory_charge() &&
        !f.session->ciphertext_memory_charge() && !f.session->scratch_memory_charge() &&
        f.session->transport_memory_charge() == 4096 && !output && output.error().kind == h::ServerErrorKind::failed;
}
template<class Backend> auto output_budget(Backend backend) -> bool {
    Fixture reference(backend, false);
    auto baseline = reference.session->shared_memory_used();
    for (std::size_t extra = 0; extra < 4096; extra += 16) {
        Fixture f(backend, true, baseline + 32768);
        auto available = baseline + 32768 - f.session->shared_memory_used();
        if (16384 + extra >= available || !f.session->reserve_input(available - 16384 - extra)) return false;
        capy::run_async(f.context.get_executor())(step(f, false));
        f.context.restart(); (void)f.context.run_for(1s);
        if (!f.done || f.error != h::TlsServerError::budget_exceeded) continue;
        std::uint8_t byte{}; auto n = ::recv(f.peer.native_handle(), &byte, 1, MSG_DONTWAIT); auto read_error = errno;
        std::array<std::byte, 64> sink{}; auto result = f.session->output(sink);
        return f.context.stopped() && n < 0 && (read_error == EAGAIN || read_error == EWOULDBLOCK) &&
            f.session->output_memory_charge() == 0 && !result && result.error().kind == h::ServerErrorKind::failed;
    }
    return false;
}
template<class Backend> auto exercise(Backend backend, bool timeout) -> bool {
    Fixture f(backend); std::array<char, 4096> filler{};
    for (;;) {
        auto n = ::send(f.socket.native_handle(), filler.data(), filler.size(), MSG_DONTWAIT | MSG_NOSIGNAL);
        if (n > 0 || (n < 0 && errno == EINTR)) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        return false;
    }
    auto ex = f.context.get_executor(); capy::run_async(ex)(step(f, timeout));
    f.context.restart(); (void)f.context.run_for(20ms);
    if (f.done || f.session->response_memory_used() != 512 || f.session->output_memory_charge() < 54 || f.session->scratch_memory_charge() != 16384) return false;
    capy::run_async(ex)(duplicate(f)); f.context.restart(); (void)f.context.run_for(20ms);
    if (f.done || !f.duplicate) return false;
    if (!timeout) f.connection->cancel();
    f.context.restart(); (void)f.context.run_for(1s);
    if (!f.context.stopped() || !f.done || !f.error ||
        *f.error != (timeout ? h::TlsServerError::timeout : h::TlsServerError::tls)) return false;
    if (f.session->response_memory_used() != 512 || f.session->output_memory_charge() != 0 || f.session->scratch_memory_charge() != 0) return false;
    f.duplicate = false; capy::run_async(ex)(duplicate(f)); f.context.restart(); (void)f.context.run_for(1s);
    if (!f.context.stopped() || !f.duplicate) return false;
    auto reset = f.session->reset_stream(1, 8);
    std::array<std::byte, 4096> sink{};
    auto output = f.session->output(sink);
    return !reset && reset.error().kind == h::ServerErrorKind::failed &&
        !output && output.error().kind == h::ServerErrorKind::failed && f.session->response_memory_used() == 512;
}
template<class Backend> auto duplicate_owner(Backend backend) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context), b(context); if (io::connect_pair(a, b)) return false;
    auto session = h::ServerSession::create({8, 16, 4096, 1024, 4096}, {nullptr, headers, data, end, closed}); if (!session) return false;
    Connection owner(a, **session, records(), c::Bytes{});
    {
        Connection duplicate(a, **session, records(t::ApplicationRole::client), c::Bytes{}); bool done = false; std::optional<h::TlsServerError> error;
        capy::run_async(context.get_executor())(read_step(duplicate, done, error)); context.restart(); (void)context.run_for(1s);
        if (!context.stopped() || !done || error != h::TlsServerError::invalid_state) return false;
        duplicate.cancel();
    }
    bool done = false, progress = false; capy::run_async(context.get_executor())(progress_step(owner, done, progress));
    context.restart(); (void)context.run_for(1s);
    return context.stopped() && done && progress;
}
template<class Backend> auto drop_idle_driver(Backend backend) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context), b(context); if (io::connect_pair(a, b)) return false;
    auto session = h::ServerSession::create({8, 16, 4096, 1024, 4096}, {nullptr, headers, data, end, closed}); if (!session) return false;
    { Connection connection(a, **session, records(), c::Bytes{}); }
    std::array<std::byte, 64> sink{}; auto output = (**session).output(sink);
    return !output && output.error().kind == h::ServerErrorKind::failed && !(**session).input_memory_charge();
}
template<class Backend> auto oversized_unread(Backend backend) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context), b(context); if (io::connect_pair(a, b)) return false;
    auto session = h::ServerSession::create({8, 16, 4096, 1024, 4096}, {nullptr, headers, data, end, closed}); if (!session) return false;
    c::Bytes unread(4097, 42); unread.reserve(1u << 20);
    Connection connection(a, **session, records(), std::move(unread));
    std::array<std::byte, 64> sink{}; auto output = (**session).output(sink);
    bool done = false; std::optional<h::TlsServerError> error;
    capy::run_async(context.get_executor())(read_step(connection, done, error)); context.restart(); (void)context.run_for(1s);
    std::uint8_t byte{}; auto n = ::recv(b.native_handle(), &byte, 1, MSG_DONTWAIT);
    return unread.capacity() == 0 && !output && output.error().kind == h::ServerErrorKind::failed &&
        context.stopped() && done && error == h::TlsServerError::invalid_state && n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
}
template<class Backend> auto transport_budget(Backend backend, bool enough) -> bool {
    h::ServerEvents events{nullptr, headers, data, end, closed}; h::ServerLimits limits{8, 16, 4096, 1024, 4096};
    auto reference = h::ServerSession::create(limits, events); if (!reference) return false;
    auto baseline = (**reference).shared_memory_used(); reference->reset();
    limits.shared_memory_bytes = baseline + (enough ? 4096 : 4095);
    auto session = h::ServerSession::create(limits, events); if (!session) return false;
    io::io_context context(backend); io::local_stream_socket a(context), b(context); if (io::connect_pair(a, b)) return false;
    {
        Connection connection(a, **session, records(), c::Bytes{});
        if ((**session).transport_memory_charge() != (enough ? 4096u : 0u)) return false;
        if (!enough) {
            bool done = false; std::optional<h::TlsServerError> error;
            capy::run_async(context.get_executor())(read_step(connection, done, error)); context.restart(); (void)context.run_for(1s);
            std::uint8_t byte{}; auto n = ::recv(b.native_handle(), &byte, 1, MSG_DONTWAIT);
            if (!done || error != h::TlsServerError::invalid_state || n >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) return false;
        }
    }
    std::array<std::byte, 32> output{}; auto result = (**session).output(output);
    return !(**session).transport_memory_charge() && (**session).shared_memory_used() == baseline &&
        !result && result.error().kind == h::ServerErrorKind::failed;
}
template<class Backend> auto wrong_role(Backend backend) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context), b(context); if (io::connect_pair(a, b)) return false;
    auto session = h::ServerSession::create({8, 16, 4096, 1024, 4096}, {nullptr, headers, data, end, closed}); if (!session) return false;
    Connection connection(a, **session, records(t::ApplicationRole::client), c::Bytes{});
    bool done = false; std::optional<h::TlsServerError> error;
    capy::run_async(context.get_executor())(read_step(connection, done, error)); context.restart(); (void)context.run_for(1s);
    std::array<std::byte, 64> sink{}; auto output = (**session).output(sink);
    std::uint8_t byte{}; auto n = ::recv(b.native_handle(), &byte, 1, MSG_DONTWAIT);
    return context.stopped() && done && error == h::TlsServerError::invalid_state &&
        !output && output.error().kind == h::ServerErrorKind::failed && n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
}
template<class Backend> auto unready_records(Backend backend, int mode) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context), b(context); if (io::connect_pair(a, b)) return false;
    auto session = h::ServerSession::create({8, 16, 4096, 1024, 4096}, {nullptr, headers, data, end, closed}); if (!session) return false;
    auto state = records(); std::optional<t::ApplicationRecords> moved;
    if (mode >= 6) {
        auto send = layer(t::RecordDirection::send, 1, 2);
        if (!send.seal(t::ContentType::application_data, c::Bytes{1})) return false;
        if (mode == 7 && !send.seal(t::ContentType::application_data, c::Bytes{2})) return false;
        state = t::ApplicationRecords(std::move(send), layer(t::RecordDirection::receive, 2), 16385, 16385, t::ApplicationRole::server);
    } else if (mode == 5) state = t::ApplicationRecords(layer(t::RecordDirection::receive, 1), layer(t::RecordDirection::send, 2), 16385, 16385, t::ApplicationRole::server);
    else if (mode == 0) moved.emplace(std::move(state));
    else if (mode == 1) { if (!state.close_notify()) return false; }
    else {
        auto peer = layer(t::RecordDirection::send, 2);
        auto message = mode == 2 ? c::Bytes{1, 0} : mode == 3 ? c::Bytes{24, 0} : c::Bytes{24, 0, 0, 1, 1};
        auto wire = peer.seal(mode == 2 ? t::ContentType::alert : t::ContentType::handshake, message);
        if (!wire || !state.open_event(*wire)) return false;
    }
    Connection connection(a, **session, std::move(state), c::Bytes{});
    bool done = false; std::optional<h::TlsServerError> error;
    capy::run_async(context.get_executor())(read_step(connection, done, error)); context.restart(); (void)context.run_for(1s);
    std::array<std::byte, 64> sink{}; auto output = (**session).output(sink);
    std::uint8_t byte{}; auto n = ::recv(b.native_handle(), &byte, 1, MSG_DONTWAIT);
    return context.stopped() && done && error == h::TlsServerError::invalid_state &&
        !output && output.error().kind == h::ServerErrorKind::failed && n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
}
