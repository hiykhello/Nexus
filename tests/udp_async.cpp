#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/udp_socket.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
import std;
import nexus.udp;

namespace capy = boost::capy;
namespace io = boost::corosio;
namespace u = nexus::udp;
namespace p = nexus::packet;
using namespace std::chrono_literals;

struct Fixture {
    io::io_context context;
    io::udp_socket sender{context}, receiver{context};
    io::endpoint source;
    std::array<char, 16> received{};
    std::array<char, 16> returned{};
    io::endpoint reply_source;
    std::string payload = "ping";
    u::Bridge4 bridge{u::Mapping::endpoint_independent, u::Filtering::address_port_dependent, {1, 1, 100}};
    u::OutboundDatagram outgoing{};
    u::FlowId flow = 0;
    u::Endpoint4 remote{{127, 0, 0, 1}, 0};
    bool sent = false, got = false, canceled = false, pre_done = false;
    std::error_code pre_error;
    std::size_t pre_size = 0;
    bool pre_rolled_back = false;
    std::error_code send_error, recv_error, cancel_error;
    std::size_t send_size = 0, recv_size = 0;
    std::error_code reply_send_error, reply_recv_error;
    std::size_t reply_send_size = 0, reply_recv_size = 0;
    bool reply_sent = false, reply_received = false;
    bool late_done = false;
    std::error_code late_error;
    std::size_t late_size = 0;
    std::optional<u::Error> late_bridge_error;
    std::uint64_t late_time = 0;
    ~Fixture() {
        sender.close(); receiver.close();
        context.restart(); (void)context.run_for(1s);
        if (!context.stopped()) std::_Exit(1);
    }
};

auto send_packet(Fixture& f, std::uint64_t token) -> capy::task<> {
    auto [error, n] = co_await f.sender.send_to(capy::const_buffer(f.outgoing.payload.data(), f.outgoing.payload.size()), f.receiver.local_endpoint());
    f.send_error = error; f.send_size = n;
    auto result = f.bridge.complete(f.flow, token, !error && n == f.payload.size(), 2);
    f.sent = static_cast<bool>(result);
}
auto canceled_send(Fixture& f, std::uint64_t token) -> capy::task<> {
    auto [error, n] = co_await f.sender.send_to(capy::const_buffer(f.outgoing.payload.data(), f.outgoing.payload.size()), f.receiver.local_endpoint());
    f.pre_error = error; f.pre_size = n;
    auto result = f.bridge.complete(f.flow, token, !error && n == f.payload.size(), 1);
    f.pre_rolled_back = !result && result.error() == u::Error::send_failed;
    f.pre_done = true;
}
auto receive_packet(Fixture& f, bool cancel) -> capy::task<> {
    auto [error, n] = co_await f.receiver.recv_from(capy::mutable_buffer(f.received.data(), f.received.size()), f.source);
    if (cancel) { f.cancel_error = error; f.canceled = true; }
    else { f.recv_error = error; f.recv_size = n; f.got = true; }
}
auto send_reply(Fixture& f) -> capy::task<> {
    auto [error, n] = co_await f.receiver.send_to(capy::const_buffer(f.received.data(), f.recv_size), f.source);
    f.reply_send_error = error; f.reply_send_size = n; f.reply_sent = true;
}
auto receive_reply(Fixture& f) -> capy::task<> {
    auto [error, n] = co_await f.sender.recv_from(capy::mutable_buffer(f.returned.data(), f.returned.size()), f.reply_source);
    f.reply_recv_error = error; f.reply_recv_size = n; f.reply_received = true;
}
// The operation owns its bytes even if its flow is removed before completion.
auto late_send(Fixture& f, u::OutboundDatagram datagram) -> capy::task<> {
    auto [error, n] = co_await f.sender.send_to(capy::const_buffer(datagram.payload.data(), datagram.payload.size()),
                                               f.receiver.local_endpoint());
    f.late_error = error; f.late_size = n;
    auto complete = f.bridge.complete(datagram.flow, datagram.token, !error && n == datagram.payload.size(), f.late_time);
    if (!complete) f.late_bridge_error = complete.error();
    f.late_done = true;
}
auto late_completion(bool expire) -> bool {
    Fixture f;
    if (f.sender.open() || f.receiver.open() ||
        f.sender.bind(io::endpoint(io::ipv4_address::loopback(), 0)) ||
        f.receiver.bind(io::endpoint(io::ipv4_address::loopback(), 0))) return false;
    f.remote.port = f.receiver.local_endpoint().port();
    p::Bytes body{'l', 'a', 't', 'e'};
    auto packet = p::make_udp4({10, 0, 0, 2}, f.remote.address, 1234, f.remote.port, body);
    if (!packet) return false;
    auto old = f.bridge.prepare(*packet, 0);
    if (!old) return false;
    auto old_id = old->flow;
    auto executor = f.context.get_executor();
    capy::run_async(executor)(receive_packet(f, false));
    capy::run_async(executor)(late_send(f, std::move(*old)));
    f.late_time = expire ? 100 : 1;
    if (expire) {
        auto expired = f.bridge.expire(f.late_time);
        if (!expired || *expired != 1) return false;
    } else if (!f.bridge.close(old_id, f.late_time)) return false;
    auto replacement = f.bridge.prepare(*packet, f.late_time);
    if (!replacement || replacement->flow == old_id) return false;
    f.context.restart(); (void)f.context.run_for(2s);
    if (!f.late_done || f.late_error || f.late_size != body.size() ||
        f.late_bridge_error != u::Error::stale_send || !f.got || f.recv_error ||
        f.recv_size != body.size() || std::string_view(f.received.data(), f.recv_size) != "late") return false;
    if (f.bridge.reply(replacement->flow, f.remote, body, f.late_time)) return false;
    return f.bridge.complete(replacement->flow, replacement->token, true, f.late_time).has_value() &&
           f.bridge.reply(replacement->flow, f.remote, body, f.late_time).has_value();
}
struct ShutdownFixture {
    io::io_context context;
    io::udp_socket socket{context};
    u::Bridge4 bridge{u::Mapping::endpoint_independent, u::Filtering::address_port_dependent, {1, 1, 100}, 1500,
        {this, [](void* context, u::FlowId) noexcept { static_cast<ShutdownFixture*>(context)->socket.close(); }}};
    io::endpoint source;
    std::array<char, 16> buffer{};
    std::error_code error;
    bool done = false;
    ~ShutdownFixture() {
        socket.close();
        context.restart(); (void)context.run_for(1s);
        if (!context.stopped()) std::_Exit(1);
    }
};
auto receive_on_shutdown(ShutdownFixture& f) -> capy::task<> {
    auto [error, n] = co_await f.socket.recv_from(capy::mutable_buffer(f.buffer.data(), f.buffer.size()), f.source);
    (void)n;
    f.error = error;
    f.done = true;
}
auto shutdown_pending_receive() -> bool {
    ShutdownFixture f;
    if (f.socket.open() || f.socket.bind(io::endpoint(io::ipv4_address::loopback(), 0))) return false;
    auto packet = p::make_udp4({10, 0, 0, 2}, {127, 0, 0, 1}, 1234, 53, p::Bytes{1});
    if (!packet) return false;
    auto pending = f.bridge.prepare(*packet, 0);
    if (!pending) return false;
    capy::run_async(f.context.get_executor())(receive_on_shutdown(f));
    f.context.restart(); (void)f.context.run_for(20ms);
    if (f.done) return false;
    auto cleared = f.bridge.clear(1);
    if (!cleared || *cleared != 1) return false;
    f.context.restart(); (void)f.context.run_for(1s);
    if (!f.done || f.error != capy::cond::canceled || !f.context.stopped()) return false;
    auto late = f.bridge.complete(pending->flow, pending->token, true, 1);
    return !late && late.error() == u::Error::stale_send;
}

int main() {
    Fixture f;
    if (f.sender.open() || f.receiver.open() ||
        f.sender.bind(io::endpoint(io::ipv4_address::loopback(), 0)) ||
        f.receiver.bind(io::endpoint(io::ipv4_address::loopback(), 0))) return 1;
    f.remote.port = f.receiver.local_endpoint().port();
    constexpr u::Endpoint4 client{{10, 0, 0, 2}, 1234};
    p::Bytes body(f.payload.begin(), f.payload.end());
    auto request = p::make_udp4(client.address, f.remote.address, client.port, f.remote.port, body);
    if (!request) return 1;
    auto pre = f.bridge.prepare(*request, 0);
    if (!pre || pre->remote != f.remote || pre->payload != body) return 1;
    f.outgoing = std::move(*pre);
    f.flow = f.outgoing.flow;
    std::stop_source stop;
    stop.request_stop();
    auto executor = f.context.get_executor();
    capy::run_async(executor, stop.get_token())(canceled_send(f, f.outgoing.token));
    f.context.restart(); (void)f.context.run_for(1s);
    if (!f.pre_done || f.pre_error != capy::cond::canceled || f.pre_size != 0 || !f.pre_rolled_back ||
        f.bridge.reply(f.flow, f.remote, body, 1)) return 1;
    auto retry = f.bridge.prepare(*request, 1);
    if (!retry || retry->flow != f.flow) return 1;
    f.outgoing = std::move(*retry);
    capy::run_async(executor)(receive_packet(f, false));
    capy::run_async(executor)(send_packet(f, f.outgoing.token));
    f.context.restart(); (void)f.context.run_for(2s);
    if (!f.sent || !f.got || f.send_error || f.recv_error || f.send_size != 4 || f.recv_size != 4 ||
        std::string_view(f.received.data(), 4) != "ping" || f.source.port() != f.sender.local_endpoint().port() ||
        f.outgoing.payload != body) return 1;
    f.context.restart();
    capy::run_async(executor)(receive_reply(f));
    capy::run_async(executor)(send_reply(f));
    (void)f.context.run_for(2s);
    if (!f.reply_sent || !f.reply_received || f.reply_send_error || f.reply_recv_error ||
        f.reply_send_size != body.size() || f.reply_recv_size != body.size() ||
        f.reply_source != f.receiver.local_endpoint()) return 1;
    auto reply_bytes = std::span(reinterpret_cast<std::uint8_t const*>(f.returned.data()), f.reply_recv_size);
    auto reply = f.bridge.reply(f.flow, f.remote, reply_bytes, 3);
    if (!reply) return 1;
    auto parsed = p::parse_udp4(*reply);
    if (!parsed || parsed->source != f.remote.address || parsed->destination != client.address ||
        parsed->source_port != f.remote.port || parsed->destination_port != client.port ||
        !std::ranges::equal(parsed->payload, body)) return 1;
    // The next receive must get the successful send, not an earlier canceled datagram.
    f.context.restart();
    capy::run_async(executor)(receive_packet(f, true));
    (void)f.context.run_for(20ms);
    if (f.canceled) return 1;
    f.receiver.cancel();
    f.context.restart(); (void)f.context.run_for(1s);
    if (!f.canceled || f.cancel_error != capy::cond::canceled) return 1;
    f.canceled = false; f.cancel_error.clear();
    auto pending = f.bridge.prepare(*request, 4);
    if (!pending) return 1;
    f.context.restart();
    capy::run_async(executor)(receive_packet(f, true));
    (void)f.context.run_for(20ms);
    if (f.canceled) return 1;
    f.receiver.close();
    f.context.restart(); (void)f.context.run_for(1s);
    if (!f.canceled || f.cancel_error != capy::cond::canceled || !f.context.stopped()) return 1;
    auto canceled_send = f.bridge.complete(f.flow, pending->token, false, 5);
    if (canceled_send || canceled_send.error() != u::Error::send_failed ||
        !f.bridge.reply(f.flow, f.remote, body, 6)) return 1;
    f.sender.close();
    if (!late_completion(false) || !late_completion(true) || !shutdown_pending_receive()) return 1;
    std::cout << "Corosio UDP bridge send, reply, pre-cancellation and receive cancellation passed\n";
}
