module nexus.packet.mux;
import std;

namespace nexus::packet {
    auto MemorySwitch::step() -> std::expected<SwitchStep, DeviceError> {
        SwitchStep result;
        if (!input_) {
            auto received = external_.receive(Side::second);
            if (!received) return std::unexpected(received.error());
            if (*received) {
                result.input = true;
                auto& bytes = **received;
                bool tcp = bytes.size() >= 20 && (bytes[0] >> 4) == 4 && bytes[9] == 6;
                bool tcp6 = tcp6_ && bytes.size() >= 40 && (bytes[0] >> 4) == 6 && bytes[6] == 6;
                bool udp4 = bytes.size() >= 20 && (bytes[0] >> 4) == 4 && bytes[9] == 17;
                // IPv6 options are checked by the UDP parser after dispatch.
                bool udp6 = bytes.size() >= 40 && (bytes[0] >> 4) == 6 &&
                            (bytes[6] == 17 || bytes[6] == 0 || bytes[6] == 60);
                if (!tcp && !tcp6 && !udp4 && !udp6) result.rejected = SwitchReject::unsupported_packet;
                else { input_route_ = tcp ? 0 : tcp6 ? 2 : 1; input_ = std::move(bytes); }
            }
        }
        if (input_) {
            try {
                auto sent = (input_route_ == 0 ? tcp_ : input_route_ == 1 ? udp_ : *tcp6_).send(Side::first, *input_);
                if (sent) { input_.reset(); result.input_delivered = true; }
                else if (sent.error() == DeviceError::queue_full) result.input_backpressured = true;
                else { result.input_error = sent.error(); input_.reset(); }
            } catch (std::bad_alloc const&) { result.input_backpressured = true; }
        }
        if (!output_) {
            auto take = [&](MemoryLink& link) -> std::expected<bool, DeviceError> {
                auto received = link.receive(Side::first);
                if (!received) return std::unexpected(received.error());
                if (!*received) return false;
                output_ = std::move(**received); return true;
            };
            auto count = tcp6_ ? 3u : 2u;
            for (std::size_t i = 0; i < count; ++i) {
                auto route = (next_output_ + i) % count;
                auto received = take(route == 0 ? tcp_ : route == 1 ? udp_ : *tcp6_);
                if (!received) return std::unexpected(received.error());
                if (*received) { next_output_ = (route + 1) % count; break; }
            }
        }
        if (output_) {
            try {
                auto sent = external_.send(Side::second, *output_);
                if (sent) { output_.reset(); result.output_delivered = true; }
                else if (sent.error() == DeviceError::queue_full) result.output_backpressured = true;
                else { result.output_error = sent.error(); if (sent.error() == DeviceError::packet_too_large) output_.reset(); }
            } catch (std::bad_alloc const&) { result.output_backpressured = true; }
        }
        return result;
    }
}
