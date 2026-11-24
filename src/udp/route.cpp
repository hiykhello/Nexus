module udp.route;
import rules;
import std;

namespace udp {
    auto RoutedBridge4::prepare_parsed(packet::Udp4View const& parsed, std::uint64_t now)
        -> std::expected<OutboundDatagram, RoutedError> {
        auto const& address = parsed.destination;
        if (!parsed.destination_port || std::ranges::all_of(address, [](auto b) { return b == 0; }))
            return std::unexpected(RoutedError{RouteError::invalid_target});
        if (!policy_.empty()) {
            auto text = std::format("{}.{}.{}.{}", address[0], address[1], address[2], address[3]);
            auto matched = policy_.match({.ip = text, .source_port = parsed.source_port, .source_ip_bytes = std::span(parsed.source)});
            if (!matched) return std::unexpected(RoutedError{RouteError::policy_error});
            if (matched->has_value()) return std::unexpected(RoutedError{RouteError::blocked});
        }
        auto result = bridge_.prepare_parsed(parsed, now);
        if (!result) return std::unexpected(RoutedError{result.error()});
        return std::move(*result);
    }
    auto RoutedBridge4::prepare(std::span<std::uint8_t const> input, std::uint64_t now)
        -> std::expected<OutboundDatagram, RoutedError> {
        auto parsed = packet::parse_udp4(input);
        if (!parsed) return std::unexpected(RoutedError{RouteError::invalid_packet});
        return prepare_parsed(*parsed, now);
    }
    auto RoutedBridge6::prepare_parsed(packet::Udp6View const& parsed, std::uint64_t now)
        -> std::expected<OutboundDatagram6, RoutedError> {
        auto const& a = parsed.destination;
        bool mapped = std::ranges::all_of(std::span(a).first<10>(), [](auto b) { return b == 0; }) &&
                      a[10] == 0xff && a[11] == 0xff;
        if (!parsed.destination_port || std::ranges::all_of(a, [](auto b) { return b == 0; }) ||
            (mapped && std::ranges::all_of(std::span(a).last<4>(), [](auto b) { return b == 0; })))
            return std::unexpected(RoutedError{RouteError::invalid_target});
        if (!policy_.empty()) {
            auto word = [&](std::size_t i) { return (static_cast<unsigned>(a[i]) << 8) | a[i + 1]; };
            auto text = std::format("{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                                    word(0), word(2), word(4), word(6), word(8), word(10), word(12), word(14));
            auto matched = policy_.match({.ip = text, .source_port = parsed.source_port, .source_ip_bytes = std::span(parsed.source)});
            if (!matched) return std::unexpected(RoutedError{RouteError::policy_error});
            if (matched->has_value()) return std::unexpected(RoutedError{RouteError::blocked});
            if (mapped) {
                auto ipv4 = std::format("{}.{}.{}.{}", a[12], a[13], a[14], a[15]);
                auto match4 = policy_.match({.ip = ipv4, .source_port = parsed.source_port, .source_ip_bytes = std::span(parsed.source)});
                if (!match4) return std::unexpected(RoutedError{RouteError::policy_error});
                if (match4->has_value()) return std::unexpected(RoutedError{RouteError::blocked});
            }
        }
        auto result = bridge_.prepare_parsed(parsed, now);
        if (!result) return std::unexpected(RoutedError{result.error()});
        return std::move(*result);
    }
    auto RoutedBridge6::prepare(std::span<std::uint8_t const> input, std::uint64_t now)
        -> std::expected<OutboundDatagram6, RoutedError> {
        auto parsed = packet::parse_udp6(input);
        if (!parsed) return std::unexpected(RoutedError{RouteError::invalid_packet});
        return prepare_parsed(*parsed, now);
    }
}
