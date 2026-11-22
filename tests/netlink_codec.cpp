import std;
import platform.netlink_abi;
import platform.netlink_codec;
namespace n = ::platform::netlink;
namespace a = ::platform::netlink_abi;
namespace {
    auto check(bool condition, std::source_location source = std::source_location::current()) -> void {
        if (!condition) {
            std::println("netlink codec failure line {}", source.line());
            throw 1;
        }
    }
    template <class T> auto bytes(T const &value) -> std::array<std::uint8_t, sizeof(T)> { return std::bit_cast<std::array<std::uint8_t, sizeof(T)>>(value); }
    auto message(std::uint16_t type, std::span<std::uint8_t const> payload, std::uint32_t sequence = 7, std::uint16_t flags = 0) -> std::vector<std::uint8_t> {
        std::vector<std::uint8_t> result(n::aligned(sizeof(a::nlmsghdr) + payload.size()));
        a::nlmsghdr header{static_cast<std::uint32_t>(sizeof(a::nlmsghdr) + payload.size()), type, flags, sequence, 123};
        std::memcpy(result.data(), &header, sizeof(header));
        std::ranges::copy(payload, result.begin() + sizeof(header));
        return result;
    }
    auto requests_and_attributes() -> void {
        n::Request request(a::RTM_NEWLINK, a::NLM_F_REQUEST | a::NLM_F_ACK, a::ifinfomsg{.ifi_index = 42});
        check(request.scalar(a::IFLA_MTU, std::uint32_t{1420}) && request.string(a::IFLA_IFALIAS, "lease-test"));
        request.stamp(7, 123);
        auto header = request.header();
        check(header.nlmsg_len == request.bytes().size() && header.nlmsg_seq == 7 && header.nlmsg_pid == 123);
        unsigned count = 0;
        auto parsed = n::attributes(request.bytes().subspan(sizeof(a::nlmsghdr) + sizeof(a::ifinfomsg)), [&](n::Attribute attribute) -> std::expected<void, n::Failure> {
            if (!count++) {
                auto value = n::native<std::uint32_t>(attribute.bytes);
                check(attribute.type == a::IFLA_MTU && value == 1420 && !attribute.flags);
            } else check(attribute.type == a::IFLA_IFALIAS && n::text(attribute, 32) == "lease-test");
            return {};
        });
        check(parsed.has_value() && count == 2);
        std::array<std::uint8_t, 1024> large{};
        check(!request.append(1, large) && !request.valid());
        for (unsigned length = 0; length < 4; ++length) {
            auto malformed = bytes(a::rtattr{static_cast<std::uint16_t>(length), 1});
            check(!n::attributes(malformed, [](auto) -> std::expected<void, n::Failure> { return {}; }));
        }
        auto oversized = bytes(a::rtattr{5, 1});
        check(!n::attributes(oversized, [](auto) -> std::expected<void, n::Failure> { return {}; }));
        std::array<std::uint8_t, 5> exact{5, 0, 1, 0, 42};
        count = 0;
        check(n::attributes(exact,
                            [&](auto attribute) -> std::expected<void, n::Failure> {
                                ++count;
                                check(attribute.bytes.size() == 1 && attribute.bytes[0] == 42);
                                return {};
                            })
                  .has_value() &&
              count == 1);
        std::array<std::uint8_t, 4> no_terminator{'t', 'e', 's', 't'}, internal_zero{'a', 0, 'b', 0};
        check(!n::text({1, 0, no_terminator}, 4) && !n::text({1, 0, internal_zero}, 4) && !n::text({1, 1, internal_zero}, 4));
        std::array<std::uint8_t, 9> unaligned{};
        std::uint32_t value = 0x01020304;
        std::memcpy(unaligned.data() + 1, &value, 4);
        check(n::native<std::uint32_t>(std::span(unaligned).subspan(1)) == value && !n::native<std::uint64_t>(unaligned, 2));
    }
    auto reply_validation() -> void {
        n::Request request(a::RTM_NEWADDR, a::NLM_F_REQUEST | a::NLM_F_ACK, a::ifaddrmsg{});
        request.stamp(7, 123);
        auto ack = message(a::NLMSG_ERROR, bytes(a::nlmsgerr{0, request.header()}));
        auto consume = [&](std::span<std::uint8_t const> wire, n::ReplyState &state) {
            return n::messages(wire, [&](n::Message view) { return state.receive(view, 123, [](n::Message) -> std::expected<void, n::Failure> { return {}; }); });
        };
        n::ReplyState state{request.header()};
        check(consume(ack, state).has_value() && state.done);
        for (unsigned fault = 0; fault < 8; ++fault) {
            auto damaged = ack;
            auto header = *n::native<a::nlmsghdr>(damaged);
            auto error = *n::native<a::nlmsgerr>(damaged, sizeof(header));
            if (!fault) header.nlmsg_seq = 8;
            if (fault == 1) header.nlmsg_pid = 0;
            if (fault == 2) header.nlmsg_len = 1;
            if (fault == 3) error.msg.nlmsg_type = a::RTM_NEWROUTE;
            if (fault == 4) error.msg.nlmsg_seq = 8;
            if (fault == 5) error.error = 1;
            if (fault == 6) error.error = std::numeric_limits<int>::min();
            if (fault == 7) header.nlmsg_flags = a::NLM_F_DUMP_INTR;
            std::memcpy(damaged.data(), &header, sizeof(header));
            std::memcpy(damaged.data() + sizeof(header), &error, sizeof(error));
            state = {request.header()};
            check(!consume(damaged, state) && !state.done);
        }
        auto refused = message(a::NLMSG_ERROR, bytes(a::nlmsgerr{-std::to_underlying(std::errc::permission_denied), request.header()}));
        state = {request.header()};
        auto failure = consume(refused, state);
        check(!failure && failure.error().system == std::errc::permission_denied);
        for (unsigned length = 0; length < sizeof(a::nlmsghdr); ++length) {
            state = {request.header()};
            check(!consume(std::span(ack).first(length), state) || !state.done);
        }
        state = {request.header(), true};
        auto data = message(a::RTM_NEWADDR, bytes(a::ifaddrmsg{}), 7, a::NLM_F_MULTI);
        auto done = message(a::NLMSG_DONE, bytes(std::int32_t{0}), 7, a::NLM_F_MULTI);
        data.insert(data.end(), done.begin(), done.end());
        check(consume(data, state).has_value() && state.done && state.received == 2);
        state = {request.header(), true};
        check(!consume(message(a::NLMSG_DONE, {}), state));
        state = {request.header(), true};
        check(!consume(message(a::RTM_NEWADDR, bytes(a::ifaddrmsg{})), state));
        state = {request.header()};
        auto stale = message(a::NLMSG_ERROR, bytes(a::nlmsgerr{}), 6);
        check(consume(stale, state).has_value() && !state.done);
        auto fresh = ack;
        stale.insert(stale.end(), fresh.begin(), fresh.end());
        state = {request.header()};
        check(consume(stale, state).has_value() && state.done);
        auto duplicate = ack;
        duplicate.insert(duplicate.end(), ack.begin(), ack.end());
        state = {request.header()};
        check(!consume(duplicate, state));
    }
} // namespace
auto main() -> int {
    try {
        requests_and_attributes();
        reply_validation();
    } catch (int value) { return value; }
    std::println("netlink bounded native-endian requests, unaligned/attribute lengths, exact ACK identity, multipart/sequence/errors and limits passed");
}
