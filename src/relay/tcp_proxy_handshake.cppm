// Client handshake helpers for SOCKS5, SOCKS4/4a, and HTTP CONNECT outbounds.
module relay:tcp_proxy_handshake;
import std;
import capy;
import corosio;
import config;
import http.connect;
import http.header;
import socks5;
import utility;
import :types;

namespace relay::tcp_proxy_detail {
    template<class TlsProfile = std::monostate>
    struct BasicTcpProxyProfile {
        std::string host, username, password;
        std::uint16_t port;
        config::TcpProxyProtocol protocol;
        bool udp;
        std::optional<std::size_t> bootstrap;
        std::uint32_t timeout_ms;
        TcpSocketOptions options;
        std::optional<TlsProfile> tls_profile{};

        ~BasicTcpProxyProfile() { utility::secure_zero(password.data(), password.size()); }
    };

    template<class Stream>
    auto read_proxy_exact(Stream& stream, std::span<std::uint8_t> bytes, Clock::time_point deadline)
        -> capy::task<bool> {
        while (!bytes.empty()) {
            auto count = co_await stream.read(bytes, deadline);
            if (!count || !*count || *count > bytes.size()) co_return false;
            bytes = bytes.subspan(*count);
        }
        co_return true;
    }

    template<class Stream, class TlsProfile>
    auto socks5_command(Stream& stream, BasicTcpProxyProfile<TlsProfile> const& profile, corosio::endpoint target, bool udp,
        Clock::time_point deadline, std::string_view domain = {}) -> capy::task<std::optional<socks5::UdpPeer>> {
        auto method = static_cast<std::uint8_t>(profile.username.empty() ? 0 : 2);
        std::array<std::uint8_t, 3> greeting{5, 1, method};
        std::array<std::uint8_t, 257> response{};
        auto reply = std::span(response);
        if (!co_await stream.send(greeting, deadline)) co_return std::nullopt;
        if (!co_await read_proxy_exact(stream, reply.first(2), deadline) || response[0] != 5 || response[1] != method)
            co_return std::nullopt;

        if (method == 2) {
            std::array<std::uint8_t, 513> authentication;
            struct Wipe {
                std::span<std::uint8_t> bytes;
                ~Wipe() { utility::secure_zero(bytes.data(), bytes.size()); }
            } wipe{authentication};
            authentication[0] = 1;
            authentication[1] = static_cast<std::uint8_t>(profile.username.size());
            auto end = std::ranges::copy(profile.username, authentication.begin() + 2).out;
            *end++ = static_cast<std::uint8_t>(profile.password.size());
            end = std::ranges::copy(profile.password, end).out;
            if (!co_await stream.send(std::span(authentication.begin(), end), deadline)) co_return std::nullopt;
            if (!co_await read_proxy_exact(stream, reply.first(2), deadline) || response[0] != 1 || response[1] != 0)
                co_return std::nullopt;
        }

        auto address = target.address();
        std::array<std::uint8_t, 262> request{5, static_cast<std::uint8_t>(udp ? 3 : 1), 0,
            static_cast<std::uint8_t>(!domain.empty() ? 3 : address.is_v6() ? 4 : 1)};
        auto end = request.begin() + 4;
        if (!domain.empty()) {
            *end++ = static_cast<std::uint8_t>(domain.size());
            end = std::ranges::copy(domain, end).out;
        } else if (address.is_v6()) end = std::ranges::copy(address.to_v6().to_bytes(), end).out;
        else end = std::ranges::copy(address.to_v4().to_bytes(), end).out;
        *end++ = static_cast<std::uint8_t>(target.port() >> 8);
        *end++ = static_cast<std::uint8_t>(target.port());
        if (!co_await stream.send(std::span(request.begin(), end), deadline)) co_return std::nullopt;
        if (!co_await read_proxy_exact(stream, reply.first(4), deadline) ||
            response[0] != 5 || response[1] != 0 || response[2] != 0)
            co_return std::nullopt;
        socks5::UdpPeer peer;
        peer.address_type = response[3];
        std::size_t address_bytes;
        switch (peer.address_type) {
            case 1: address_bytes = 4; break;
            case 4: address_bytes = 16; break;
            case 3:
                if (udp) co_return std::nullopt;
                if (!co_await read_proxy_exact(stream, reply.first(1), deadline) || !response[0]) co_return std::nullopt;
                address_bytes = response[0]; break;
            default: co_return std::nullopt;
        }
        if (!co_await read_proxy_exact(stream, reply.first(address_bytes + 2), deadline)) co_return std::nullopt;
        if (udp) {
            std::copy_n(response.begin(), address_bytes, peer.address.begin());
            peer.port = static_cast<std::uint16_t>((unsigned(response[address_bytes]) << 8) | response[address_bytes + 1]);
            if (!peer.port) co_return std::nullopt;
        }
        co_return peer;
    }

    template<class Stream, class TlsProfile>
    auto socks4_command(Stream& stream, BasicTcpProxyProfile<TlsProfile> const& profile, corosio::endpoint target,
        Clock::time_point deadline, std::string_view domain = {}) -> capy::task<bool> {
        bool is_4a = profile.protocol == config::TcpProxyProtocol::socks4a && !domain.empty();
        if (!domain.empty() && !is_4a) co_return false;
        if (domain.empty() && !target.address().is_v4()) co_return false;
        if (domain.size() > 255 || profile.username.size() > 255) co_return false;
        std::vector<std::uint8_t> req;
        req.reserve(9 + profile.username.size() + (is_4a ? domain.size() + 1 : 0));
        req.push_back(4); req.push_back(1);
        req.push_back(static_cast<std::uint8_t>(target.port() >> 8));
        req.push_back(static_cast<std::uint8_t>(target.port()));
        if (is_4a) { req.insert(req.end(), {0, 0, 0, 1}); }
        else {
            auto b = target.address().to_v4().to_bytes();
            req.insert(req.end(), b.begin(), b.end());
        }
        req.insert(req.end(), profile.username.begin(), profile.username.end());
        req.push_back(0);
        if (is_4a) {
            req.insert(req.end(), domain.begin(), domain.end());
            req.push_back(0);
        }
        if (!co_await stream.send(req, deadline)) co_return false;
        std::array<std::uint8_t, 8> rep{};
        if (!co_await read_proxy_exact(stream, rep, deadline)) co_return false;
        co_return rep[0] == 0 && rep[1] == 0x5A;
    }

    inline auto append_basic_auth(std::string& wire, std::string_view username, std::string_view password) -> void {
        constexpr std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        auto size = username.size() + 1 + password.size();
        auto byte = [&](std::size_t index) -> unsigned char {
            if (index < username.size()) return static_cast<unsigned char>(username[index]);
            if (index == username.size()) return ':';
            if (index >= size) return 0;
            return static_cast<unsigned char>(password[index - username.size() - 1]);
        };
        for (std::size_t index = 0; index < size; index += 3) {
            auto value = (static_cast<unsigned>(byte(index)) << 16) |
                (static_cast<unsigned>(byte(index + 1)) << 8) | byte(index + 2);
            wire.push_back(alphabet[value >> 18]);
            wire.push_back(alphabet[(value >> 12) & 63]);
            wire.push_back(index + 1 < size ? alphabet[(value >> 6) & 63] : '=');
            wire.push_back(index + 2 < size ? alphabet[value & 63] : '=');
        }
    }

    inline auto connect_response_status(http::HeaderView const& response) -> std::optional<unsigned> {
        auto line = response.first;
        if ((!line.starts_with("HTTP/1.1 ") && !line.starts_with("HTTP/1.0 ")) ||
            line.size() < 13 || line[12] != ' ' || !http::valid_header_field_value(line.substr(13))) return {};
        unsigned status = 0;
        auto first = line.data() + 9;
        auto last = first + 3;
        auto [end, error] = std::from_chars(first, last, status);
        if (error != std::errc{} || end != last || status < 100 || status > 599) return {};
        http::HeaderFieldCursor fields(response.field_lines);
        for (;;) {
            auto field = fields.next();
            if (field.status == http::HeaderFieldStatus::end) return status;
            if (field.status == http::HeaderFieldStatus::malformed) return {};
        }
    }

    template<class Stream, class TlsProfile>
    auto http_connect(Stream& stream, BasicTcpProxyProfile<TlsProfile> const& profile, corosio::endpoint target,
        std::string& buffered, Clock::time_point deadline, std::string_view domain = {}) -> capy::task<bool> {
        {
            auto host = domain.empty() ? target.address().to_string() : std::string(domain);
            auto authority = domain.empty() && target.is_v6() ? "[" + host + "]:" + std::to_string(target.port()) :
                host + ":" + std::to_string(target.port());
            std::string request;
            request.reserve(1024);
            struct Wipe {
                std::string& bytes;
                ~Wipe() { utility::secure_zero(bytes.data(), bytes.size()); }
            } wipe{request};
            request = "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n";
            if (!profile.username.empty()) {
                request += "Proxy-Authorization: Basic ";
                append_basic_auth(request, profile.username, profile.password);
                request += "\r\n";
            }
            request += "\r\n";
            auto bytes = std::span(reinterpret_cast<std::uint8_t const*>(request.data()), request.size());
            if (!co_await stream.send(bytes, deadline)) co_return false;
        }

        std::size_t informational = 0;
        http::HeaderBoundary boundary;
        std::array<std::uint8_t, 4096> input;
        for (;;) {
            auto state = boundary.inspect(buffered);
            if (state == http::HeaderBoundaryStatus::too_large) co_return false;
            if (state == http::HeaderBoundaryStatus::incomplete) {
                auto size = co_await stream.read(input, deadline);
                if (!size || !*size || *size > input.size()) co_return false;
                buffered.append(reinterpret_cast<char const*>(input.data()), *size);
                continue;
            }
            auto header = http::inspect_header(buffered);
            if (header.status != http::HeaderStatus::complete) co_return false;
            auto status = connect_response_status(header);
            if (!status || *status == 101 || *status >= 300) co_return false;
            buffered.erase(0, header.consumed);
            if (*status >= 200) co_return true;
            if (++informational > 8) co_return false;
            boundary = {};
        }
    }
}
