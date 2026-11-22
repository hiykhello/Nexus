module tls.server_hello;
import std;
import crypto.ecdh;

namespace tls {
    namespace {
        constexpr std::array<std::uint8_t,32> retry_random{0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c};
        auto put16(std::vector<std::uint8_t>& b, std::size_t n) -> void { b.push_back(static_cast<std::uint8_t>(n>>8)); b.push_back(static_cast<std::uint8_t>(n)); }
    }
    auto ServerHello::parse(std::span<std::uint8_t const> body) -> std::expected<ServerHello,ServerHelloError> {
        if (body.size()<35) return std::unexpected(ServerHelloError::truncated);
        ServerHello out; out.legacy_version=read16(body,0); std::ranges::copy(body.subspan(2,32),out.random.begin());
        auto sid=std::size_t{body[34]}; if (sid>32) return std::unexpected(ServerHelloError::invalid_session_id);
        auto pos=std::size_t{35}; if (body.size()-pos<sid+5) return std::unexpected(ServerHelloError::truncated);
        out.session_id_echo.assign(body.begin()+static_cast<std::ptrdiff_t>(pos),body.begin()+static_cast<std::ptrdiff_t>(pos+sid)); pos+=sid;
        out.cipher_suite=read16(body,pos); pos+=2; out.compression_method=body[pos++]; auto size=std::size_t{read16(body,pos)}; pos+=2;
        if (size!=body.size()-pos) return std::unexpected(ServerHelloError::invalid_length);
        std::bitset<65536> seen;
        while (pos<body.size()) {
            if (body.size()-pos<4) return std::unexpected(ServerHelloError::invalid_extension);
            auto type=read16(body,pos); auto length=std::size_t{read16(body,pos+2)}; pos+=4;
            if (length>body.size()-pos) return std::unexpected(ServerHelloError::invalid_extension);
            if (seen.test(type)) return std::unexpected(ServerHelloError::duplicate_extension); seen.set(type);
            out.extensions.push_back({type,{body.begin()+static_cast<std::ptrdiff_t>(pos),body.begin()+static_cast<std::ptrdiff_t>(pos+length)}}); pos+=length;
        }
        return out;
    }
    auto ServerHello::encode() const -> std::expected<std::vector<std::uint8_t>,ServerHelloError> {
        if (session_id_echo.size()>32) return std::unexpected(ServerHelloError::invalid_session_id);
        std::size_t ext_size=0; std::bitset<65536> seen;
        for (auto const& e:extensions) {
            if (seen.test(e.type)) return std::unexpected(ServerHelloError::duplicate_extension); seen.set(e.type);
            if (e.data.size()>65531 || ext_size>65531-e.data.size()) return std::unexpected(ServerHelloError::invalid_length);
            ext_size+=4+e.data.size();
        }
        std::vector<std::uint8_t> out; out.reserve(40+session_id_echo.size()+ext_size);
        put16(out,legacy_version); out.insert(out.end(),random.begin(),random.end()); out.push_back(static_cast<std::uint8_t>(session_id_echo.size()));
        out.insert(out.end(),session_id_echo.begin(),session_id_echo.end()); put16(out,cipher_suite); out.push_back(compression_method); put16(out,ext_size);
        for (auto const& e:extensions) { put16(out,e.type); put16(out,e.data.size()); out.insert(out.end(),e.data.begin(),e.data.end()); }
        return out;
    }
    auto ServerHello::is_retry() const noexcept -> bool { return random==retry_random; }




}
