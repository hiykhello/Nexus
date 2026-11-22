#pragma once

namespace tls {
    namespace {
        auto add_browser_extensions(ClientHello& hello,Fingerprint profile,std::span<std::string_view const> alpn,
            HandshakeTransport transport,bool real_ech,bool old_alps,bool allow_tls12,Random& random) -> bool {
            auto chromium=profile==Fingerprint::chrome || profile==Fingerprint::edge;
            auto firefox=profile==Fingerprint::firefox;
            hello.extensions.push_back({5,{1,0,0,0,0}});
            hello.extensions.push_back({18,{}});
            if (firefox) hello.extensions.push_back({34,{0,8,4,3,5,3,6,3,8,7}});
            if (transport==HandshakeTransport::tcp && chromium && std::ranges::contains(alpn,std::string_view("h2")))
                hello.extensions.push_back({static_cast<std::uint16_t>(old_alps ? 0x4469 : 0x44cd),{0,3,2,'h','2'}});
            if ((chromium || firefox) && !real_ech) {
                auto size=random.sample(4);
                if (!size) return false;
                auto payload=128u+32u*(*size);
                Extension ech{0xfe0d,{0,0,1,0,1,0,0,32}};
                ech.data.resize(42+payload);
                if (!crypto::random_bytes(std::span(ech.data).subspan(5,1)) ||
                    !crypto::random_bytes(std::span(ech.data).subspan(8,32)) ||
                    !crypto::random_bytes(std::span(ech.data).subspan(42))) return false;
                ech.data[40]=static_cast<std::uint8_t>(payload>>8);
                ech.data[41]=static_cast<std::uint8_t>(payload);
                hello.extensions.push_back(std::move(ech));
            }
            if (transport==HandshakeTransport::quic) return true;
            hello.extensions.push_back({11,{1,0}});
            hello.extensions.push_back({23,{}});
            hello.extensions.push_back({35,{}});
            hello.extensions.push_back({0xff01,{0}});
            if (!allow_tls12) return true;
            constexpr std::array<std::uint16_t,6> legacy{0xc02b,0xc02f,0xc02c,0xc030,0xcca9,0xcca8};
            hello.cipher_suites.append_range(legacy);
            for (auto& extension:hello.extensions)
                if (extension.type==43) extension.data={4,3,4,3,3};
            return true;
        }
    }
}
