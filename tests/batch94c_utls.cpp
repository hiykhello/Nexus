import std;
import crypto;
import tls.certificate_trust;
import tls.fingerprint;
import tls.psk_client_policy;
import tls.encrypted_extensions;

namespace {
    auto require(bool pass,std::string_view name) -> void {
        if (!pass) throw std::runtime_error(std::string(name));
    }

    auto hello(tls::Fingerprint profile,tls::HandshakeTransport transport,bool real_ech=false,bool old_alps=false)
        -> tls::ClientHello {
        auto config=tls::make_profile_fingerprint_config(profile,0x001d,false,transport);
        config.legacy_alps=old_alps;
        constexpr std::array<std::string_view,1> h2{"h2"},h3{"h3"};
        std::array<std::uint8_t,3> parameters{0x04,0x01,0x20};
        auto quic=transport==tls::HandshakeTransport::quic;
        auto result=tls::make_fingerprint_hello("localhost",quic ? h3 : h2,config,transport,
            quic ? std::optional<std::span<std::uint8_t const>>(parameters) : std::nullopt,{},real_ech);
        require(result.has_value(),"create ClientHello");
        auto wire=result->hello.encode();
        require(wire.has_value(),"encode ClientHello");
        auto parsed=tls::ClientHello::parse(*wire);
        require(parsed.has_value(),"decode ClientHello");
        return std::move(*parsed);
    }

    auto grease(tls::ClientHello const& client) -> void {
        auto* extension=client.extension(0xfe0d);
        require(extension && extension->data.size()>=42,"GREASE ECH present");
        auto const& bytes=extension->data;
        constexpr std::array<std::uint8_t,5> prefix{0,0,1,0,1};
        require(std::ranges::equal(std::span(bytes).first(5),prefix) && bytes[6]==0 && bytes[7]==32,"ECH outer suite and enc");
        auto length=(std::size_t{bytes[40]}<<8)|bytes[41];
        constexpr std::array<std::size_t,4> lengths{128,160,192,224};
        require(std::ranges::contains(lengths,length) && length==bytes.size()-42,"GREASE ECH payload length");
    }

    auto hex_list(std::vector<std::uint16_t> const& values) -> std::string {
        std::string text;
        for (auto value:values) {
            if (!text.empty()) text+=',';
            text+=std::format("{:04x}",value);
        }
        return text;
    }

    auto short_sha256(std::string_view text) -> std::string {
        auto bytes=std::span(reinterpret_cast<std::uint8_t const*>(text.data()),text.size());
        auto digest=crypto::digest(crypto::Hash::sha256,bytes);
        require(digest.has_value(),"JA4 SHA-256");
        std::string result;
        for (auto byte:std::span(*digest).first(6)) result+=std::format("{:02x}",byte);
        return result;
    }

    auto ja4(tls::ClientHello const& client,bool quic) -> std::string {
        auto suites=client.cipher_suites;
        std::erase_if(suites,tls::is_grease);
        std::ranges::sort(suites);
        std::vector<std::uint16_t> types,signatures;
        std::size_t count=0;
        for (auto const& ext:client.extensions) {
            if (tls::is_grease(ext.type)) continue;
            ++count;
            if (ext.type!=0 && ext.type!=16) types.push_back(ext.type);
            if (ext.type==13) for (std::size_t i=2;i+1<ext.data.size();i+=2) {
                auto value=static_cast<std::uint16_t>((std::uint16_t{ext.data[i]}<<8)|ext.data[i+1]);
                if (!tls::is_grease(value)) signatures.push_back(value);
            }
        }
        std::ranges::sort(types);
        auto suite_hash=short_sha256(hex_list(suites));
        require(suite_hash==(quic ? "55b375c5d22e" : "f91f431d341e"),"JA4 cipher snapshot");
        return std::format("{}13d{:02}{:02}h{}_{}_{}",quic ? 'q' : 't',suites.size(),count,quic ? '3' : '2',
            suite_hash,short_sha256(hex_list(types)+"_"+hex_list(signatures)));
    }

    auto profiles() -> void {
        constexpr std::array names{
            "chrome","chrome-133","edge","firefox","firefox-135","safari","safari-18","ios","android"};
        constexpr std::array<std::uint16_t,6> legacy{0xc02b,0xc02f,0xc02c,0xc030,0xcca8,0xcca9};
        for (auto name:names) {
            auto preset=tls::parse_fingerprint(name);
            require(preset.has_value(),"parse browser name");
            auto tcp=hello(*preset,tls::HandshakeTransport::tcp);
            auto quic=hello(*preset,tls::HandshakeTransport::quic);
            for (std::uint16_t type:{5,18,11,23,35,0xff01}) require(tcp.extension(type)!=nullptr,"TCP extension");
            for (std::uint16_t type:{21,28,11,23,35,0xff01})
                require(!quic.extension(type),"QUIC omits TCP extensions");
            for (auto suite:legacy) require(std::ranges::contains(tcp.cipher_suites,suite),"TLS 1.2 AEAD");
            for (auto suite:quic.cipher_suites)
                require(tls::is_grease(suite) || (suite>=0x1301 && suite<=0x1303),"QUIC does not offer TLS 1.2");
            require(std::ranges::equal(std::span(tcp.extension(43)->data).last(4),std::array<std::uint8_t,4>{3,4,3,3}),"TLS 1.3 and 1.2 versions");
            auto const& versions=quic.extension(43)->data;
            if (tls::is_grease(quic.cipher_suites.front()))
                require(versions.size()==5 && versions.front()==4 && tls::is_grease((versions[1]<<8)|versions[2]) &&
                    versions[3]==3 && versions[4]==4,"QUIC GREASE and TLS 1.3 only");
            else
                require(versions==std::vector<std::uint8_t>{2,3,4},"QUIC TLS 1.3 only");
            require(quic.extension(0x39) && quic.session_id.empty(),"QUIC parameters");
            bool chromium=*preset==tls::Fingerprint::chrome || *preset==tls::Fingerprint::edge;
            bool firefox=*preset==tls::Fingerprint::firefox;
            std::vector<std::uint16_t> types;
            for (auto const& ext:tcp.extensions)
                if (!tls::is_grease(ext.type) && ext.type!=21 && ext.type!=27) types.push_back(ext.type);
            std::ranges::sort(types);
            std::vector<std::uint16_t> expected{0,5,10,11,13,16,18,23,35,43,45,51,0xff01};
            if (chromium) expected.append_range(std::array<std::uint16_t,2>{0x44cd,0xfe0d});
            if (firefox) expected.append_range(std::array<std::uint16_t,3>{28,34,0xfe0d});
            std::ranges::sort(expected);
            require(types==expected,"TCP extension snapshot");
            require(bool(tcp.extension(34))==firefox,"Firefox delegated credentials");
            require(bool(tcp.extension(0x44cd))==chromium && !quic.extension(0x44cd),"ALPS requires h2");
            if (chromium || firefox) {
                grease(tcp);
                grease(quic);
                require(!hello(*preset,tls::HandshakeTransport::quic,true).extension(0xfe0d),"real ECH suppresses GREASE");
            }
            std::println("{} TCP {} suites, {} extensions; QUIC {} suites, {} extensions",name,
                tcp.cipher_suites.size(),tcp.extensions.size(),quic.cipher_suites.size(),quic.extensions.size());
            std::println("  {} {}",ja4(tcp,false),ja4(quic,true));
        }
        require(tls::parse_fingerprint("chrome")==tls::parse_fingerprint("chrome-133") &&
            tls::parse_fingerprint("firefox")==tls::parse_fingerprint("firefox-135") &&
            tls::parse_fingerprint("safari")==tls::parse_fingerprint("safari-18"),"versioned aliases");
    }

    auto alps() -> void {
        for (bool old:{false,true}) {
            auto client=hello(tls::Fingerprint::chrome,tls::HandshakeTransport::tcp,false,old);
            auto code=old ? 0x4469 : 0x44cd;
            std::vector<std::uint8_t> extensions{8,0,0,15,0,13,
                static_cast<std::uint8_t>(code>>8),static_cast<std::uint8_t>(code),0,0,
                0,16,0,5,0,3,2,'h','2'};
            auto parsed=tls::validate_encrypted_extensions(client,extensions);
            require(parsed && parsed->application_settings_code==code,"ALPS before ALPN is valid");
            extensions.back()='3';
            require(!tls::validate_encrypted_extensions(client,extensions),"ALPS rejects mismatched protocol");
        }
    }

    auto isolation() -> void {
        std::array<std::uint8_t,1> a{1},b{2};
        std::array<std::span<std::uint8_t const>,1> anchors{a},other{b};
        constexpr std::array<std::uint8_t,2> h2{'h','2'},h3{'h','3'};
        constexpr std::array<std::uint8_t,9> name{'l','o','c','a','l','h','o','s','t'};
        auto client=hello(tls::Fingerprint::chrome,tls::HandshakeTransport::tcp);
        auto bind=[&](auto const& trust,auto const& alpn,auto const& endpoint) {
            return tls::make_ticket_binding(client,trust,tls::PeerNameKind::dns,name,alpn,endpoint).value();
        };
        auto original=bind(anchors,h2,a);
        require(original!=bind(other,h2,a) && original!=bind(anchors,h3,a) && original!=bind(anchors,h2,b),
            "anchor, ALPN and endpoint isolation");
        client=hello(tls::Fingerprint::firefox,tls::HandshakeTransport::tcp);
        auto sni=std::ranges::find(client.extensions,std::uint16_t{0},&tls::Extension::type);
        sni->data.back()='x';
        require(original!=bind(anchors,h2,a),"offered SNI isolation");
    }
}

auto main() -> int {
    profiles();
    alps();
    isolation();
    std::println("ClientHello layouts, ECH exclusivity, ALPS and TLS PSK bindings passed");
}
