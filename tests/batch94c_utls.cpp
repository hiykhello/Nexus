import std;
import crypto;
import tls.certificate_trust;
import tls.certificate_compression;
import tls.certificate_verify;
import tls.client_hello_exchange;
import tls.fingerprint;
import tls.psk_client_policy;
import tls.encrypted_extensions;
import tls.server_credential;
import tls.server_keys;
import utility.tls_fingerprint;

namespace {
    auto require(bool pass,std::string_view name) -> void {
        if (!pass) throw std::runtime_error(std::string(name));
    }

    auto hello(tls::Fingerprint profile,tls::HandshakeTransport transport,bool real_ech=false)
        -> tls::ClientHello {
        auto config=tls::make_profile_fingerprint_config(profile,0x001d,false,transport);
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
            "chrome","chrome-133","chrome-155","chrome-158","edge","edge-133","edge-155","edge-158",
            "firefox","firefox-135","firefox-148","firefox-161",
            "safari","safari-18","safari-26","safari-26.3",
            "ios","ios-18","ios-26.3","android","android-11","android-16"};
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
            if (chromium) expected.append_range(std::array<std::uint16_t,3>{0x44cd,0xca34,0xfe0d});
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
            tls::parse_fingerprint("chrome")==tls::parse_fingerprint("chrome-155") &&
            tls::parse_fingerprint("chrome")==tls::parse_fingerprint("chrome-158") &&
            tls::parse_fingerprint("edge")==tls::parse_fingerprint("edge-155") &&
            tls::parse_fingerprint("edge")==tls::parse_fingerprint("edge-158") &&
            tls::parse_fingerprint("firefox")==tls::parse_fingerprint("firefox-135") &&
            tls::parse_fingerprint("firefox")==tls::parse_fingerprint("firefox-148") &&
            tls::parse_fingerprint("firefox")==tls::parse_fingerprint("firefox-161") &&
            tls::parse_fingerprint("safari")==tls::parse_fingerprint("safari-18") &&
            tls::parse_fingerprint("safari")==tls::parse_fingerprint("safari-26.3") &&
            tls::parse_fingerprint("ios")==tls::parse_fingerprint("ios-26.3") &&
            tls::parse_fingerprint("android")==tls::parse_fingerprint("android-16"),"versioned aliases");
        require(tls::fingerprint_baseline(tls::Fingerprint::chrome)=="chrome-158" &&
            tls::fingerprint_baseline(tls::Fingerprint::edge)=="edge-158" &&
            tls::fingerprint_baseline(tls::Fingerprint::firefox)=="firefox-161" &&
            tls::fingerprint_baseline(tls::Fingerprint::safari)=="safari-26.3" &&
            tls::fingerprint_baseline(tls::Fingerprint::ios)=="ios-26.3" &&
            tls::fingerprint_baseline(tls::Fingerprint::android)=="android-16","baseline metadata");

        auto index_of=[](tls::ClientHello const& h,std::uint16_t type) -> std::size_t {
            for (std::size_t i=0;i<h.extensions.size();++i) if (h.extensions[i].type==type) return i;
            return h.extensions.size();
        };
        auto u16_list=[](std::span<std::uint8_t const> data) -> std::vector<std::uint16_t> {
            std::vector<std::uint16_t> out;
            for (std::size_t i=2;i+1<data.size();i+=2)
                out.push_back(static_cast<std::uint16_t>((std::uint16_t{data[i]}<<8)|data[i+1]));
            return out;
        };

        // Chrome 155: GREASE + ML-DSA-44/65/87 in signature_algorithms and TrustAnchors (0xca34).
        auto chrome_tcp=hello(tls::Fingerprint::chrome,tls::HandshakeTransport::tcp);
        auto chrome_sigs=u16_list(chrome_tcp.extension(13)->data);
        require(chrome_sigs.size()>=4 && tls::is_grease(chrome_sigs[0]) &&
            chrome_sigs[1]==0x0904 && chrome_sigs[2]==0x0905 && chrome_sigs[3]==0x0906,
            "Chrome 155 GREASE + ML-DSA sigalgs");
        auto* chrome_ta=chrome_tcp.extension(0xca34);
        require(chrome_ta && chrome_ta->data.size()==186 &&
            ((std::size_t{chrome_ta->data[0]}<<8)|chrome_ta->data[1])==184,"Chrome 155 TrustAnchors");

        // Firefox 148: P-521 group, ChaCha before AES-256-GCM, SCT before KeyShare, zlib/brotli/zstd cert comp.
        auto ff_tcp=hello(tls::Fingerprint::firefox,tls::HandshakeTransport::tcp);
        auto ff_groups=u16_list(ff_tcp.extension(10)->data);
        require(std::ranges::contains(ff_groups,std::uint16_t{25}),"Firefox 148 P-521 group");
        require(index_of(ff_tcp,18)<index_of(ff_tcp,51) && index_of(ff_tcp,28)<index_of(ff_tcp,0xfe0d),"Firefox 148 extension order");
        auto ff_chacha=std::ranges::find(ff_tcp.cipher_suites,std::uint16_t{0xcca9});
        auto ff_aes256=std::ranges::find(ff_tcp.cipher_suites,std::uint16_t{0xc02c});
        require(ff_chacha<ff_aes256,"Firefox 148 TLS 1.2 ChaCha order");
        if constexpr (tls::certificate_compression_enabled()) {
            auto* ff_cc=ff_tcp.extension(27);
            require(ff_cc && ff_cc->data==std::vector<std::uint8_t>{6,0,1,0,2,0,3},"Firefox 148 cert compression");
        }

        // Safari 26.3: AES-256-GCM first, P-521 group, Apple extension layout, zlib cert comp.
        auto saf_tcp=hello(tls::Fingerprint::safari,tls::HandshakeTransport::tcp);
        require(saf_tcp.cipher_suites.size()>=4 && tls::is_grease(saf_tcp.cipher_suites[0]) &&
            saf_tcp.cipher_suites[1]==0x1302 && saf_tcp.cipher_suites[2]==0x1303 && saf_tcp.cipher_suites[3]==0x1301,
            "Safari 26.3 TLS 1.3 cipher order");
        auto saf_groups=u16_list(saf_tcp.extension(10)->data);
        require(std::ranges::contains(saf_groups,std::uint16_t{25}),"Safari 26.3 P-521 group");
        require(index_of(saf_tcp,0)<index_of(saf_tcp,23) && index_of(saf_tcp,13)<index_of(saf_tcp,18) &&
            index_of(saf_tcp,18)<index_of(saf_tcp,51) && index_of(saf_tcp,51)<index_of(saf_tcp,43),"Safari 26.3 extension order");
        if constexpr (tls::certificate_compression_enabled()) {
            auto* saf_cc=saf_tcp.extension(27);
            require(saf_cc && saf_cc->data==std::vector<std::uint8_t>{2,0,1},"Safari 26.3 zlib cert compression");
        }

        // Single-source external subscription fingerprint normalization.
        require(utility::normalize_external_tls_fingerprint("chrome_120")=="chrome" &&
            utility::normalize_external_tls_fingerprint("Chrome-155")=="chrome" &&
            utility::normalize_external_tls_fingerprint("chrome_auto")=="chrome" &&
            utility::normalize_external_tls_fingerprint("chrome_131_psk")=="chrome" &&
            utility::normalize_external_tls_fingerprint("firefox_148")=="firefox" &&
            utility::normalize_external_tls_fingerprint("safari_26_3")=="safari" &&
            utility::normalize_external_tls_fingerprint("randomized")=="random" &&
            utility::normalize_external_tls_fingerprint("RANDOMIZED_ALPN")=="random" &&
            utility::normalize_external_tls_fingerprint("edge_106")=="edge" &&
            utility::normalize_external_tls_fingerprint("ios_14")=="ios" &&
            utility::normalize_external_tls_fingerprint("android_11_okhttp")=="android" &&
            utility::normalize_external_tls_fingerprint("qq").empty() &&
            utility::normalize_external_tls_fingerprint("360").empty(),"external fingerprint normalization");
    }

    auto alps() -> void {
        auto client=hello(tls::Fingerprint::chrome,tls::HandshakeTransport::tcp);
        constexpr std::uint16_t code=0x44cd;
        std::vector<std::uint8_t> extensions{8,0,0,15,0,13,
            static_cast<std::uint8_t>(code>>8),static_cast<std::uint8_t>(code),0,0,
            0,16,0,5,0,3,2,'h','2'};
        auto parsed=tls::validate_encrypted_extensions(client,extensions);
        require(parsed && parsed->application_settings_code==code,"ALPS 0x44cd before ALPN is valid");
        // Legacy pre-Chrome-133 ALPS codepoint 0x4469 is no longer offered or accepted.
        std::vector<std::uint8_t> legacy_ext=extensions;
        legacy_ext[6]=0x44; legacy_ext[7]=0x69;
        require(!tls::validate_encrypted_extensions(client,legacy_ext),"legacy ALPS 0x4469 rejected");
        extensions.back()='3';
        require(!tls::validate_encrypted_extensions(client,extensions),"ALPS rejects mismatched protocol");
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
    auto state_machine_extensions() -> void {
        // 1. Firefox 161 3-slot initial KeyShare (X25519MLKEM768 + X25519 + P-256).
        constexpr std::array<std::string_view,1> h2{"h2"};
        auto ff_cfg=tls::make_profile_fingerprint_config(tls::Fingerprint::firefox,0x11ec,false,tls::HandshakeTransport::tcp);
        auto ff_shape=tls::make_fingerprint_hello("localhost",h2,ff_cfg,tls::HandshakeTransport::tcp);
        require(ff_shape && ff_shape->group_count==3 &&
            ff_shape->groups[0]==0x11ec && ff_shape->groups[1]==29 && ff_shape->groups[2]==23,
            "Firefox 161 3 initial key_share groups");
        auto exchange=tls::ClientHelloExchange::create(std::move(ff_shape->hello),ff_shape->initial_groups(),tls::HandshakeTransport::tcp);
        require(exchange.has_value(),"ClientHelloExchange 3-slot create");
        auto wire=exchange->initial();
        require(exchange->initial_sent().has_value(),"ClientHelloExchange initial_sent");
        auto parsed_ff=tls::ClientHello::parse(wire.subspan(4));
        require(parsed_ff.has_value(),"parse 3-slot Firefox ClientHello");
        auto ks=tls::KeyShare::parse_client(parsed_ff->extension(51)->data);
        require(ks && ks->size()==3 && (*ks)[0].group==0x11ec && (*ks)[1].group==29 && (*ks)[2].group==23 &&
            (*ks)[0].key_exchange.size()==1216 && (*ks)[1].key_exchange.size()==32 && (*ks)[2].key_exchange.size()==65,
            "Firefox 161 3 real key shares on wire");
        std::array<std::uint16_t,2> schemes{0x0403,0x0804},ciphers{0x1301,0x1303};
        auto server=tls::server_handshake_secrets(wire,schemes,tls::PeerSignaturePolicy::require_offered,ciphers,tls::HandshakeTransport::tcp);
        require(server && exchange->receive(server->server_hello),"3-slot server handshake");
        auto flight=exchange->take_flight();
        require(flight.has_value(),"3-slot take_flight");

        // 2. ML-DSA-44 / ML-DSA-65 / ML-DSA-87 (0x0904 / 0x0905 / 0x0906) CertificateVerify sign & verify.
        std::array<std::uint8_t,32> transcript{};
        for (std::size_t i=0;i<transcript.size();++i) transcript[i]=static_cast<std::uint8_t>(i+1);
        constexpr std::array<std::uint16_t,3> mldsa_schemes{0x0904,0x0905,0x0906};
        for (auto scheme:mldsa_schemes) {
            auto cred=tls::ServerCredential::generate_mldsa(scheme);
            require(cred && cred->scheme()==scheme,"generate ML-DSA credential");
            auto sig_msg=cred->sign(crypto::Hash::sha256,transcript);
            require(sig_msg.has_value(),"ML-DSA CertificateVerify sign");
            auto ok=tls::verify_server_certificate_signature(cred->certificate(),crypto::Hash::sha256,transcript,mldsa_schemes,*sig_msg);
            require(ok.has_value(),"ML-DSA CertificateVerify verify");
            auto tampered=*sig_msg;
            tampered.back()^=0x01;
            require(!tls::verify_server_certificate_signature(cred->certificate(),crypto::Hash::sha256,transcript,mldsa_schemes,tampered),
                "ML-DSA tampered signature rejected");
        }

        // 3. TrustAnchors (0xca34) in EncryptedExtensions (valid, malformed, and unoffered).
        auto chrome_client=hello(tls::Fingerprint::chrome,tls::HandshakeTransport::tcp);
        // EncryptedExtensions with 0xca34 containing 1 ID: {0xd6, 0x79, 0x09, 0x01}.
        std::vector<std::uint8_t> ee_valid{8,0,0,13, 0,11, 0xca,0x34, 0,7, 0,5, 4, 0xd6,0x79,0x09,0x01};
        auto parsed_ee=tls::validate_encrypted_extensions(chrome_client,ee_valid);
        require(parsed_ee && parsed_ee->peer_trust_anchors.size()==1 &&
            parsed_ee->peer_trust_anchors[0]==std::vector<std::uint8_t>{0xd6,0x79,0x09,0x01},
            "TrustAnchors EncryptedExtensions valid");
        std::vector<std::uint8_t> ee_bad{8,0,0,9, 0,7, 0xca,0x34, 0,3, 0,1, 0};
        require(!tls::validate_encrypted_extensions(chrome_client,ee_bad),"TrustAnchors rejects empty ID");
        auto ff_client=hello(tls::Fingerprint::firefox,tls::HandshakeTransport::tcp);
        require(!tls::validate_encrypted_extensions(ff_client,ee_valid),"TrustAnchors rejects unoffered extension");
    }
}

auto main() -> int {
    profiles();
    alps();
    isolation();
    state_machine_extensions();
    std::println("ClientHello layouts, 3-slot KeyShare, ML-DSA-44/65/87, TrustAnchors, ECH, ALPS and TLS PSK bindings passed");
}
