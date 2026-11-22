import std;
import tls.certificate_trust;
namespace t = tls;
using Bytes = std::vector<std::uint8_t>;
using View = std::span<std::uint8_t const>;
static auto read(std::string const& name) -> Bytes {
    std::ifstream f("tests/fixtures/tls-trust/" + name + ".der", std::ios::binary);
    return Bytes(std::istreambuf_iterator<char>(f), {});
}
static auto dns(std::string_view s) -> View { return {reinterpret_cast<std::uint8_t const*>(s.data()), s.size()}; }
static auto pem_of(Bytes const& der) -> std::string {
    constexpr char alphabet[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out="-----BEGIN CERTIFICATE-----\n"; std::size_t columns=0;
    for (std::size_t i=0;i<der.size();i+=3) {
        auto remaining=der.size()-i; unsigned value=unsigned(der[i])<<16;
        if (remaining>1) value|=unsigned(der[i+1])<<8; if (remaining>2) value|=der[i+2];
        out+=alphabet[(value>>18)&63]; out+=alphabet[(value>>12)&63]; out+=remaining>1 ? alphabet[(value>>6)&63] : '='; out+=remaining>2 ? alphabet[value&63] : '=';
        columns+=4; if (columns==64) { out+='\n'; columns=0; }
    }
    if (columns) out+='\n'; return out+"-----END CERTIFICATE-----\n";
}
int main() {
    auto root=read("root"), intermediate=read("intermediate"), server=read("server"), client=read("client"), cn=read("cn");
    if (root.empty() || intermediate.empty() || server.empty() || client.empty() || cn.empty()) return 1;
    constexpr std::int64_t valid_time=1798761600;
    std::array<View,2> chain{server,intermediate}; std::array<View,1> anchors{root};
    auto verify=[&](auto c, auto a, auto kind, auto name, auto time) {
        return t::verify_server_certificate_chain(c,a,kind,name,time);
    };
    auto ok=[&](auto name) { return verify(chain,anchors,t::PeerNameKind::dns,dns(name),valid_time).has_value(); };
    if (!ok("server.example") || !ok("one.example.org") || ok("two.one.example.org") || ok("bad.example")) return 2;
    std::array<std::uint8_t,4> ip4{127,0,0,1}, wrong_ip{127,0,0,2};
    std::array<std::uint8_t,16> ip6{}; ip6[15]=1;
    if (!verify(chain,anchors,t::PeerNameKind::ip,ip4,valid_time) || !verify(chain,anchors,t::PeerNameKind::ip,ip6,valid_time) ||
        verify(chain,anchors,t::PeerNameKind::ip,wrong_ip,valid_time)) return 3;
    if (verify(chain,anchors,t::PeerNameKind::dns,dns("cn-only.example"),valid_time)) return 4;
    std::array<View,2> cn_chain{cn,intermediate}, client_chain{client,intermediate};
    if (verify(cn_chain,anchors,t::PeerNameKind::dns,dns("cn-only.example"),valid_time) ||
        verify(client_chain,anchors,t::PeerNameKind::dns,dns("server.example"),valid_time)) return 5;
    if (verify(chain,anchors,t::PeerNameKind::dns,dns("server.example"),0) ||
        verify(chain,anchors,t::PeerNameKind::dns,dns("server.example"),2000000000)) return 6;
    std::array<View,1> leaf_only{server}, wrong_anchor{cn};
    if (verify(leaf_only,anchors,t::PeerNameKind::dns,dns("server.example"),valid_time) ||
        verify(chain,wrong_anchor,t::PeerNameKind::dns,dns("server.example"),valid_time)) return 7;
    auto damaged=server; damaged.back()^=1; std::array<View,2> damaged_chain{damaged,intermediate};
    if (verify(damaged_chain,anchors,t::PeerNameKind::dns,dns("server.example"),valid_time)) return 8;
    auto trailing=server; trailing.push_back(0); std::array<View,2> invalid_chain{trailing,intermediate};
    auto invalid=verify(invalid_chain,anchors,t::PeerNameKind::dns,dns("server.example"),valid_time);
    if (invalid || invalid.error()!=t::CertificateTrustError::invalid_certificate) return 9;
    std::array<std::uint8_t,4> nul_name{'a',0,'b','c'};
    auto bad=verify(chain,anchors,t::PeerNameKind::dns,nul_name,valid_time);
    if (bad || bad.error()!=t::CertificateTrustError::invalid_input ||
        verify(chain,anchors,t::PeerNameKind::ip,std::span{ip4}.first(3),valid_time) ||
        verify(std::span<View const>{},anchors,t::PeerNameKind::dns,dns("server.example"),valid_time)) return 10;
    std::array<View, 16> full_chain{}; full_chain.fill(intermediate); full_chain[0]=server;
    if (!verify(full_chain,anchors,t::PeerNameKind::dns,dns("server.example"),valid_time)) return 22;
    std::array<View, 17> too_many{}; too_many.fill(intermediate);
    std::array<View, 1025> too_many_anchors{}; too_many_anchors.fill(root);
    Bytes too_large(1048577, 0); std::array<View,1> large_chain{too_large};
    if (verify(too_many,anchors,t::PeerNameKind::dns,dns("server.example"),valid_time).error()!=t::CertificateTrustError::invalid_input ||
        verify(chain,too_many_anchors,t::PeerNameKind::dns,dns("server.example"),valid_time).error()!=t::CertificateTrustError::invalid_input ||
        verify(large_chain,anchors,t::PeerNameKind::dns,dns("server.example"),valid_time).error()!=t::CertificateTrustError::invalid_input) return 11;
    auto pem=pem_of(root); auto bundle=t::parse_trust_bundle(pem);
    if (!bundle || bundle->size()!=1 || bundle->front()!=root) return 12;
    std::array<View,1> parsed_anchor{bundle->front()};
    if (!verify(chain,parsed_anchor,t::PeerNameKind::dns,dns("server.example"),valid_time)) return 13;
    if (t::parse_trust_bundle(pem+pem) || t::parse_trust_bundle(pem+"garbage") ||
        t::parse_trust_bundle(pem.substr(0,pem.size()-15)) || t::parse_trust_bundle(" \n") ||
        t::parse_trust_bundle("-----BEGIN CERTIFICATE-----\n!\n-----END CERTIFICATE-----\n") ||
        t::parse_trust_bundle(std::string(4194305,' '))) return 14;
    auto appended=root; appended.push_back(0);
    auto concatenated=root; concatenated.insert(concatenated.end(),server.begin(),server.end());
    if (t::parse_trust_bundle(pem_of(appended)) || t::parse_trust_bundle(pem_of(concatenated))) {
        std::cerr << "trust bundle accepted trailing DER data\n"; return 18;
    }
    if (t::load_trust_bundle("/dev/null") || t::load_trust_bundle(std::string_view{"bad\0path",8}) || t::load_trust_bundle("/this/path/does/not/exist")) return 15;
    auto system=t::load_trust_bundle("/etc/ssl/certs/ca-certificates.crt");
    if (std::filesystem::exists("/etc/ssl/certs/ca-certificates.crt")) {
        if (!system || system->empty() || system->size()>1024) { std::cerr << "system bundle failed: " << (system ? -1 : static_cast<int>(system.error())) << "\n"; return 16; }
        std::vector<View> many; many.push_back(root); for (auto const& cert:*system) many.emplace_back(cert);
        if (!verify(chain,many,t::PeerNameKind::dns,dns("server.example"),valid_time)) return 17;
        std::cout << "loaded " << system->size() << " system trust anchors\n";
    }
    std::cout << "TLS certificate trust, identity, purpose and time passed\n";
}
