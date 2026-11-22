import std;
import tls.client_auth;
namespace t=tls; namespace c = ::crypto;
using Bytes=std::vector<std::uint8_t>; using View=std::span<std::uint8_t const>;
auto read(std::string const& file) -> Bytes { std::ifstream f("tests/fixtures/tls-trust/"+file,std::ios::binary); return Bytes(std::istreambuf_iterator<char>(f),{}); }
auto dns(std::string_view s) -> View { return {reinterpret_cast<std::uint8_t const*>(s.data()),s.size()}; }
auto transcript() -> t::Transcript {
    auto x=t::Transcript::create(c::Hash::sha256);
    Bytes ch{1,0,0,0}, sh{2,0,0,0}, ee{8,0,0,2,0,0};
    if (!x || !x->append(ch) || !x->append(sh) || !x->append(ee)) std::abort();
    return std::move(*x);
}
auto auth() -> t::ClientAuth { return {c::Hash::sha256,transcript(),t::Secret(Bytes(32,0x11)),t::Secret(Bytes(32,0x22))}; }
int main() {
    auto cert=read("certificate.bin"), sig=read("signature.bin"), root=read("root.der");
    if (cert.empty() || sig.size()!=256 || root.empty()) return 1;
    Bytes cv{15,0,1,4,8,4,1,0}; cv.insert(cv.end(),sig.begin(),sig.end());
    std::array<View,1> anchors{root}; std::array<std::uint16_t,1> offered{0x0804}; constexpr auto when=1798761600;
    auto tr=transcript(); if (!tr.append(cert) || !tr.append(cv)) return 2;
    auto digest=tr.snapshot(); auto data=t::finished_verify_data(c::Hash::sha256,Bytes(32,0x22),*digest);
    if (!data) return 3;
    Bytes fin{20,0,0,32}; fin.insert(fin.end(),data->view().begin(),data->view().end());
    auto a=auth();
    if (a.certificate_verify(cv,offered) || a.client_finished()) return 4;
    if (!a.certificate(cert,anchors,t::PeerNameKind::dns,dns("server.example"),when) ||
        !a.certificate_verify(cv,offered) || !a.server_finished(fin)) return 5;
    if (!tr.append(fin)) return 6;
    auto client_hash=tr.snapshot(); auto client_data=t::finished_verify_data(c::Hash::sha256,Bytes(32,0x11),*client_hash);
    auto reply=a.client_finished(); if (!client_data || !reply || reply->size()!=36 ||
        !std::ranges::equal(View(*reply).subspan(4),client_data->view()) || a.client_finished()) return 6;
    auto b=auth(); if (b.certificate(cert,anchors,t::PeerNameKind::dns,dns("wrong.example"),when) ||
        b.certificate(cert,anchors,t::PeerNameKind::dns,dns("server.example"),when)) return 7;
    auto d=auth(); auto corrupt=cv; corrupt.back()^=1;
    if (!d.certificate(cert,anchors,t::PeerNameKind::dns,dns("server.example"),when) || d.certificate_verify(corrupt,offered) ||
        d.certificate_verify(cv,offered) || d.server_finished(fin)) return 8;
    auto e=auth(); auto badfin=fin; badfin.back()^=1;
    if (!e.certificate(cert,anchors,t::PeerNameKind::dns,dns("server.example"),when) || !e.certificate_verify(cv,offered) ||
        e.server_finished(badfin) || e.server_finished(fin) || e.client_finished()) return 9;
    auto f=auth(); auto badcert=cert; badcert[4]=1;
    if (f.certificate(badcert,anchors,t::PeerNameKind::dns,dns("server.example"),when) ||
        f.certificate(cert,anchors,t::PeerNameKind::dns,dns("server.example"),when)) return 10;
    auto g=auth(); if (!g.certificate(cert,anchors,t::PeerNameKind::dns,dns("server.example"),when) ||
        g.certificate_verify(cv,std::span<std::uint16_t const>{}) || g.server_finished(fin)) return 11;
    bool called=false;
    t::CertificateVerifier policy=[&](std::span<View const> chain) { called=true; return chain.size()==2 && !chain[0].empty(); };
    auto custom=auth();
    if (!custom.certificate(cert,policy) || !called || !custom.certificate_verify(cv,offered) || !custom.server_finished(fin) || !custom.client_finished()) return 15;
    auto corrupt_custom=auth();
    if (!corrupt_custom.certificate(cert,policy) || corrupt_custom.certificate_verify(corrupt,offered) || corrupt_custom.server_finished(fin)) return 16;
    t::CertificateVerifier deny=[](std::span<View const>) { return false; };
    auto denied=auth();
    if (denied.certificate(cert,deny) || denied.certificate(cert,policy) || denied.certificate_verify(cv,offered)) return 17;
    auto corrupt_finished=auth();
    if (!corrupt_finished.certificate(cert,policy) || !corrupt_finished.certificate_verify(cv,offered) || corrupt_finished.server_finished(badfin) || corrupt_finished.client_finished()) return 18;
    auto u24=[&](std::size_t p) { return (std::size_t{cert[p]}<<16)|(std::size_t{cert[p+1]}<<8)|cert[p+2]; };
    auto second=8+3+u24(8)+2;
    if (second>=cert.size()) return 12;
    Bytes many=cert;
    auto update_lengths=[&] {
        auto put=[&](std::size_t p,std::size_t value) { many[p]=value>>16; many[p+1]=value>>8; many[p+2]=value; };
        put(1,many.size()-4); put(5,many.size()-8);
    };
    for (int i=2;i<16;++i) many.insert(many.end(),cert.begin()+second,cert.end());
    update_lengths(); auto full=auth();
    if (!full.certificate(many,anchors,t::PeerNameKind::dns,dns("server.example"),when)) return 13;
    many.insert(many.end(),cert.begin()+second,cert.end()); update_lengths(); auto excess=auth();
    auto rejected=excess.certificate(many,anchors,t::PeerNameKind::dns,dns("server.example"),when);
    if (rejected || rejected.error()!=t::ClientAuthError::malformed_certificate) return 14;
    std::cout << "TLS client certificate authentication sequence passed\n";
}
