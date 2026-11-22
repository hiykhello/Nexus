import std;
import tls.server_credential;
import tls.certificate_verify;
static thread_local bool deny_allocation=false;
static thread_local bool track_allocation=false;
static thread_local std::size_t allocation_count=0, allocation_size=0;
static thread_local void* allocation_pointer=nullptr;
void* operator new(std::size_t size) {
    if (deny_allocation) throw std::bad_alloc{};
    if (auto p=std::malloc(size ? size : 1)) {
        if (track_allocation) { ++allocation_count; allocation_size=size; allocation_pointer=p; }
        return p;
    }
    throw std::bad_alloc{};
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p,std::size_t) noexcept { std::free(p); }
namespace t=tls; namespace c = ::crypto;
auto read(char const* path) -> c::Bytes { std::ifstream f(path,std::ios::binary); return {std::istreambuf_iterator<char>(f),{}}; }
int main(int argc,char** argv) {
    if (argc==4 && std::string_view(argv[3])=="unsupported") {
        auto rejected=t::ServerCredential::create(read(argv[1]),read(argv[2]));
        return !rejected && rejected.error()==t::ServerCredentialError::unsupported_key ? 0 : 11;
    }
    if (argc!=6) return 1;
    auto cert=read(argv[1]), key=read(argv[2]), wrong=read(argv[3]);
    auto expected=static_cast<std::uint16_t>(std::strtoul(argv[4],nullptr,16));
    auto mismatch=t::ServerCredential::create(cert,wrong); if (mismatch || mismatch.error()!=t::ServerCredentialError::key_mismatch) return 2;
    auto bad=key; bad.push_back(0); if (t::ServerCredential::create(cert,bad).error()!=t::ServerCredentialError::invalid_private_key) return 3;
    auto credential=t::ServerCredential::create(cert,key); if (!credential || credential->scheme()!=expected) return 4;
    auto moved=std::move(*credential); if (credential->scheme() || credential->sign(c::Hash::sha256,c::Bytes(32)).error()!=t::ServerCredentialError::invalid_state) return 5;
    if (credential->clone().error()!=t::ServerCredentialError::invalid_state) return 14;
    // A clone owns its certificate bytes; a failed copy must leave the source
    // usable and a successful copy must not borrow its storage.
    bool allocation_failed=false;
    deny_allocation=true;
    try { (void)moved.clone(); } catch (std::bad_alloc const&) { allocation_failed=true; }
    deny_allocation=false;
    if (!allocation_failed || moved.scheme()!=expected || !std::ranges::equal(moved.certificate(),cert)) return 15;
    auto retained=moved.clone();
    if (!retained || retained->scheme()!=expected || retained->certificate().data()==moved.certificate().data() ||
        !std::ranges::equal(retained->certificate(),cert)) return 15;
    auto replacement=t::ServerCredential::create(cert,key); if (!replacement) return 12;
    *replacement=std::move(moved);
    if (moved.scheme() || replacement->scheme()!=expected || !std::ranges::equal(replacement->certificate(),cert)) return 13;
    moved=std::move(*replacement);
    for (auto hash:{c::Hash::sha256,c::Hash::sha384}) {
        c::Bytes digest(hash==c::Hash::sha256 ? 32 : 48,0x42);
        allocation_count=0; track_allocation=true; auto signature=moved.sign(hash,digest); track_allocation=false;
        if (!signature || allocation_count!=1 || allocation_pointer!=signature->data() || allocation_size<signature->size()) return 6;
        std::array<std::uint16_t,1> offered{expected};
        if (!t::verify_server_certificate_signature(cert,hash,digest,offered,*signature)) return 7;
        auto altered=*signature; altered.back()^=1;
        if (t::verify_server_certificate_signature(cert,hash,digest,offered,altered).error()!=t::CertificateVerifyError::invalid_signature) return 8;
        if (hash==c::Hash::sha256) {
            std::ofstream out(argv[5],std::ios::binary); out.write(reinterpret_cast<char const*>(signature->data()+8),signature->size()-8); if (!out) return 9;
        }
    }
    if (moved.sign(c::Hash::sha256,c::Bytes(31)).error()!=t::ServerCredentialError::invalid_transcript) return 10;
    // Both owners sign concurrently with separate contexts; the retained key also
    // survives replacement and destruction of the original owner.
    std::atomic_bool ok=true;
    auto sign=[&](t::ServerCredential const& owner) {
        for (int i=0;i<16;++i) {
            c::Bytes digest(32,0x42); auto signature=owner.sign(c::Hash::sha256,digest);
            std::array<std::uint16_t,1> offered{expected};
            if (!signature || !t::verify_server_certificate_signature(cert,c::Hash::sha256,digest,offered,*signature)) ok=false;
        }
    };
    std::thread first(sign,std::cref(moved)), second(sign,std::cref(*retained)); first.join(); second.join();
    if (!ok) return 16;
    { auto original=std::move(moved); }
    if (!std::ranges::equal(retained->certificate(),cert) || !retained->sign(c::Hash::sha256,c::Bytes(32))) return 17;
    std::cout << "server credential signing passed\n";
}
