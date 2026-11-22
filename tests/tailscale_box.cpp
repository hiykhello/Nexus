import std;
import tailscale.box;
import crypto;
namespace b=tailscale::box;
namespace c = ::crypto;
using Bytes=std::vector<std::uint8_t>;
auto require(bool condition,std::string_view message) -> void { if (!condition) throw std::runtime_error(std::string(message)); }
auto sequence(unsigned start,std::size_t count) -> Bytes {
    Bytes value(count);for (std::size_t i=0;i<count;++i) value[i]=static_cast<std::uint8_t>(start+i);return value;
}
auto hex(std::span<std::uint8_t const> bytes) -> std::string {
    constexpr std::string_view digits="0123456789abcdef";std::string value;
    for (auto byte:bytes) {value.push_back(digits[byte>>4]);value.push_back(digits[byte&15]);}return value;
}
auto vectors() -> std::map<std::string,std::string> {
    std::map<std::string,std::string> result;
    auto secret=b::SharedKey::from_secretbox_key(sequence(0,32));require(bool(secret),"secretbox key");
    auto nonce=sequence(32,24);
    for (unsigned size:{0,1,15,16,17,31,32,33,63,64,65,127,128,129,1024,1048576}) {
        auto plain=sequence(64,size);Bytes sealed(size+16),output(size);
        auto encoded=secret->seal_to(sealed,nonce,plain);require(encoded && *encoded==sealed.size(),"secretbox seal");
        auto decoded=secret->open_to(output,nonce,sealed);require(decoded && *decoded==size && output==plain,"secretbox open");
        if (size<=129) result[std::format("secretbox-{}",size)]=hex(sealed);
        else {
            auto digest=c::digest(c::Hash::sha256,sealed);require(bool(digest),"secretbox digest");
            result[std::format("secretbox-sha256-{}",size)]=hex(*digest);
        }
    }
    auto local=c::X25519Private::from_bytes(sequence(0,32)),remote=c::X25519Private::from_bytes(sequence(32,32));
    require(local && remote,"node private keys");
    auto ap=local->public_key(),bp=remote->public_key();require(ap && bp,"node public keys");
    result["local-public"]=hex(*ap);result["remote-public"]=hex(*bp);
    auto one=b::SharedKey::derive(*local,*bp),two=b::SharedKey::derive(*remote,*ap);require(one && two,"node box shared key");
    nonce=sequence(64,24);
    for (unsigned size:{0,1,31,32,33,64,65,1024,1048576}) {
        auto plain=sequence(128,size);Bytes sealed(size+16),output(size);
        auto encoded=one->seal_to(sealed,nonce,plain);require(encoded && *encoded==sealed.size(),"box seal");
        auto decoded=two->open_to(output,nonce,sealed);require(decoded && *decoded==size && output==plain,"box open");
        if (size<=65) result[std::format("box-{}",size)]=hex(sealed);
        else {
            auto digest=c::digest(c::Hash::sha256,sealed);require(bool(digest),"box digest");
            result[std::format("box-sha256-{}",size)]=hex(*digest);
        }
    }
    return result;
}
auto failures() -> void {
    auto secret=b::SharedKey::from_secretbox_key(sequence(0,32));auto nonce=sequence(32,24),plain=sequence(64,65);
    require(bool(secret),"test secret");
    Bytes sealed(plain.size()+16),output(plain.size(),0x7c);
    require(bool(secret->seal_to(sealed,nonce,plain)),"baseline seal");
    for (std::size_t index=0;index<sealed.size();++index) for (unsigned bit=0;bit<8;++bit) {
        auto damaged=sealed;damaged[index]^=static_cast<std::uint8_t>(1<<bit);
        auto before=output;auto opened=secret->open_to(output,nonce,damaged);
        require(!opened && opened.error()==b::Error::authentication && output==before,"tag/ciphertext exposed unauthenticated output");
    }
    for (std::size_t index=0;index<nonce.size();++index) for (unsigned bit=0;bit<8;++bit) {
        auto changed=nonce;changed[index]^=static_cast<std::uint8_t>(1<<bit);
        auto before=output;auto opened=secret->open_to(output,changed,sealed);
        require(!opened && opened.error()==b::Error::authentication && output==before,"nonce mismatch exposed output");
    }
    auto other=b::SharedKey::from_secretbox_key(sequence(1,32));auto before=output;
    require(other && !other->open_to(output,nonce,sealed) && output==before,"wrong shared key");
    Bytes short_output(plain.size()+15,0x7c);auto previous=short_output;
    require(secret->seal_to(short_output,nonce,plain).error()==b::Error::capacity && short_output==previous,"seal capacity writes");
    auto prefix=std::span(output).first(output.size()-1);
    require(secret->open_to(prefix,nonce,sealed).error()==b::Error::capacity && output==before,"open capacity writes");
    require(secret->seal_to(short_output,std::span(nonce).first(23),plain).error()==b::Error::invalid_nonce && short_output==previous,"nonce length");
    require(secret->open_to(output,nonce,std::span(sealed).first(15)).error()==b::Error::invalid_length && output==before,"short box");
    require(!b::SharedKey::from_secretbox_key(sequence(0,31)),"short key");
    Bytes overlap=sequence(0,128),snapshot=overlap;
    require(secret->seal_to(overlap,nonce,std::span(overlap).first(64)).error()==b::Error::overlap && overlap==snapshot,"seal overlap writes");
    require(secret->seal_to(std::span(overlap).subspan(16),nonce,std::span(overlap).first(64)).error()==b::Error::overlap && overlap==snapshot,"seal shifted overlap");
    require(secret->open_to(overlap,nonce,std::span(overlap).first(80)).error()==b::Error::overlap && overlap==snapshot,"open overlap writes");
    auto moved=std::move(*secret);
    require(!secret->valid() && moved.valid() && secret->seal_to(sealed,nonce,plain).error()==b::Error::invalid_key,"moved key reuse");
    *other=std::move(moved);require(other->valid() && !moved.valid(),"move assignment");
    other->clear();require(!other->valid() && other->open_to(output,nonce,sealed).error()==b::Error::invalid_key && output==before,"cleared key reuse");
    auto local=c::X25519Private::from_bytes(sequence(0,32));require(bool(local),"X25519 key");
    std::array<std::uint8_t,32> low{};
    require(b::SharedKey::derive(*local,low).error()==b::Error::peer,"low-order peer");
    require(b::SharedKey::derive(*local,std::span(low).first(31)).error()==b::Error::peer,"short peer");
    low[0]=1;require(b::SharedKey::derive(*local,low).error()==b::Error::peer,"low-order one");
}
auto bound() -> void {
    auto key=b::SharedKey::from_secretbox_key(sequence(0,32));auto nonce=sequence(32,24);require(bool(key),"limit key");
    auto plain=sequence(64,b::max_message_size+1);Bytes output(plain.size()+16,0x7c);
    auto before=output;
    require(key->seal_to(output,nonce,plain).error()==b::Error::invalid_length && output==before,"unbounded seal");
    Bytes decoded(plain.size(),0x7c);auto old=decoded;
    require(key->open_to(decoded,nonce,output).error()==b::Error::invalid_length && decoded==old,"unbounded open");
}
auto main(int argc,char** argv) -> int {
    try {
        auto expected=vectors();
        if (argc==2 && std::string_view(argv[1])=="--vectors") {
            std::cout<<'{';bool first=true;
            for (auto const& [name,value]:expected) {if (!first) std::cout<<',';first=false;std::cout<<'"'<<name<<"\":\""<<value<<'"';}
            std::cout<<"}\n";return 0;
        }
        failures();bound();
        std::println("NaCl box/secretbox sizes, two-party keys, verify-before-write, tampering, output bounds, overlap and moved/cleared keys passed");
        std::cout<<"sizeof(SharedKey)="<<sizeof(b::SharedKey)<<'\n';
    } catch (std::exception const& error) {std::cerr<<error.what()<<'\n';return 1;}
}

