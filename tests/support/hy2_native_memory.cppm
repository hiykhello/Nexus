export module nexus.test.hy2_native_memory;
import std;
import nexus.thirdparty.ngtcp2;
import nexus.thirdparty.nghttp3;
import nexus.test.quic_tls_link;

export namespace nexus::test::hy2_native_memory {
    enum class Kind {transport,http3};
    struct Fault {
        Kind kind=Kind::transport;
        std::size_t at=0,calls=0;
        bool denied=false;
        auto arm(Kind selected,std::size_t target) noexcept -> void {kind=selected;at=target;calls=0;denied=false;}
        auto hit(Kind selected) noexcept -> bool {if(!at || kind!=selected)return false;++calls;if(calls!=at)return false;denied=true;at=0;return true;}
    };
    inline Fault fault;
    inline bool cpp_denied=false;
    struct Oracle {std::size_t objects=0;bool valid=true;};
    inline Oracle oracle;
    struct Memory:quic_tls::Memory {
        Kind kind;
        explicit Memory(Kind kind=Kind::transport) noexcept:kind(kind){++oracle.objects;}
        Memory(Memory const&)=delete;
        ~Memory(){oracle.valid&=!used && allocations==frees;--oracle.objects;}
        static auto allocate(std::size_t bytes,void* owner) noexcept -> void* {
            auto& self=*static_cast<Memory*>(owner);if(fault.hit(self.kind))return nullptr;
            return quic_tls::Memory::allocate(bytes,static_cast<quic_tls::Memory*>(&self));
        }
        static auto release(void* pointer,void* owner) noexcept -> void {auto& self=*static_cast<Memory*>(owner);quic_tls::Memory::release(pointer,static_cast<quic_tls::Memory*>(&self));}
        static auto zero(std::size_t count,std::size_t size,void* owner) noexcept -> void* {
            if(size && count>std::numeric_limits<std::size_t>::max()/size)return nullptr;
            auto bytes=count*size;auto* out=allocate(bytes,owner);if(out)std::memset(out,0,bytes);return out;
        }
        static auto resize(void* pointer,std::size_t bytes,void* owner) noexcept -> void* {
            if(!pointer)return allocate(bytes,owner);if(!bytes){release(pointer,owner);return nullptr;}
            auto* out=allocate(bytes,owner);if(!out)return nullptr;auto old=(static_cast<quic_tls::Memory::Header*>(pointer)-1)->bytes-sizeof(quic_tls::Memory::Header);
            std::memcpy(out,pointer,std::min(old,bytes));release(pointer,owner);return out;
        }
        auto transport() noexcept -> nex::ngtcp2::ngtcp2_mem {return {this,allocate,release,zero,resize};}
        auto http3() noexcept -> nex::nghttp3::nghttp3_mem {return {this,allocate,release,zero,resize};}
    };
}
