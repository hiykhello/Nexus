export module quic.native_memory;
export import quic.transport_memory;
import std;
import nexus.thirdparty.nghttp3;

export namespace quic {
    template<class Heap = NativeHeap>
    struct NativeMemory : NativeTransportMemory<Heap> {
        using NativeTransportMemory<Heap>::NativeTransportMemory;
        auto http3() noexcept -> nex::nghttp3::nghttp3_mem {
            return {this, this->allocate, this->release, this->zero, this->resize};
        }
    };
}
