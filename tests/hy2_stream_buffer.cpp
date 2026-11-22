import std;
import hysteria2.stream_buffer;
import containers.byte_ring;

auto main() -> int {
    using hysteria2::StreamBuffer;
    StreamBuffer<11> output;
    std::array<std::uint8_t,9> first{1,2,3,4,5,6,7,8,9};
    if (!output.append(first)) return 1;
    auto retained=output.view()[0].subspan(5,2);
    if (!output.accept(7) || output.available()!=2) return 1;
    auto pending=output.view(); if (pending[0].size()!=2 || pending[0][0]!=8) return 2;
    if (!output.acknowledge(0,5) || output.acknowledge(4,1) || output.available()!=7) return 3;
    std::array<std::uint8_t,6> second{10,11,12,13,14,15};
    if (!output.append(second) || output.append(second)) return 4;
    if (retained[0]!=6 || retained[1]!=7 || retained.data()+2!=output.view()[0].data()) return 13;
    pending=output.view(); if (pending[0].size()!=4 || pending[1].size()!=4) return 5;
    std::array<std::uint8_t,8> expected{8,9,10,11,12,13,14,15};
    std::vector<std::uint8_t> joined; joined.insert(joined.end(),pending[0].begin(),pending[0].end()); joined.insert(joined.end(),pending[1].begin(),pending[1].end());
    if (!std::ranges::equal(joined,expected) || !output.accept(8) || !output.acknowledge(5,10) || output.size()) return 6;
    StreamBuffer<11> input; if (!input.append(first)) return 7;
    std::array<std::uint8_t,6> pulled{}; if (input.pull(pulled)!=6 || !input.append(second)) return 8;
    std::array<std::uint8_t,9> all{}; if (input.pull(all)!=9) return 9;
    if (all!=std::array<std::uint8_t,9>{7,8,9,10,11,12,13,14,15}) return 10;
    // Every wrap keeps QUIC-retained prefix bytes unchanged until its ACK.
    StreamBuffer<13> ring; std::uint64_t offset=0;
    for (unsigned i=0;i<100000;++i) {
        std::array<std::uint8_t,10> bytes{}; for (std::size_t j=0;j<10;++j) bytes[j]=static_cast<std::uint8_t>(i+j);
        if (!ring.append(bytes) || !ring.accept(10) || ring.available()!=3 || ring.offset()!=offset+10) return 11;
        if (!ring.acknowledge(offset,10)) return 12; offset+=10;
    }
    containers::ByteRing<5> storage;
    static_assert(sizeof(storage)==5);
    std::array<std::uint8_t,5> input_bytes{1,2,3,4,5}, output_bytes{};
    storage.write(4,input_bytes);
    auto split=storage.view(4,input_bytes.size());
    if (split[0].size()!=1 || split[1].size()!=4 || split[0].data()!=split[1].data()+4) return 14;
    storage.read(4,output_bytes);
    if (output_bytes!=input_bytes) return 15;
    std::println("Hy2 stream buffers: retained ACK prefix, split ring wrap, backpressure, receive pull, 100000 wraps passed");
}
