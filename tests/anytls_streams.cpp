import std;
import anytls.streams;

auto main() -> int {
    using namespace anytls;
    StreamTable table({.max_streams=2,.per_stream_bytes=4,.total_bytes=6});
    auto first=table.open(),second=table.open();
    if (!first || !second || *first!=1 || *second!=2 || table.open() || table.accept(1)) return 1;
    std::array<std::uint8_t,4> data{1,2,3,4},buffer{};
    if (table.push(1,data)!=PushResult::queued || table.push(1,data)!=PushResult::backpressure ||
        table.push(2,data)!=PushResult::backpressure || table.push(99,data)!=PushResult::discarded || table.buffered()!=4) return 2;
    auto partial=table.read(1,std::span(buffer).first(2));
    if (!partial || *partial!=2 || buffer[0]!=1 || buffer[1]!=2 || table.buffered()!=2 ||
        table.push(2,data)!=PushResult::queued || table.buffered()!=6) return 3;
    if (!table.finish(1) || table.writable(1) || table.push(1,data)!=PushResult::discarded || table.acknowledge(1)) return 4;
    auto pending=table.read(1,buffer),eof=table.read(1,buffer);
    if (!pending || *pending!=2 || buffer[0]!=3 || buffer[1]!=4 || !eof || *eof || table.buffered()!=4) return 5;
    if (!table.acknowledge(2) || !table.acknowledged(2) || !table.acknowledge(2,false) || table.acknowledged(2) ||
        table.writable(2) || table.read(2,buffer) || table.buffered()) return 6;
    if (!table.release(1) || !table.release(2) || table.release(2) || table.size()) return 7;
    auto next=table.open();
    if (!next || *next!=3 || table.accept(2) || table.push(*next,{})!=PushResult::discarded) return 8;
    if (table.push(*next,data)!=PushResult::queued) return 9;
    table.close();
    if (table.buffered() || table.read(*next,buffer) || table.writable(*next) || table.open()) return 10;
    if (!table.release(*next) || table.size()) return 11;
    StreamTable last;
    if (!last.accept(0xffffffffu) || !last.exhausted() || last.open() || !last.release(0xffffffffu) || last.open()) return 12;
    StreamTable frames({.per_stream_bytes=100,.total_bytes=100,.per_stream_frames=2,.total_frames=2});
    auto frame_id=frames.open();
    if (!frame_id || frames.push(*frame_id,std::span(data).first(1))!=PushResult::queued ||
        frames.push(*frame_id,std::span(data).first(1))!=PushResult::queued ||
        frames.push(*frame_id,std::span(data).first(1))!=PushResult::backpressure ||
        !frames.read(*frame_id,buffer) || frames.push(*frame_id,std::span(data).first(1))!=PushResult::queued) return 13;
    std::println("AnyTLS stream IDs, independent byte budgets, retained backpressure, FIN/rejection and exhaustion passed");
}
