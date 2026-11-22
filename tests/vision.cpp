// Assertions are the test's checks and some advance the protocol state.
// Keep them active when this test is compiled with a release profile.
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
import std;
import vision;
namespace v=vision;
int main() {
    v::UserId id{}; std::iota(id.begin(),id.end(),std::uint8_t{0});
    {
        unsigned calls=0;
        auto source=[&](std::span<std::uint8_t> bytes) { ++calls; bytes[0]=calls==1 ? 255 : 0; bytes[1]=calls==1 ? 255 : 123; return true; };
        auto sample=v::uniform_padding_random(500,source);
        assert(sample && *sample==123 && calls==2);
        assert(v::uniform_padding_random(0,source).error()==v::RandomError::invalid_bound);
        assert(v::uniform_padding_random(65537,source).error()==v::RandomError::invalid_bound);
        assert(v::uniform_padding_random(500,[](auto) { return false; }).error()==v::RandomError::source_failure);
        calls=0;
        auto bad=[&](std::span<std::uint8_t> bytes) { ++calls; bytes[0]=bytes[1]=255; return true; };
        assert(v::uniform_padding_random(500,bad).error()==v::RandomError::exhausted && calls==128);
        auto max=v::uniform_padding_random(65536,bad); assert(max && *max==65535);
    }
    assert(v::complete_application_records({}));
    std::vector<std::uint8_t> record{0x17,3,3,0,1,42};
    assert(v::complete_application_records(record));
    for (std::size_t i=1;i<record.size();++i) assert(!v::complete_application_records(std::span(record).first(i)));
    auto two_records=record; two_records.insert(two_records.end(),record.begin(),record.end());
    assert(v::complete_application_records(two_records)); two_records.back()=0;
    two_records[8]=2; assert(!v::complete_application_records(two_records));
    assert(!v::complete_application_records(std::array<std::uint8_t,5>{0x17,3,3,0,0}));
    std::vector<std::uint8_t> server(85); server[0]=0x16; server[1]=server[2]=3; server[4]=80; server[5]=2;
    server[43]=32; server[76]=0x13; server[77]=1;
    std::array<std::uint8_t,6> extension{0,0x2b,0,2,3,4}; std::ranges::copy(extension,server.begin()+79);
    v::TrafficFilter filter; filter.observe(server);
    assert(filter.is_tls() && filter.tls12_or_later() && filter.direct_eligible() && filter.cipher()==0x1301 && filter.remaining()==0);
    for (unsigned suite=0x1301;suite<=0x1305;++suite) {
        auto candidate=server; candidate[77]=static_cast<std::uint8_t>(suite);
        v::TrafficFilter split; split.observe(std::span(candidate).first(79)); split.observe(std::span(candidate).subspan(79));
        assert(split.is_tls() && split.tls12_or_later() && split.cipher()==suite && split.remaining()==0 && split.direct_eligible()==(suite!=0x1305));
    }
    auto invalid_server=server; invalid_server[43]=255;
    v::TrafficFilter malformed_filter; malformed_filter.observe(invalid_server);
    assert(malformed_filter.is_tls() && !malformed_filter.direct_eligible());
    v::TrafficFilter exhausted; std::array<std::uint8_t,1> ordinary{42};
    for (int i=0;i<8;++i) exhausted.observe(ordinary);
    exhausted.observe(server); assert(exhausted.remaining()==0 && !exhausted.is_tls());
    v::TrafficFilter client; client.observe(std::array<std::uint8_t,6>{0x16,3,1,0,1,1});
    assert(client.is_tls() && !client.tls12_or_later() && !client.direct_eligible() && client.remaining()==7);
    v::TrafficFilter empty_filter; empty_filter.observe({}); assert(empty_filter.remaining()==7);
    v::TrafficFilter split_extension; split_extension.observe(std::span(server).first(82)); split_extension.observe(std::span(server).subspan(82));
    assert(split_extension.is_tls() && !split_extension.direct_eligible() && split_extension.remaining()==0);
    {
        v::Sender sender(id); v::TrafficFilter traffic;
        assert(sender.random_bound(traffic,0,true)==500);
        assert(!sender.prepare(traffic,{},500,true));
        auto initial=sender.prepare(traffic,{},0,true);
        assert(initial && initial->padded && initial->wire.size()==921 && initial->command==v::Command::more && sender.status()==v::SendStatus::pending);
        assert(!sender.prepare(traffic,record,0) && sender.commit(true) && sender.status()==v::SendStatus::padding);
        traffic.observe(server);
        auto final=sender.prepare(traffic,record,0);
        assert(final && final->command==v::Command::direct && sender.status()==v::SendStatus::pending);
        v::Receiver receiver(id); std::array<std::uint8_t,32> decoded{};
        auto first_block=receiver.feed(initial->wire,decoded);
        assert(first_block.consumed==initial->wire.size() && !first_block.written && first_block.status==v::ReceiveStatus::padded);
        auto last_block=receiver.feed(final->wire,decoded);
        assert(last_block.consumed==final->wire.size() && last_block.written==record.size() && last_block.status==v::ReceiveStatus::direct &&
               std::ranges::equal(std::span(decoded).first(last_block.written),record));
        assert(sender.commit(true) && sender.status()==v::SendStatus::direct);
        auto raw=sender.prepare(traffic,record,0);
        assert(raw && !raw->padded && raw->wire==record && sender.commit(true) && sender.status()==v::SendStatus::direct);
    }
    {
        v::Sender sender(id); v::TrafficFilter traffic;
        std::array<std::uint8_t,1> data{42};
        for (int i=0;i<7;++i) traffic.observe(data);
        auto last=sender.prepare(traffic,data,255);
        assert(last && last->command==v::Command::end && last->wire.size()==16+5+1+255);
        assert(sender.status()==v::SendStatus::pending && sender.commit(true) && sender.status()==v::SendStatus::plain);
        auto plain=sender.prepare(traffic,data,0); assert(plain && !plain->padded && plain->wire==std::vector<std::uint8_t>{42});
        assert(sender.commit(false) && sender.status()==v::SendStatus::failed && !sender.prepare(traffic,data,0));
    }
    {
        v::Sender sender(id); v::TrafficFilter traffic; traffic.observe(server);
        auto bad=record; bad.pop_back(); auto block=sender.prepare(traffic,bad,0);
        assert(block && block->command==v::Command::more && sender.commit(true));
        std::vector<std::uint8_t> large(8172); assert(!sender.prepare(traffic,large,0));
        server[77]=5; v::TrafficFilter ccm; ccm.observe(server);
        auto final=sender.prepare(ccm,record,0); assert(final && final->command==v::Command::end && sender.commit(true) && sender.status()==v::SendStatus::plain);
        server[77]=1;
    }
    for (std::size_t size:{8171u,8192u}) {
        std::vector<std::uint8_t> data(size,0x55);
        data[0]=0x17; data[1]=3; data[2]=3; data[3]=static_cast<std::uint8_t>((size-5)>>8); data[4]=static_cast<std::uint8_t>(size-5);
        v::TrafficFilter traffic; traffic.observe(server); v::Sender sender(id);
        auto plan=sender.plan_large(traffic,data); assert((plan && plan->split==4096 && plan->random_bounds==std::array<std::size_t,2>{256,256}));
        assert(!sender.prepare_large(traffic,data,{256,0}));
        auto batch=sender.prepare_large(traffic,data,{0,0});
        assert(batch && batch->command==v::Command::direct && sender.status()==v::SendStatus::pending);
        v::Receiver receiver(id); std::vector<std::uint8_t> decoded(size);
        auto step=receiver.feed(batch->wire,decoded);
        assert(step.status==v::ReceiveStatus::direct && step.written==size && step.consumed==batch->wire.size() && decoded==data);
        assert(sender.commit(true) && sender.status()==v::SendStatus::direct);
    }
    {
        std::vector<std::uint8_t> data(8192,0x55); data[100]=0x17; data[101]=3; data[102]=3;
        v::TrafficFilter traffic; traffic.observe(server); v::Sender sender(id);
        auto plan=sender.plan_large(traffic,data); assert(plan && plan->split==100 && plan->random_bounds[0]==500);
        auto batch=sender.prepare_large(traffic,data,{0,0}); assert(batch && batch->command==v::Command::more);
        v::Receiver receiver(id); std::vector<std::uint8_t> decoded(data.size());
        auto result=receiver.feed(batch->wire,decoded);
        assert(result.status==v::ReceiveStatus::padded && result.written==data.size() && decoded==data && sender.commit(true));
    }
    {
        std::vector<std::uint8_t> data(8192,0x55); v::TrafficFilter traffic;
        std::array<std::uint8_t,1> ordinary{42}; for (int i=0;i<7;++i) traffic.observe(ordinary);
        v::Sender sender(id); auto plan=sender.plan_large(traffic,data);
        assert(plan && plan->random_bounds[0]==256 && plan->random_bounds[1]==0);
        auto batch=sender.prepare_large(traffic,data,{0,0}); assert(batch && batch->command==v::Command::end);
        v::Receiver receiver(id); std::vector<std::uint8_t> decoded(data.size());
        auto result=receiver.feed(batch->wire,decoded);
        assert(result.status==v::ReceiveStatus::plain && result.written==data.size() && decoded==data && sender.commit(true) && sender.status()==v::SendStatus::plain);
    }
    std::vector<std::uint8_t> vector{id.begin(),id.end()};
    std::array<std::uint8_t,20> blocks{0,0,5,0,0,'h','e','l','l','o',1,0,5,0,0,'w','o','r','l','d'};
    vector.insert(vector.end(),blocks.begin(),blocks.end());
    std::array<std::uint8_t,5> hello{'h','e','l','l','o'},world{'w','o','r','l','d'};
    auto a=v::encode_block(id,v::Command::more,hello,{}), b=v::encode_block({},v::Command::end,world,{});
    assert(a && b); a->insert(a->end(),b->begin(),b->end()); assert(*a==vector);
    for (std::size_t split=0;split<=vector.size();++split) {
        v::Decoder decoder(id); std::array<std::uint8_t,10> out{};
        auto one=decoder.feed(std::span(vector).first(split),out);
        auto two=decoder.feed(std::span(vector).subspan(split),std::span(out).subspan(one.written));
        assert(one.consumed==split && two.consumed==vector.size()-split);
        assert(one.written+two.written==10 && two.status==v::Status::end);
        assert(std::string_view(reinterpret_cast<char*>(out.data()),out.size())=="helloworld");
        assert(decoder.finish()==v::Status::end);
    }
    std::array<std::uint8_t,3> pad{1,2,3};
    auto direct=v::encode_block(id,v::Command::direct,hello,pad); assert(direct); direct->push_back(99);
    for (std::size_t split=0;split<direct->size();++split) {
        v::Decoder decoder(id); std::array<std::uint8_t,5> output{};
        auto first_part=decoder.feed(std::span(*direct).first(split),output);
        auto last_part=decoder.feed(std::span(*direct).subspan(split),std::span(output).subspan(first_part.written));
        assert(first_part.consumed==split && first_part.written+last_part.written==5);
        assert(first_part.consumed+last_part.consumed==direct->size()-1 && last_part.status==v::Status::direct && output==hello);
    }
    v::Decoder limited(id); std::array<std::uint8_t,5> out{};
    auto first=limited.feed(*direct,std::span(out).first(2));
    assert(first.written==2 && first.status==v::Status::reading);
    auto second=limited.feed(std::span(*direct).subspan(first.consumed),std::span(out).subspan(2));
    assert(second.written==3 && second.status==v::Status::direct && first.consumed+second.consumed==direct->size()-1 && out==hello);
    v::Decoder bad(id); auto invalid=vector; invalid[0]^=1;
    assert(bad.feed(invalid,out).status==v::Status::invalid);
    invalid=vector; invalid[16]=3; v::Decoder bad_command(id);
    assert(bad_command.feed(invalid,out).status==v::Status::invalid);
    for (std::size_t i=0;i<vector.size();++i) {
        v::Decoder partial(id); std::array<std::uint8_t,10> data{};
        auto step=partial.feed(std::span(vector).first(i),data);
        assert(step.status==v::Status::reading && partial.finish()==(i==a->size()-b->size() ? v::Status::end : v::Status::truncated));
    }
    auto empty=v::encode_block(id,v::Command::end,{},{}); assert(empty);
    v::Decoder zero(id); assert(zero.feed(*empty,{}).status==v::Status::end);
    std::vector<std::uint8_t> oversized(65536);
    assert(!v::encode_block(id,v::Command::more,oversized,{}));
    for (std::size_t split=0;split<=vector.size();++split) {
        v::PrefixDetector detector(id);
        auto one=detector.feed(std::span(vector).first(split));
        auto two=detector.feed(std::span(vector).subspan(split));
        assert(one.consumed+two.consumed==16 && detector.status()==v::PrefixStatus::padded);
        v::Decoder decoded(id); std::array<std::uint8_t,10> output{};
        auto prefix=decoded.feed(detector.buffered(),output);
        assert(prefix.consumed==16 && prefix.written==0 && detector.consume(prefix.consumed));
        auto suffix=decoded.feed(std::span(vector).subspan(16),output);
        assert(suffix.status==v::Status::end && suffix.written==10);
        assert(std::string_view(reinterpret_cast<char*>(output.data()),output.size())=="helloworld");
    }
    for (std::size_t mismatch=0;mismatch<id.size();++mismatch) {
        std::vector<std::uint8_t> plain(id.begin(),id.end()); plain[mismatch]^=0x80; plain.push_back(42);
        for (std::size_t split=0;split<=plain.size();++split) {
            v::PrefixDetector detector(id);
            auto first=detector.feed(std::span(plain).first(split));
            auto second=detector.feed(std::span(plain).subspan(split));
            auto consumed=first.consumed+second.consumed;
            assert(detector.status()==v::PrefixStatus::plain && consumed==mismatch+1);
            std::vector<std::uint8_t> delivered;
            while (!detector.buffered().empty()) {
                delivered.push_back(detector.buffered().front()); assert(detector.consume(1));
            }
            assert(!detector.consume(1));
            delivered.insert(delivered.end(),plain.begin()+consumed,plain.end());
            assert(delivered==plain && detector.feed(plain).consumed==0);
        }
    }
    for (std::size_t length=0;length<id.size();++length) {
        v::PrefixDetector detector(id);
        assert(detector.feed(std::span(id).first(length)).status==v::PrefixStatus::detecting);
        assert(!detector.consume(0) && detector.finish()==v::PrefixStatus::plain);
        assert(std::ranges::equal(detector.buffered(),std::span(id).first(length)));
    }
    auto end_wire=vector; end_wire.insert(end_wire.end(),{'!','?'});
    std::vector<std::uint8_t> end_expected{'h','e','l','l','o','w','o','r','l','d','!','?'};
    for (std::size_t chunk=1;chunk<=end_wire.size();++chunk) {
        v::Receiver receiver(id); std::vector<std::uint8_t> got; std::size_t pos=0;
        while (pos<end_wire.size()) {
            std::array<std::uint8_t,2> output{};
            auto step=receiver.feed(std::span(end_wire).subspan(pos,std::min(chunk,end_wire.size()-pos)),output);
            assert(step.consumed || step.written); pos+=step.consumed;
            got.insert(got.end(),output.begin(),output.begin()+step.written);
        }
        assert(got==end_expected && receiver.status()==v::ReceiveStatus::plain && receiver.finish()==v::ReceiveStatus::closed);
    }
    for (std::size_t chunk=1;chunk<=direct->size();++chunk) {
        v::Receiver receiver(id); std::vector<std::uint8_t> got; std::size_t pos=0;
        while (receiver.status()!=v::ReceiveStatus::direct) {
            std::array<std::uint8_t,2> output{};
            auto step=receiver.feed(std::span(*direct).subspan(pos,std::min(chunk,direct->size()-pos)),output);
            assert(step.consumed || step.written || step.status==v::ReceiveStatus::direct);
            pos+=step.consumed; got.insert(got.end(),output.begin(),output.begin()+step.written);
        }
        assert(pos==direct->size()-1 && got==std::vector<std::uint8_t>(hello.begin(),hello.end()));
    }
    for (std::size_t mismatch=0;mismatch<id.size();++mismatch) {
        std::vector<std::uint8_t> plain(id.begin(),id.end()); plain[mismatch]^=0x80; plain.push_back(42);
        for (std::size_t chunk=1;chunk<=plain.size();++chunk) {
            v::Receiver receiver(id); std::vector<std::uint8_t> got; std::size_t pos=0;
            while (pos<plain.size()) {
                std::array<std::uint8_t,1> output{};
                auto step=receiver.feed(std::span(plain).subspan(pos,std::min(chunk,plain.size()-pos)),output);
                assert(step.consumed || step.written); pos+=step.consumed;
                got.insert(got.end(),output.begin(),output.begin()+step.written);
            }
            while (got.size()<plain.size()) {
                std::array<std::uint8_t,1> output{}; auto step=receiver.feed({},output);
                assert(step.written); got.push_back(output[0]);
            }
            assert(got==plain && receiver.finish()==v::ReceiveStatus::closed);
        }
    }
    for (std::size_t length=0;length<id.size();++length) {
        v::Receiver receiver(id); std::array<std::uint8_t,16> output{};
        auto step=receiver.feed(std::span(id).first(length),output); assert(step.consumed==length && !step.written);
        assert(receiver.finish()==(length ? v::ReceiveStatus::plain : v::ReceiveStatus::closed));
        std::vector<std::uint8_t> got;
        while (receiver.status()==v::ReceiveStatus::plain) {
            auto part=receiver.feed({},std::span(output).first(1)); got.insert(got.end(),output.begin(),output.begin()+part.written);
        }
        assert(std::ranges::equal(got,std::span(id).first(length)) && receiver.status()==v::ReceiveStatus::closed);
    }
    // A clean transport EOF after a complete continuation block is valid.
    auto continuation=v::encode_block(id,v::Command::more,std::array<std::uint8_t,3>{4,5,6},std::array<std::uint8_t,2>{7,8}); assert(continuation);
    for (std::size_t length=16;length<continuation->size();++length) {
        v::Receiver partial(id); std::array<std::uint8_t,8> out{};
        (void)partial.feed(std::span(*continuation).first(length),out);
        assert(partial.finish()==v::ReceiveStatus::truncated);
    }
    v::Receiver complete(id); std::array<std::uint8_t,8> complete_out{};
    auto completed=complete.feed(*continuation,complete_out);
    assert(completed.written==3 && complete.finish()==v::ReceiveStatus::closed);
    v::Receiver truncated(id); std::array<std::uint8_t,16> scratch{};
    assert(truncated.feed(std::span(vector).first(17),scratch).status==v::ReceiveStatus::padded);
    assert(truncated.finish()==v::ReceiveStatus::truncated);
}
