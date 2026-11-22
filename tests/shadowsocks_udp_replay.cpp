import std;
import shadowsocks.udp_replay;
namespace s=shadowsocks;
using R=s::UdpReplayResult;

int main() {
    s::UdpReplayWindow window;
    if (window.check(0)!=R::fresh || window.check(0)!=R::fresh || window.commit(0)!=R::fresh ||
        window.commit(0)!=R::duplicate || window.commit(1023)!=R::fresh || window.check(0)!=R::duplicate ||
        window.commit(1024)!=R::fresh || window.check(0)!=R::too_old || window.commit(1)!=R::fresh ||
        window.commit(1)!=R::duplicate) return 1;
    // A forged high packet is checked but not committed, leaving lower IDs usable.
    if (window.check(1000000)!=R::fresh || window.commit(2)!=R::fresh || window.commit(2)!=R::duplicate) return 2;
    if (window.commit(5000)!=R::fresh || window.check(1024)!=R::too_old || window.commit(4999)!=R::fresh) return 3;
    auto max=std::numeric_limits<std::uint64_t>::max();
    if (window.commit(max)!=R::fresh || window.commit(max)!=R::duplicate || window.commit(max-1023)!=R::fresh ||
        window.check(max-1024)!=R::too_old || window.check(0)!=R::too_old) return 4;
    s::UdpReplayWindow restored;
    auto saved=window.snapshot();
    auto encoded=s::encode_udp_replay(saved);
    if (!encoded || (*encoded)[0]!=1 || (*encoded)[1]!=1 || (*encoded)[2]!=0xff ||
        (*encoded)[9]!=0xff || !s::decode_udp_replay(*encoded) || *s::decode_udp_replay(*encoded)!=saved ||
        s::decode_udp_replay(std::span{*encoded}.first(encoded->size()-1))) return 30;
    auto corrupt=*encoded; corrupt[0]=2;
    if (s::decode_udp_replay(corrupt)) return 31;
    corrupt=*encoded; corrupt[1]=2;
    if (s::decode_udp_replay(corrupt)) return 32;
    s::UdpReplaySnapshot sample{true,0x0102030405060708ULL,{}};
    sample.seen[0]=0x1122334455667789ULL;
    auto sample_bytes=s::encode_udp_replay(sample);
    constexpr std::array<std::uint8_t,18> prefix{1,1,1,2,3,4,5,6,7,8,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x89};
    if (!sample_bytes || !std::ranges::equal(std::span{*sample_bytes}.first(prefix.size()),prefix) ||
        s::decode_udp_replay(*sample_bytes)!=sample) return 36;
    if (!restored.restore(saved) || restored.snapshot()!=saved || restored.restore(saved) ||
        restored.check(max)!=R::duplicate || restored.check(max-1023)!=R::duplicate ||
        restored.check(max-1024)!=R::too_old || restored.commit(max-1)!=R::fresh ||
        restored.commit(max-1)!=R::duplicate) return 7;

    s::UdpReplayWindow empty;
    auto blank=empty.snapshot();
    if (!empty.restore(blank) || empty.snapshot()!=blank) return 8;
    auto invalid=blank; invalid.highest=1;
    if (s::encode_udp_replay(invalid)) return 33;
    auto encoded_blank=s::encode_udp_replay(blank);
    if (!encoded_blank || !s::decode_udp_replay(*encoded_blank) || *s::decode_udp_replay(*encoded_blank)!=blank) return 34;
    (*encoded_blank)[9]=1;
    if (s::decode_udp_replay(*encoded_blank)) return 35;
    if (empty.restore(invalid) || empty.snapshot()!=blank) return 9;
    invalid=blank; invalid.seen[0]=1;
    if (empty.restore(invalid) || empty.snapshot()!=blank) return 10;
    invalid={true,3,{}};
    if (empty.restore(invalid) || empty.snapshot()!=blank) return 11;
    invalid.seen[0]=1 | (std::uint64_t{1} << 4);
    if (empty.restore(invalid) || empty.snapshot()!=blank) return 12;
    invalid.seen[0]=1 | (std::uint64_t{1} << 3);
    if (!empty.restore(invalid) || empty.check(0)!=R::duplicate || empty.check(1)!=R::fresh) return 13;

    // A proposed state may be durably committed before the live window moves.
    s::UdpReplayWindow owner, foreign;
    auto proposal=owner.prepare(42);
    if (!proposal || owner.snapshot()!=blank || foreign.apply(*proposal)) return 16;
    s::UdpReplayWindow recovered;
    if (!recovered.restore(proposal->next_state()) || recovered.check(42)!=R::duplicate ||
        !owner.apply(*proposal) || owner.snapshot()!=recovered.snapshot() || owner.apply(*proposal)) return 17;
    auto duplicate=owner.prepare(42);
    if (duplicate || duplicate.error()!=R::duplicate) return 18;
    auto stale=owner.prepare(45);
    auto newer=owner.prepare(44);
    if (!stale || !newer || !owner.apply(*newer)) return 19;
    auto after_newer=owner.snapshot();
    if (owner.apply(*stale) || owner.snapshot()!=after_newer) return 20;
    if (owner.commit(2048)!=R::fresh) return 21;
    auto old=owner.prepare(42);
    if (old || old.error()!=R::too_old) return 22;
    auto jump=owner.prepare(max);
    if (!jump) return 23;
    auto persisted=jump->next_state();
    if (!owner.apply(*jump) || owner.snapshot()!=persisted || owner.check(max)!=R::duplicate) return 24;

    // Compare randomized reordering, duplicates and unauthenticated checks to
    // a simple reference set; only accepted packets may mutate either state.
    s::UdpReplayWindow actual;
    std::set<std::uint64_t> seen;
    std::optional<std::uint64_t> highest;
    std::mt19937_64 random(0x2022);
    auto reference=[&](std::uint64_t id) {
        if (!highest || id>*highest) return R::fresh;
        if (*highest-id>=s::UdpReplayWindow::width) return R::too_old;
        return seen.contains(id) ? R::duplicate : R::fresh;
    };
    for (std::size_t i=0;i<100000;++i) {
        auto base=highest.value_or(0);
        auto offset=random()%2500;
        auto id=(random()%4==0 || offset>base) ? base+offset : base-offset;
        auto expected=reference(id);
        if (actual.check(id)!=expected || actual.check(id)!=expected) return 5;
        if (i%997==0) {
            auto before=actual.snapshot();
            auto staged=actual.prepare(id);
            if (actual.snapshot()!=before || static_cast<bool>(staged)!=(expected==R::fresh)) return 25;
            if (staged) {
                s::UdpReplayWindow comparison;
                if (!comparison.restore(before) || comparison.commit(id)!=R::fresh ||
                    comparison.snapshot()!=staged->next_state()) return 26;
            } else if (staged.error()!=expected) return 27;
        }
        if (random()%3==0) continue; // Failed authentication: no commit.
        if (actual.commit(id)!=expected) return 6;
        if (expected==R::fresh) {
            if (!highest || id>*highest) highest=id;
            seen.insert(id);
            while (!seen.empty() && *highest-*seen.begin()>=s::UdpReplayWindow::width) seen.erase(seen.begin());
        }
        if (i%997==0) {
            s::UdpReplayWindow copy;
            auto state=actual.snapshot();
            if (!copy.restore(state) || copy.snapshot()!=state) return 14;
            auto high=highest.value_or(0);
            for (std::uint64_t distance=0;distance<=std::min(high,std::uint64_t{1025});++distance)
                if (copy.check(high-distance)!=actual.check(high-distance)) return 15;
        }
    }
    std::println("SS-2022 UDP replay window passed");
}
