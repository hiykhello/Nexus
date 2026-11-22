#include <cstdlib>
#include <unistd.h>
import std;
import state;

using namespace std::chrono_literals;

namespace {
    namespace fs=std::filesystem;

    auto check(bool condition,std::string_view message) -> void {
        if (condition) return;
        std::cerr << "FAIL " << message << '\n';
        std::exit(1);
    }

    struct Directory {
        fs::path path;
        Directory() {
            char name[]="/tmp/nexus-92c-unit.XXXXXX";
            auto* created=::mkdtemp(name);
            check(created!=nullptr,"private temporary state");
            path=created;
        }
        ~Directory() {std::error_code ignored;fs::remove_all(path,ignored);}
    };

    auto name(unsigned index) -> std::string {
        return std::format("{}.{}.{}.{}.test",index,std::string(63,'a'),std::string(63,'b'),std::string(63,'c'));
    }

    auto fakeip() -> void {
        Directory root;
        state::FakeIpScope pool{0xC6120000,0xC612FFFF,0xC6120001,0xC612FFFE};
        pool.exclude_cidrs={{pool.first,pool.first},{pool.last,pool.last},{pool.alloc_first+3,pool.alloc_first+3}};
        auto opened=state::FakeIpStore::open(root.path,pool,state::CrashMode::range_reserve);
        check(opened.has_value(),"open range store");
        auto device=std::move(*opened);
        constexpr unsigned count=8200;
        for (unsigned i=0;i<count;++i) {
            auto text=name(i);
            auto limit=std::chrono::steady_clock::now()+3s;
            for (;;) {
                auto assigned=device->assign(text,2);
                if (assigned) {
                    check(*assigned==pool.alloc_first+i+(i>=3),"monotonic allocation skips exclusions");
                    break;
                }
                check(assigned.error().stage==state::Stage::capacity && std::chrono::steady_clock::now()<limit,
                      "bounded WAL queue continues after worker progress");
                std::this_thread::sleep_for(1ms);
            }
        }
        device.reset();
        check(fs::exists(root.path/"fakeip/fakeip.ckpt"),"checkpoint written at threshold");
        auto wal=root.path/"fakeip/fakeip.wal";
        check(fs::file_size(wal)<2*1024*1024,"WAL truncated after checkpoint");
        {
            std::ofstream tail(wal,std::ios::app|std::ios::binary);
            tail << "NXFP01";
        }
        opened=state::FakeIpStore::open(root.path,pool,state::CrashMode::per_mapping);
        check(opened.has_value(),"checkpoint plus partial WAL tail recovery");
        device=std::move(*opened);
        unsigned recovered=0;
        check(device->visit_recovered([&](auto const&) {++recovered;return true;}) && recovered==count,
            "all complete records replayed");
        check(device->assign(name(0),2)==pool.alloc_first,"forward bijection survives recovery");
        auto next=device->assign(name(0),3);
        check(next && *next==pool.alloc_first+8448,"skip pre-reserved highwater and isolate views");
        device.reset();
        opened=state::FakeIpStore::open(root.path,pool,state::CrashMode::per_mapping);
        check(opened && (*opened)->assign(name(0),3)==*next,"per-mapping result is durable");
        opened->reset();
        pool.identity[0]=std::byte{1};
        auto alien=state::FakeIpStore::open(root.path,pool,state::CrashMode::range_reserve);
        check(!alien && alien.error().stage==state::Stage::format,"refuse mismatched pool identity");
        std::cout << "PASS FakeIP exclusions, both modes, WAL compaction/truncation and owner-bound replay\n";
    }

    auto dns_cache() -> void {
        Directory root;
        state::DnsCache cache(root.path,4096);
        state::Fingerprint one{std::byte{1}},two{std::byte{2}},three{std::byte{3}};
        state::Bytes body(1500,std::byte{7});
        auto before=cache.lookup(one);
        check(before && !before->payload,"empty cache");
        check(cache.store(one,before->epoch,body).has_value() && cache.store(two,before->epoch,body).has_value(),
            "durable independent views");
        check(cache.lookup(one)->payload==body && cache.lookup(two)->payload==body,"restore each view");
        check(cache.store(three,before->epoch,body).has_value() && !cache.lookup(two)->payload,
            "disk byte limit evicts a view");
        check(cache.clear().has_value(),"persist clear barrier");
        auto stale=cache.store(one,before->epoch,body);
        check(!stale && stale.error().stage==state::Stage::stale_epoch,"old generation cannot republish");
        state::DnsCache reopened(root.path,4096);
        auto after=reopened.lookup(one);
        check(after && !after->payload && after->epoch>before->epoch,"clear survives restart");
        check(reopened.store(one,after->epoch,body).has_value(),"new epoch can populate");
        std::cout << "PASS NXDN03 independent views, byte budget, persisted clear and stale-writer rejection\n";
    }
}

int main() {
    fakeip();
    dns_cache();
}
