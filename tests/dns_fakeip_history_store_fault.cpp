#include <stdlib.h>
import std;
import dns.fakeip_history_store;
import dns.fakeip_recovery;
namespace d=dns;
using namespace std::chrono_literals;
auto main(int argc,char** argv) -> int {
    if (argc!=3) return 2;
    std::array<std::uint8_t,16> instance{}; std::array<std::uint8_t,32> key{};
    std::iota(key.begin(),key.end(),std::uint8_t{1});
    auto mode=std::string_view(argv[2]);
    auto result=d::FakeIpHistoryStore::open(argv[1],instance,key,mode=="init" ? d::FakeIpHistoryStoreMode::create_new : d::FakeIpHistoryStoreMode::open_existing); if(!result) return 3;
    auto& store=*result;
    if (mode=="verify-old" || mode=="verify-new") {
        auto expected=mode=="verify-old" ? 1u : 2u;
        if (!store.history() || store.generation()!=expected || store.history()->ranges.size()!=expected ||
            store.history()->ranges[0].first!=0xc6120000 ||
            (expected==2 && store.history()->ranges[1].first!=0xc6130000)) return 4;
        return 0;
    }
    if (mode!="init" && mode!="update" && mode!="update-start") return 2;
    bool init=mode=="init";
    if (store.generation()!=(init ? 0u : 1u)) return 5;
    d::FakeIpRecoveryPool pool{init ? 0xc6120000u : 0xc6130000u,init ? 0xc6120003u : 0xc6130003u,
        init ? 0xc6120001u : 0xc6130001u,init ? 0xc6120001u : 0xc6130001u,10s,2s};
    if (mode=="update-start") {
        auto owner=d::start_fakeip(std::move(store),pool,3s);
        if (owner || !std::holds_alternative<d::FakeIpHistoryStoreError>(owner.error()) ||
            std::get<d::FakeIpHistoryStoreError>(owner.error())!=d::FakeIpHistoryStoreError::io) return 10;
        return 0;
    }
    auto const empty=std::vector<d::FakeIpHistoricalRange>{};
    auto next=d::update_fakeip_history(pool,store.history() ? store.history()->ranges : empty);
    if (!next) return 6;
    auto committed=store.commit({init ? 1u : 2u,std::move(*next)});
    bool injected=std::getenv("NEXUS_EXPECT_FAULT")!=nullptr;
    if (injected) {
        if (committed || !store.failed() || store.history()) return 7;
        if (store.commit({2,{{0xc6120000,0xc6120003,12s}}})) return 8;
    } else if (!committed || store.failed()) return 9;
    return 0;
}
