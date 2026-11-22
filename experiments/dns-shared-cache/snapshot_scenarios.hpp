// Snapshot-specific lifecycle and index tests; include after the common test helpers.
#pragma once
#ifdef DNS_SNAPSHOT_EXPERIMENT
auto collision_and_compaction() -> int {
#ifdef DNS_ORDERED_SNAPSHOT_EXPERIMENT
    SemanticCache cache(256,0,1);
    auto reader=cache.reader(0);
    std::vector<d::CacheKey> keys;
    for (unsigned i=0;i<384;++i)
        keys.push_back({1+i%3,std::string(63,'a')+".long-common-prefix-"+std::to_string(i)+".test",
                        static_cast<std::uint16_t>(i%2 ? 1 : 28)});
    for (unsigned i=256;i-- > 0;) {
        auto token=cache.begin_query(keys[i]);
        if (!token || !cache.publish(keys[i],answer(keys[i],60,i),1000,*token)) return 1;
    }
    for (unsigned i=0;i<256;i+=2) {
        auto token=cache.begin_query(keys[i]);
        if (!token || !cache.invalidate(keys[i],1000,*token)) return 2;
    }
    for (unsigned i=0;i<256;++i) {
        auto value=cache.lookup(keys[i],1000,reader);
        if (!value || value->has_value()!=(i%2!=0) || (*value && (**value).addresses[0].bytes[0]!=i)) return 3;
    }
    for (unsigned i=256;i<384;++i) {
        auto token=cache.begin_query(keys[i]);
        if (!token || !cache.publish(keys[i],answer(keys[i],i%2 ? 60 : 1,i),1000,*token)) return 4;
    }
    if (cache.size()!=256) return 5;
    auto tick=cache.begin_refresh({1,"missing.test",1},3000,1);
    if (!tick || *tick || cache.size()!=192) return 6;
    for (unsigned i=0;i<384;++i) {
        auto value=cache.lookup(keys[i],3000,reader);
        bool present=i%2!=0;
        if (!value || value->has_value()!=present || (*value && (**value).addresses[0].bytes[0]!=static_cast<std::uint8_t>(i))) return 7;
    }
    return 0;
#else
    std::vector<d::CacheKey> colliding;
    for (unsigned i=0;colliding.size()<4 && i<100000;++i) {
        d::CacheKey key{1,"collision-"+std::to_string(i)+".test",1};
        if (dns_hp_experiment::ActualKeyHash{}(key)%512==511) colliding.push_back(std::move(key));
    }
    if (colliding.size()!=4) return 1;
    {
        SemanticCache cache(8,0,1);
        auto reader=cache.reader(0);
        for (unsigned i=0;i<3;++i) {
            auto token=cache.begin_query(colliding[i]);
            if (!token || !cache.publish(colliding[i],answer(colliding[i],60,i+1),1000,*token)) return 2;
        }
        auto remove=cache.begin_query(colliding[0]);
        if (!remove || !cache.invalidate(colliding[0],1000,*remove) || cache.tombstones_for_test()!=1) return 3;
        auto second=cache.lookup(colliding[1],1000,reader),third=cache.lookup(colliding[2],1000,reader);
        if (!second || !*second || (**second).addresses[0].bytes[0]!=2 ||
            !third || !*third || (**third).addresses[0].bytes[0]!=3) return 4;
        auto fresh=cache.begin_query(colliding[3]);
        if (!fresh || !cache.publish(colliding[3],answer(colliding[3],60,4),1000,*fresh) || cache.tombstones_for_test()!=0) return 5;
        auto fourth=cache.lookup(colliding[3],1000,reader);
        if (!fourth || !*fourth || (**fourth).addresses[0].bytes[0]!=4) return 6;
    }
    {
        SemanticCache cache(256,0,1);
        auto reader=cache.reader(0);
        std::vector<d::CacheKey> keys;
        for (unsigned i=0;i<384;++i) keys.push_back({1,"compact-"+std::to_string(i)+".test",1});
        for (unsigned i=0;i<256;++i) {
            auto token=cache.begin_query(keys[i]);
            if (!token || !cache.publish(keys[i],answer(keys[i],60,i),1000,*token)) return 7;
        }
        for (unsigned i=0;i<128;++i) {
            auto token=cache.begin_query(keys[i]);
            if (!token || !cache.invalidate(keys[i],1000,*token)) return 8;
            if (i==126 && cache.tombstones_for_test()!=127) return 9;
        }
        if (cache.tombstones_for_test()!=0 || cache.size()!=128) return 10;
        for (unsigned i=0;i<256;++i) {
            auto value=cache.lookup(keys[i],1000,reader);
            if (!value || value->has_value()!=(i>=128) || (*value && (**value).addresses[0].bytes[0]!=i)) return 11;
        }
        for (unsigned i=256;i<384;++i) {
            auto token=cache.begin_query(keys[i]);
            if (!token || !cache.publish(keys[i],answer(keys[i],60,i),1000,*token)) return 12;
        }
        if (cache.size()!=256) return 13;
        for (unsigned i=128;i<384;++i) {
            auto value=cache.lookup(keys[i],1000,reader);
            if (!value || !*value || (**value).addresses[0].bytes[0]!=static_cast<std::uint8_t>(i)) return 14;
        }
    }
    return 0;
#endif
}

auto reader_slot_lifetime() -> int {
    SemanticCache cache(8,0,1);
    try { (void)cache.reader(1); return 1; } catch (std::out_of_range const&) {}
    {
        auto first=cache.reader(0);
        auto moved=std::move(first);
        try { (void)cache.reader(0); return 2; } catch (std::logic_error const&) {}
    }
    auto again=cache.reader(0);
    SemanticCache other(8,0,1);
    auto foreign=other.reader(0);
    d::CacheKey key{1,"reader.test",1};
    auto token=cache.begin_query(key);
    if (!token || !cache.publish(key,answer(key,60,42),1000,*token)) return 3;
    try { (void)cache.lookup(key,1000,foreign); return 4; } catch (std::invalid_argument const&) {}
    try { (void)cache.lookup_negative(key,1000,foreign); return 5; } catch (std::invalid_argument const&) {}
    bool positive_rejected=false,negative_rejected=false;
    auto result=cache.lookup_with_hook(key,1000,again,[&] {
        try { (void)cache.lookup(key,1000,again); } catch (std::logic_error const&) { positive_rejected=true; }
        try { (void)cache.lookup_negative(key,1000,again); } catch (std::logic_error const&) { negative_rejected=true; }
    });
    if (!result || !*result || !positive_rejected || !negative_rejected) return 6;
    try {
        (void)cache.lookup_with_hook(key,1000,again,[] { throw std::runtime_error("test"); });
        return 7;
    } catch (std::runtime_error const&) {}
    result=cache.lookup(key,1000,again);
    if (!result || !*result) return 8;
    auto moved=std::move(again);
    try { (void)cache.lookup(key,1000,again); return 9; } catch (std::invalid_argument const&) {}
    result=cache.lookup(key,1000,moved);
    if (!result || !*result) return 10;
    return 0;
}
#ifdef DNS_ORDERED_SNAPSHOT_EXPERIMENT
auto large_reader_pool() -> int {
    constexpr std::size_t count=257;
    SemanticCache cache(1,0,count);
    std::vector<SemanticCache::Reader> readers;
    readers.reserve(count);
    for (std::size_t i=0;i<count;++i) readers.push_back(cache.reader(i));
    try { (void)cache.reader(count); return 1; } catch (std::out_of_range const&) {}
    d::CacheKey key{1,"large-pool.test",1};
    auto publish=[&](unsigned value) {
        auto token=cache.begin_query(key);
        return token && cache.publish(key,answer(key,60,value),1000,*token).has_value();
    };
    if (!publish(0)) return 2;
    bool intact=true;
    auto pin=[&](auto&& self,std::size_t i) -> void {
        auto result=cache.lookup_with_hook(key,1000,readers[i],[&] {
            if (!publish(i+1)) { intact=false; return; }
            if (i+1<count) self(self,i+1);
            else if (SemanticCache::live_nodes()!=count+1) intact=false;
        });
        if (!result || !*result || (**result).addresses[0].bytes[0]!=static_cast<std::uint8_t>(i)) intact=false;
    };
    pin(pin,0);
    if (!intact || !publish(9) || SemanticCache::live_nodes()!=1) return 3;
    return 0;
}

auto full_history_bound() -> int {
#ifdef DNS_ORDERED_SCALED_EXPERIMENT
    constexpr std::size_t count=4,entries=512;
#else
    constexpr std::size_t count=4,entries=256;
#endif
    SemanticCache cache(entries,0,count);
    std::vector<SemanticCache::Reader> readers;
    readers.reserve(count);
    for (std::size_t i=0;i<count;++i) readers.push_back(cache.reader(i));
    std::vector<d::CacheKey> keys;
    for (std::size_t i=0;i<entries;++i) keys.push_back({1,"bound-"+std::to_string(i)+".test",1});
    auto publish=[&](d::CacheKey const& key,unsigned value) {
        auto token=cache.begin_query(key);
        return token && cache.publish(key,answer(key,60,value),1000,*token).has_value();
    };
    for (auto const& key:keys) if (!publish(key,0)) return 1;
    bool intact=true;
    auto pin=[&](auto&& self,std::size_t i) -> void {
        auto result=cache.lookup_with_hook(keys[0],1000,readers[i],[&] {
            for (auto const& key:keys) if (!publish(key,i+1)) { intact=false; return; }
            if (i+1<count) self(self,i+1);
            else if (SemanticCache::live_nodes()!=(count+1)*entries || !publish(keys[0],5) ||
                     SemanticCache::live_nodes()!=(count+1)*entries || SemanticCache::peak_nodes()<(count+1)*entries+1) intact=false;
        });
        if (!result || !*result || (**result).addresses[0].bytes[0]!=i) intact=false;
    };
    pin(pin,0);
    if (!intact || !publish(keys[0],9) || SemanticCache::live_nodes()!=entries) return 2;
    return 0;
}

auto ordered_replacement_race() -> int {
    SemanticCache cache(64,0,2);
    std::vector<d::CacheKey> keys;
    for (unsigned i=0;i<32;++i) keys.push_back({1,"key-"+std::to_string(i)+".test",1});
    for (unsigned i=0;i<keys.size();++i) {
        auto token=cache.begin_query(keys[i]);
        if (!token || !cache.publish(keys[i],answer(keys[i],60,i+40),1000,*token)) return 1;
    }
    std::atomic<bool> pinned=false,release=false,valid=false;
    std::thread old_reader([&] {
        auto reader=cache.reader(0);
        auto result=cache.lookup_with_hook(keys[16],1000,reader,[&] {
            pinned=true;
            while (!release.load()) std::this_thread::yield();
        });
        valid=result && *result && (**result).addresses[0].bytes[0]==56;
    });
    while (!pinned.load()) std::this_thread::yield();
    bool writer_ok=true;
    auto remove=cache.begin_query(keys[16]);
    writer_ok=remove && cache.invalidate(keys[16],1000,*remove).has_value();
    for (unsigned i=0;i<32 && writer_ok;++i) {
        d::CacheKey fresh{1,"other-"+std::to_string(i)+".test",1};
        auto token=cache.begin_query(fresh);
        writer_ok=token && cache.publish(fresh,answer(fresh,60,i),1000,*token).has_value();
    }
    writer_ok=writer_ok && cache.clear(1000).has_value();
    d::CacheKey new_key{2,"new.test",1};
    auto token=cache.begin_query(new_key);
    writer_ok=writer_ok && token && cache.publish(new_key,answer(new_key,60,99),1000,*token).has_value();
    auto current=cache.reader(1);
    auto old=cache.lookup(keys[16],1000,current),fresh=cache.lookup(new_key,1000,current);
    writer_ok=writer_ok && old && !*old && fresh && *fresh && (**fresh).addresses[0].bytes[0]==99;
    release=true;
    old_reader.join();
    return writer_ok && valid ? 0 : 2;
}
#endif

auto snapshot_protect_retry() -> int {
    SemanticCache cache(8,0,1);
    d::CacheKey key{1,"retry.test",1};
    auto publish=[&](unsigned revision) {
        auto token=cache.begin_query(key);
        return token && cache.publish(key,answer(key,60,revision),1000,*token).has_value();
    };
    if (!publish(1)) return 1;
    dns_hp_experiment::loaded_snapshot=nullptr;
    dns_hp_experiment::resume_snapshot_load=false;
    std::atomic<bool> guarded=false,release=false;
    std::optional<std::expected<std::optional<d::AddressAnswer>,d::CacheError>> result;
    std::thread reader([&] {
        auto handle=cache.reader(0);
        dns_hp_experiment::pause_snapshot_load=true;
        result=cache.lookup_with_hook(key,1000,handle,[&] {
            guarded=true;
            while (!release.load()) std::this_thread::yield();
        });
    });
    while (!dns_hp_experiment::loaded_snapshot.load()) std::this_thread::yield();
    auto* original=dns_hp_experiment::loaded_snapshot.load();
    if (!publish(2)) std::abort();
    bool changed=cache.current_for_test()!=original;
    dns_hp_experiment::resume_snapshot_load=true;
    while (!guarded.load()) std::this_thread::yield();
    for (unsigned i=0;i<1000;++i) if (!publish(3+i)) std::abort();
    release=true;
    reader.join();
    if (!changed || !result || !*result || !(**result) || (***result).addresses[0].bytes[0]!=2) return 2;
    return 0;
}

auto reused_snapshot_address() -> int {
    SemanticCache cache(8,0,1);
    d::CacheKey key{1,"reuse.test",1};
    auto publish=[&](unsigned revision) {
        auto token=cache.begin_query(key);
        return token && cache.publish(key,answer(key,60,revision),1000,*token).has_value();
    };
    if (!publish(1)) return 1;
    dns_hp_experiment::loaded_snapshot=nullptr;
    dns_hp_experiment::resume_snapshot_load=false;
    std::atomic<bool> guarded=false,release=false;
    std::optional<std::expected<std::optional<d::AddressAnswer>,d::CacheError>> result;
    std::thread reader([&] {
        auto handle=cache.reader(0);
        dns_hp_experiment::pause_snapshot_load=true;
        result=cache.lookup_with_hook(key,1000,handle,[&] {
            guarded=true;
            while (!release.load()) std::this_thread::yield();
        });
    });
    while (!dns_hp_experiment::loaded_snapshot.load()) std::this_thread::yield();
    auto* original=dns_hp_experiment::loaded_snapshot.load();
    if (!publish(2)) std::abort();
    bool reused=cache.current_for_test()!=original;
    if (!publish(3)) std::abort();
    reused=reused && cache.current_for_test()==original;
    dns_hp_experiment::resume_snapshot_load=true;
    while (!guarded.load()) std::this_thread::yield();
    // The read guard now protects the new version at the same address. Repeated
    // publication must neither mutate it nor reclaim its answer.
    for (unsigned i=0;i<1000;++i) if (!publish(4+i)) std::abort();
    release=true;
    reader.join();
    if (!reused || !result || !*result || !(**result) || (***result).addresses[0].bytes[0]!=3) return 2;
    return 0;
}

auto retained_snapshots() -> int {
    if (SemanticCache::live_nodes()!=0) return 1;
    SemanticCache cache(8,0,8);
    std::array<d::CacheKey,8> keys;
    for (unsigned i=0;i<keys.size();++i) {
        keys[i]={1,"held-"+std::to_string(i)+".test",1};
        auto token=cache.begin_query(keys[i]);
        if (!token || !cache.publish(keys[i],answer(keys[i],60,1),1000,*token)) return 2;
    }
    std::array<std::atomic<bool>,8> pinned{};
    std::atomic<bool> release=false,failed=false;
    std::vector<std::thread> readers;
    for (unsigned t=0;t<8;++t) {
        readers.emplace_back([&,t] {
            auto reader=cache.reader(t);
            auto result=cache.lookup_with_hook(keys[0],1000,reader,[&] {
                pinned[t]=true;
                while (!release.load()) std::this_thread::yield();
            });
            if (!result || !*result || (**result).addresses[0].bytes[0]!=t+1) failed=true;
        });
        while (!pinned[t].load()) std::this_thread::yield();
        for (auto const& key:keys) {
            auto token=cache.begin_query(key);
            if (!token || !cache.publish(key,answer(key,60,t+2),1000,*token)) std::abort();
        }
    }
    if (SemanticCache::live_nodes()!=72) failed=true;
    for (int i=0;i<1000;++i) {
        auto token=cache.begin_query(keys[0]);
        if (!token || !cache.publish(keys[0],answer(keys[0],60,i),1000,*token)) std::abort();
    }
    if (SemanticCache::live_nodes()!=72) failed=true;
    release=true;
    for (auto& reader:readers) reader.join();
    auto token=cache.begin_query(keys[0]);
    if (!token || !cache.publish(keys[0],answer(keys[0],60,1),1000,*token) || SemanticCache::live_nodes()!=8 || failed) return 3;
    return 0;
}
#endif
