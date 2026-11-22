#include "bounded_table.hpp"
#include <cstdlib>
#include <iostream>
#include <new>

namespace { thread_local bool fail_next_allocation=false; }
auto operator new(std::size_t size) -> void* {
    if (fail_next_allocation) { fail_next_allocation=false; throw std::bad_alloc(); }
    if (auto* p=std::malloc(size ? size : 1)) return p;
    throw std::bad_alloc();
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p,std::size_t) noexcept { std::free(p); }

int main() {
    using namespace dns_hp_experiment;
    HazardTable table(1);
    auto reader=table.reader(0);
    Key key{1,"existing.example.test",1};
    Answer original{key.name,{key.name},{},1000,1};
    if (!table.put(key,original)) return 1;
    Key replacement_key=key;
    Answer replacement=original; replacement.revision=2;
    fail_next_allocation=true;
    try {
        (void)table.put(std::move(replacement_key),std::move(replacement));
        return 2;
    } catch (std::bad_alloc const&) {}
    if (fail_next_allocation) return 3;
    auto value=reader.get(key);
    if (!value || value->revision!=1) return 4;

    Key absent{1,"new.example.test",1};
    Key candidate=absent;
    Answer answer{absent.name,{absent.name},{},1000,3};
    fail_next_allocation=true;
    try {
        (void)table.put(std::move(candidate),std::move(answer));
        return 5;
    } catch (std::bad_alloc const&) {}
    if (fail_next_allocation || reader.get(absent) || !reader.get(key)) return 6;

    try { (void)reader.visit(key,[](Answer const&) { throw 7; }); return 8; }
    catch (int error) { if (error!=7) return 9; }
    // Erasure and retirement must need no allocation, even after a throwing reader.
    fail_next_allocation=true;
    if (!table.erase(key) || !fail_next_allocation) return 10;
    fail_next_allocation=false;
    if (reader.get(key) || HazardTable::live_nodes()!=0) return 11;
    std::cout<<"allocation failure preserves contents; reclamation does not allocate\n";
}
