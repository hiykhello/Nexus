import std;
import nexus.tls.key_share;
static bool trace=false, deny=false;
static std::size_t allocations=0, first_size=0;
void* operator new(std::size_t size) {
    if (deny) throw std::bad_alloc{};
    if (auto p=std::malloc(size ? size : 1)) {
        if (trace) { if (!allocations) first_size=size; ++allocations; }
        return p;
    }
    throw std::bad_alloc{};
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p,std::size_t) noexcept { ::operator delete(p); }
namespace t=nexus::tls;
int main() {
    std::vector<t::KeyShareEntry> entries{{0x001d,std::vector<std::uint8_t>(32,0x11)},{0x0017,std::vector<std::uint8_t>(65,0x22)}};
    auto encoded=t::KeyShare::encode_client(entries); if (!encoded) return 1; auto parsed=t::KeyShare::parse_client(*encoded); if (!parsed || *parsed!=entries) return 2;
    auto view=t::KeyShare::view_client(*encoded); std::size_t cursor=0;
    if (!view) return 13;
    for (auto const& entry:entries) {
        auto borrowed=view->next(cursor);
        if (!borrowed || borrowed->group!=entry.group || !std::ranges::equal(borrowed->key_exchange,entry.key_exchange)) return 14;
    }
    if (view->next(cursor)) return 15;
    cursor=std::numeric_limits<std::size_t>::max(); if (view->next(cursor)) return 17;
    auto repeated=*encoded; repeated[2+4+32]=0; repeated[2+4+32+1]=0x1d;
    if (t::KeyShare::view_client(repeated).error()!=t::KeyShareError::duplicate_group) return 18;
    auto empty_entry=*encoded; empty_entry[4]=0; empty_entry[5]=0;
    if (t::KeyShare::view_client(empty_entry).error()!=t::KeyShareError::empty) return 19;
    if (t::KeyShare::view_client(*encoded,encoded->size()-1).error()!=t::KeyShareError::message_too_large) return 20;
    auto server=t::KeyShare::encode_server(entries[0]); if (!server) return 3; auto server_parsed=t::KeyShare::parse_server(*server); if (!server_parsed || *server_parsed!=entries[0]) return 4;
    auto server_view=t::KeyShare::view_server(*server);
    if (!server_view || server_view->group!=entries[0].group || !std::ranges::equal(server_view->key_exchange,entries[0].key_exchange)) return 21;
    std::array<std::uint8_t,1120> hybrid{}; allocations=0; trace=true;
    auto encoded_hybrid=t::KeyShare::encode_server_view({0x11ec,hybrid}); trace=false;
    if (!encoded_hybrid || allocations!=1 || first_size!=1124 || !std::ranges::equal(std::span{*encoded_hybrid}.subspan(4),hybrid)) return 26;
    deny=true; auto empty_server=t::KeyShare::encode_server_view({29,{}}); deny=false;
    if (empty_server || empty_server.error()!=t::KeyShareError::empty) return 27;
    auto retry=t::KeyShare::encode_retry(0x001d); if (t::KeyShare::parse_retry(retry)!=0x001d) return 5;
    auto bad= *encoded; bad[1]--; if (t::KeyShare::parse_client(bad).error()!=t::KeyShareError::invalid_length) return 6;
    if (t::KeyShare::view_client(bad).error()!=t::KeyShareError::invalid_length) return 16;
    auto duplicate=entries; duplicate.push_back(entries[0]); if (t::KeyShare::encode_client(duplicate).error()!=t::KeyShareError::duplicate_group) return 7;
    auto empty=entries; empty[0].key_exchange.clear(); if (t::KeyShare::encode_client(empty).error()!=t::KeyShareError::empty) return 8;
    auto empty_list=std::vector<std::uint8_t>{0,0}; if (!t::KeyShare::parse_client(empty_list) || !t::KeyShare::parse_client(empty_list)->empty()) return 9;
    auto truncated=*encoded; truncated.pop_back(); if (t::KeyShare::parse_client(truncated).error()!=t::KeyShareError::invalid_length) return 10;
    auto bad_server=*server; bad_server[3]--; if (t::KeyShare::parse_server(bad_server).error()!=t::KeyShareError::invalid_length) return 11;
    if (t::KeyShare::view_server(bad_server).error()!=t::KeyShareError::invalid_length) return 22;
    if (t::KeyShare::parse_retry(std::vector<std::uint8_t>{1}).error()!=t::KeyShareError::truncated || t::KeyShare::parse_retry(std::vector<std::uint8_t>{1,2,3}).error()!=t::KeyShareError::invalid_length) return 12;
    std::vector<t::KeyShareEntry> many;
    for (std::uint16_t i=0;i<500;++i) many.push_back({i,{42}});
    allocations=0; trace=true; auto many_encoded=t::KeyShare::encode_client(many); trace=false;
    if (!many_encoded || allocations!=1 || first_size!=2502) return 23;
    allocations=0; trace=true; auto many_parsed=t::KeyShare::parse_client(*many_encoded); trace=false;
    if (!many_parsed || *many_parsed!=many || allocations!=501 || first_size!=500*sizeof(t::KeyShareEntry)) return 24;
    deny=true; auto invalid_duplicate=t::KeyShare::encode_client(duplicate); auto invalid_empty=t::KeyShare::encode_client(empty); deny=false;
    if (invalid_duplicate || invalid_duplicate.error()!=t::KeyShareError::duplicate_group || invalid_empty || invalid_empty.error()!=t::KeyShareError::empty) return 25;
    std::cout << "TLS key_share encoding and boundaries passed\n";
}
