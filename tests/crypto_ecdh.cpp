import crypto.ecdh;
import std;
int main() {
    namespace c = ::crypto;
    for (auto group:{23,24,25}) for (int trial=0;trial<12;++trial) {
        auto a=c::EcPrivate::generate(group),b=c::EcPrivate::generate(group);
        if (!a || !b || a->group()!=group || b->group()!=group) return 1;
        auto ap=a->public_key(),bp=b->public_key(); if (!ap || !bp || ap->view().size()!=c::nist_curve(group)->public_size()) return 2;
        auto ab=a->agree(bp->view()),ba=b->agree(ap->view());
        if (!ab || !ba || ab->view().size()!=c::nist_curve(group)->coordinate_size || !c::constant_time_equal(ab->view(),ba->view())) return 3;
        for (auto prefix:{0,2,3,5,6,7}) { auto malformed=*bp; malformed.bytes[0]=prefix; if (a->agree(malformed.view())) return 4; }
        if (a->agree(bp->view().first(bp->size-1))) return 5;
        auto invalid=*bp; std::ranges::fill(invalid.bytes,std::uint8_t{0xff}); invalid.bytes[0]=4; if (a->agree(invalid.view())) return 6;
        invalid=*bp; std::ranges::fill(invalid.bytes,std::uint8_t{0}); invalid.bytes[0]=4; if (a->agree(invalid.view())) return 7;
        auto moved=std::move(*a); if (a->public_key() || a->agree(bp->view()) || a->group()) return 8;
        if (!moved.agree(bp->view())) return 9;
    }
    if (c::EcPrivate::generate(22) || c::EcPrivate::generate(29)) return 10;
    std::println("ecdh 36 agreements plus malformed/moved/unsupported passed; owner={} secret={} public={}",sizeof(c::EcPrivate),sizeof(c::EcSecret),sizeof(c::EcPublic));
}
