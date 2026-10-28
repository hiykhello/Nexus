import std;
import nexus.shadowsocks.udp_id_reservation;
namespace s=nexus::shadowsocks;
int main() {
    using W=s::UdpIdWatermark;
    using E=s::UdpIdError;
    if (s::UdpIdReservation::create({},0) || s::UdpIdReservation::create({1,true},1)) return 1;
    W stored{}; unsigned writes=0;
    auto commit=[&](W next) noexcept { ++writes; stored=next; return true; };
    auto owner=s::UdpIdReservation::create(stored,4);
    if (!owner || (*owner)->take(commit)!=0 || stored!=W{4,false} || writes!=1 ||
        (*owner)->take(commit)!=1 || writes!=1) return 2;
    // Simulate a crash after only two of four reserved IDs were used.
    auto restarted=s::UdpIdReservation::create(stored,4);
    if (!restarted || (*restarted)->take(commit)!=4 || stored!=W{8,false} || writes!=2) return 3;
    auto fail=[](W) noexcept { return false; };
    auto failing=s::UdpIdReservation::create(W{10,false},3);
    if (!failing || (*failing)->take(fail).error()!=E::storage ||
        (*failing)->take(commit).error()!=E::storage || writes!=2) return 4;
    // A commit may reach storage even when its caller sees failure. Recovery
    // must use the observed bound and skip the entire ambiguous reservation.
    W ambiguous{20,false};
    auto uncertain=[&](W next) noexcept { ambiguous=next; return false; };
    auto interrupted=s::UdpIdReservation::create(ambiguous,5);
    if (!interrupted || (*interrupted)->take(uncertain).error()!=E::storage || ambiguous!=W{25,false}) return 10;
    auto reconciled=s::UdpIdReservation::create(ambiguous,5);
    if (!reconciled || (*reconciled)->take(commit)!=25 || stored!=W{30,false}) return 11;
    auto limit=std::numeric_limits<std::uint64_t>::max();
    auto end=s::UdpIdReservation::create(W{limit-1,false},4);
    if (!end || (*end)->take(commit)!=limit-1 || stored!=W{0,true} ||
        (*end)->take(commit)!=limit || (*end)->take(commit).error()!=E::exhausted) return 5;
    auto already_done=s::UdpIdReservation::create(stored,1);
    if (!already_done || (*already_done)->take(commit).error()!=E::exhausted) return 6;
    auto reentrant=s::UdpIdReservation::create({},1);
    bool busy=false;
    auto recurse=[&](W) noexcept { auto nested=(*reentrant)->take(commit); busy=!nested && nested.error()==E::busy; return true; };
    if (!reentrant || (*reentrant)->take(recurse)!=0 || !busy) return 7;
    // A reservation may cover all but the final ID without overflowing.
    auto huge=s::UdpIdReservation::create({},limit);
    if (!huge || (*huge)->take(commit)!=0 || stored!=W{limit,false}) return 8;
    auto final=s::UdpIdReservation::create(stored,limit);
    if (!final || (*final)->take(commit)!=limit || stored!=W{0,true} ||
        (*final)->take(commit).error()!=E::exhausted) return 9;
    std::println("SS-2022 UDP durable ID reservation passed");
}
