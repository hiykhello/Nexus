import std;
import shadowsocks.udp_sessions;
import shadowsocks.udp_packet;
import shadowsocks.udp_replay;
import shadowsocks.udp_id_reservation;
namespace s=shadowsocks;
using namespace std::chrono_literals;
int main() {
    std::array<std::uint8_t,16> key{}; std::iota(key.begin(),key.end(),0);
    s::UdpPeer first{4,{127,0,0,1},1000}, second{4,{127,0,0,1},2000};
    auto t=std::chrono::steady_clock::time_point{};
    s::UdpPacket packet{{0,1,2,3,4,5,6,7},0,1000,{}, {1,127,0,0,1,0,80},{1}};
    {
        s::UdpServerSessions clock(1);
        if (!clock.expire(t,1000) || !clock.expire(t+1s,1001) ||
            clock.expire(t+1s,1000).error()!=s::UdpSessionError::time_reversed) return 71;
    }
    auto wire=[&] { return *s::encode_udp_packet(key,s::UdpDirection::client,packet,{}); };
    auto original=wire();
    s::UdpServerSessions sessions(1);
    auto accepted=sessions.receive(key,original,first,t,1000);
    if (!accepted || !accepted->new_session || accepted->source!=first || sessions.peer(packet.session_id)!=first || sessions.size()!=1) return 1;
    auto first_accepted=*accepted;
    s::UdpServerSessions other_owner(1);
    auto other_accepted=other_owner.receive(key,original,first,t,1000);
    if (!other_accepted || !sessions.current(*accepted) || !other_owner.current(*other_accepted) ||
        sessions.current(*other_accepted) || other_owner.current(*accepted)) return 53;
    if (sessions.receive(key,original,second,t+1s,1001).error()!=s::UdpSessionError::duplicate || sessions.peer(packet.session_id)!=first) return 2;
    packet.packet_id=1; packet.timestamp=1001; auto next=wire();
    auto forged=next; forged.back()^=1;
    if (sessions.receive(key,forged,second,t+1s,1001).error()!=s::UdpSessionError::packet || sessions.peer(packet.session_id)!=first) return 3;
    accepted=sessions.receive(key,next,second,t+1s,1001);
    if (!accepted || accepted->new_session || accepted->source!=second || first_accepted.source!=first ||
        sessions.peer(packet.session_id)!=second) return 4;
    packet.packet_id=5000; packet.timestamp=1001; auto forged_high=wire(); forged_high.back()^=1;
    if (sessions.receive(key,forged_high,first,t+1s,1001).error()!=s::UdpSessionError::packet) return 14;
    packet.packet_id=2; auto lower=wire();
    if (!sessions.receive(key,lower,second,t+1s,1001)) return 15;
    packet.session_id[0]=8; packet.packet_id=0; auto other=wire();
    if (sessions.receive(key,other,first,t+1s,1001).error()!=s::UdpSessionError::full) return 5;
    auto expired=sessions.expire(t+62s,1062);
    if (!expired || !expired->empty() || sessions.size()!=1) return 6;
    if (sessions.expire(t+63s,1001).error()!=s::UdpSessionError::time_reversed || sessions.size()!=1) return 7;
    expired=sessions.expire(t+63s,1063);
    if (!expired || expired->size()!=1 || (*expired)[0][0]!=0 || sessions.size()!=0) return 8;
    packet.timestamp=1063; other=wire();
    if (!sessions.receive(key,other,first,t+63s,1063) || sessions.size()!=1) return 9;
    packet.packet_id=2000; packet.timestamp=1064;
    auto high=wire();
    if (!sessions.receive(key,high,second,t+64s,1064)) return 10;
    packet.packet_id=0; auto old=wire();
    if (sessions.receive(key,old,first,t+64s,1064).error()!=s::UdpSessionError::too_old || sessions.peer(packet.session_id)!=second) return 11;
    auto badpeer=first; badpeer.address[5]=1;
    if (sessions.receive(key,high,badpeer,t+64s,1064).error()!=s::UdpSessionError::invalid_peer) return 12;
    if (sessions.expire(t+63s,1064).error()!=s::UdpSessionError::time_reversed) return 13;
    // Separate response lifecycle: rebinding, nonce consumption on failure,
    // outbound activity and new server ID after session expiry.
    s::UdpServerSessions replies(2);
    packet.session_id={0,1,2,3,4,5,6,7}; packet.packet_id=0; packet.timestamp=2000;
    auto request=wire();
    if (!replies.receive(key,request,first,t,2000)) return 16;
    auto make_reply=[&](auto now, std::uint64_t wall, auto const& address) {
        return replies.response(key,packet.session_id,address,packet.payload,{},now,wall);
    };
    auto one=make_reply(t+1s,2001,packet.address);
    if (!one || one->peer!=first) return 17;
    auto decoded=s::decode_udp_packet(key,s::UdpDirection::server,one->wire,2001,packet.session_id);
    if (!decoded || decoded->packet_id!=0 || decoded->session_id==packet.session_id || decoded->payload!=packet.payload) return 18;
    auto server_id=decoded->session_id;
    auto client_id=packet.session_id;
    packet.session_id=server_id; packet.packet_id=0; packet.timestamp=2001;
    if (replies.receive(key,wire(),first,t+1s,2001).error()!=s::UdpSessionError::session_id_conflict) return 69;
    packet.session_id=client_id;
    packet.packet_id=1; packet.timestamp=2002;
    if (!replies.receive(key,wire(),second,t+2s,2002)) return 19;
    std::vector<std::uint8_t> bad_address{0};
    if (make_reply(t+3s,2003,bad_address).error()!=s::UdpSessionError::packet) return 20;
    auto two=make_reply(t+4s,2004,packet.address);
    if (!two || two->peer!=second) return 21;
    decoded=s::decode_udp_packet(key,s::UdpDirection::server,two->wire,2004,packet.session_id);
    if (!decoded || decoded->packet_id!=2 || decoded->session_id!=server_id) return 22;
    auto active=replies.expire(t+65s,2065);
    if (!active || !active->empty()) return 23;
    active=replies.expire(t+66s,2066);
    if (!active || active->size()!=1) return 24;
    packet.session_id=server_id; packet.packet_id=0; packet.timestamp=2066;
    if (replies.receive(key,wire(),first,t+66s,2066).error()!=s::UdpSessionError::session_id_conflict) return 70;
    packet.session_id=client_id;
    if (make_reply(t+66s,2066,packet.address).error()!=s::UdpSessionError::missing) return 25;
    packet.packet_id=0; packet.timestamp=2066;
    if (!replies.receive(key,wire(),first,t+66s,2066)) return 26;
    auto three=make_reply(t+66s,2066,packet.address);
    if (!three) return 27;
    decoded=s::decode_udp_packet(key,s::UdpDirection::server,three->wire,2066,packet.session_id);
    if (!decoded || decoded->packet_id!=0 || decoded->session_id==server_id) return 28;
    // A failed authentication cannot bind the owner; after binding, even a
    // fully authenticated packet under another key cannot change its state.
    s::UdpServerSessions keys(2);
    std::array<std::uint8_t,16> other_key{}; other_key.fill(0xa5);
    packet.packet_id=0; packet.timestamp=3000; packet.session_id={1,1,1,1,1,1,1,1};
    auto first_wire=*s::encode_udp_packet(key,s::UdpDirection::client,packet,{});
    auto corrupt=first_wire; corrupt.back()^=1;
    if (keys.receive(key,corrupt,first,t,3000).error()!=s::UdpSessionError::packet) return 29;
    auto other_wire=*s::encode_udp_packet(other_key,s::UdpDirection::client,packet,{});
    if (!keys.receive(other_key,other_wire,first,t,3000)) return 30;
    packet.packet_id=1; auto changed=*s::encode_udp_packet(key,s::UdpDirection::client,packet,{});
    if (keys.receive(key,changed,second,t+1s,3001).error()!=s::UdpSessionError::key_mismatch || keys.peer(packet.session_id)!=first) return 31;
    if (keys.response(key,packet.session_id,packet.address,packet.payload,{},t+1s,3001).error()!=s::UdpSessionError::key_mismatch) return 32;
    auto valid_other=*s::encode_udp_packet(other_key,s::UdpDirection::client,packet,{});
    if (!keys.receive(other_key,valid_other,second,t+1s,3001) || keys.peer(packet.session_id)!=second) return 33;

    // Experimental durable receive: authentication and replay checks precede
    // the callback, which must succeed before a new peer is visible.
    auto durable_receive=[](auto& owner, auto const& key_arg, auto const& bytes, auto peer_arg, auto now, std::uint64_t wall, auto& commit) {
        auto clock=[&]() noexcept -> std::optional<s::UdpClockSample> { return s::UdpClockSample{now,wall}; };
        return owner.receive_durable(key_arg,bytes,peer_arg,now,wall,commit,clock);
    };
    s::UdpServerSessions durable(2,true);
    packet.session_id={3,1,2,3,4,5,6,7}; packet.packet_id=0; packet.timestamp=4000;
    auto durable_wire=wire();
    unsigned writes=0; bool allow=true, saw_busy=false;
    std::optional<s::UdpPeer> peer_during_commit;
    s::UdpReplaySnapshot stored;
    auto save=[&](std::array<std::uint8_t,8> const& id, s::UdpReplaySnapshot const& snapshot, std::uint64_t wall) noexcept {
        ++writes;
        if (id!=packet.session_id || wall!=packet.timestamp+60) return false;
        auto nested=durable.receive(key,durable_wire,first,t,4000);
        saw_busy=!nested && nested.error()==s::UdpSessionError::busy;
        peer_during_commit=durable.peer(id);
        if (!allow) return false;
        stored=snapshot;
        return true;
    };
    if (durable.receive(key,durable_wire,first,t,4000).error()!=s::UdpSessionError::durability_required) return 34;
    if (durable_receive(durable,key,durable_wire,first,t,4000,save).error()!=s::UdpSessionError::invalid_state ||
        !durable.restore_durable(key,{},4000,t,4000,{},4)) return 44;
    auto committed=durable_receive(durable,key,durable_wire,first,t,4000,save);
    if (!committed || !committed->new_session || !saw_busy || writes!=1 || durable.peer(packet.session_id)!=first) return 35;
    s::UdpReplayWindow recovered;
    if (!recovered.restore(stored) || recovered.check(0)!=s::UdpReplayResult::duplicate) return 36;
    if (durable_receive(durable,key,durable_wire,second,t,4000,save).error()!=s::UdpSessionError::duplicate || writes!=1) return 37;
    packet.packet_id=1; packet.timestamp=4001; durable_wire=wire();
    auto bad=durable_wire; bad.back()^=1;
    if (durable_receive(durable,key,bad,second,t+1s,4001,save).error()!=s::UdpSessionError::packet || writes!=1) return 38;
    if (!durable_receive(durable,key,durable_wire,second,t+1s,4001,save) || writes!=2 ||
        peer_during_commit!=first || durable.peer(packet.session_id)!=second) return 43;
    packet.packet_id=2; packet.timestamp=4002; durable_wire=wire();
    allow=false;
    if (durable_receive(durable,key,durable_wire,first,t+2s,4002,save).error()!=s::UdpSessionError::storage ||
        writes!=3 || peer_during_commit!=second || durable.peer(packet.session_id)!=second || durable.current(*committed)) return 39;
    allow=true;
    if (durable_receive(durable,key,durable_wire,first,t+2s,4002,save).error()!=s::UdpSessionError::storage || writes!=3 ||
        durable.expire(t+2s,4002).error()!=s::UdpSessionError::storage ||
        durable.response(key,packet.session_id,packet.address,packet.payload,{},t+2s,4002).error()!=s::UdpSessionError::storage) return 40;
    s::UdpServerSessions fresh_failure(1,true);
    allow=false;
    if (!fresh_failure.restore_durable(key,{},4002,t,4002,{},4)) return 45;
    if (durable_receive(fresh_failure,key,durable_wire,first,t,4002,save).error()!=s::UdpSessionError::storage || fresh_failure.size()!=0) return 41;
    s::UdpServerSessions disabled(1,true);
    if (disabled.expire(t,4000).error()!=s::UdpSessionError::durability_required ||
        disabled.response(key,packet.session_id,packet.address,packet.payload,{},t,4000).error()!=s::UdpSessionError::durability_required) return 42;
    s::UdpStoredSession record{packet.session_id,stored};
    std::array records{record};
    s::UdpServerSessions restored_sessions(2,true);
    if (restored_sessions.restore_durable(key,records,4002,t,4001,{},4).error()!=s::UdpSessionError::time_reversed ||
        restored_sessions.size()!=0) return 46;
    auto broken=records; broken[0].replay.seen[0]=0;
    if (restored_sessions.restore_durable(key,broken,4002,t,4002,{},4).error()!=s::UdpSessionError::invalid_state ||
        restored_sessions.size()!=0) return 47;
    std::array duplicates{record,record};
    if (restored_sessions.restore_durable(key,duplicates,4002,t,4002,{},4).error()!=s::UdpSessionError::invalid_state ||
        restored_sessions.size()!=0) return 48;
    if (!restored_sessions.restore_durable(key,records,4002,t,4002,{},4) || restored_sessions.size()!=1 ||
        restored_sessions.peer(packet.session_id) ||
        restored_sessions.restore_durable(key,records,4002,t,4002,{},4).error()!=s::UdpSessionError::invalid_state) return 49;
    auto restored_save=[](auto const&, auto const&, std::uint64_t) noexcept { return true; };
    packet.packet_id=1; packet.timestamp=4002;
    if (durable_receive(restored_sessions,key,wire(),first,t,4002,restored_save).error()!=s::UdpSessionError::duplicate ||
        restored_sessions.peer(packet.session_id)) return 50;
    packet.packet_id=2;
    if (durable_receive(restored_sessions,other_key,wire(),first,t,4002,restored_save).error()!=s::UdpSessionError::key_mismatch ||
        !durable_receive(restored_sessions,key,wire(),second,t,4002,restored_save) ||
        restored_sessions.peer(packet.session_id)!=second) return 51;
    s::UdpServerSessions too_small(0,true);
    if (too_small.restore_durable(key,records,4002,t,4002,{},4).error()!=s::UdpSessionError::full || too_small.size()!=0) return 52;
    // Responses consume persisted server-ID reservations before encoding. A
    // restarted owner discards the old range and allocates a distinct ID.
    s::UdpIdWatermark bound{}; unsigned reservations=0;
    auto reserve=[&](s::UdpIdWatermark next) noexcept { bound=next; ++reservations; return true; };
    auto save_wall=[](std::uint64_t) noexcept { return true; };
    auto response_clock=[&]() noexcept -> std::optional<s::UdpClockSample> { return s::UdpClockSample{t,4002}; };
    auto reply=restored_sessions.response_durable(key,packet.session_id,packet.address,packet.payload,{},t,4002,reserve,save_wall,response_clock);
    if (!reply || reservations!=1 || bound!=s::UdpIdWatermark{4,false}) return 54;
    auto decoded_reply=s::decode_udp_packet(key,s::UdpDirection::server,reply->wire,4002,packet.session_id);
    if (!decoded_reply || decoded_reply->packet_id!=0) return 55;
    auto prior_server_id=decoded_reply->session_id;
    auto again=restored_sessions.response_durable(key,packet.session_id,packet.address,packet.payload,{},t,4002,reserve,save_wall,response_clock);
    if (!again || reservations!=1) return 56;
    decoded_reply=s::decode_udp_packet(key,s::UdpDirection::server,again->wire,4002,packet.session_id);
    if (!decoded_reply || decoded_reply->packet_id!=1 || decoded_reply->session_id!=prior_server_id) return 57;
    s::UdpServerSessions reboot(2,true);
    if (!reboot.restore_durable(key,records,4002,t,4002,bound,4) ||
        !durable_receive(reboot,key,wire(),second,t,4002,restored_save)) return 58;
    auto after_restart=reboot.response_durable(key,packet.session_id,packet.address,packet.payload,{},t,4002,reserve,save_wall,response_clock);
    if (!after_restart || reservations!=2 || bound!=s::UdpIdWatermark{8,false}) return 59;
    decoded_reply=s::decode_udp_packet(key,s::UdpDirection::server,after_restart->wire,4002,packet.session_id);
    if (!decoded_reply || decoded_reply->packet_id!=0 || decoded_reply->session_id==prior_server_id) return 60;
    s::UdpServerSessions failed_response(2,true);
    if (!failed_response.restore_durable(key,records,4002,t,4002,{},4) ||
        !durable_receive(failed_response,key,wire(),first,t,4002,restored_save)) return 61;
    auto fail_id=[](s::UdpIdWatermark) noexcept { return false; };
    if (failed_response.response_durable(key,packet.session_id,packet.address,packet.payload,{},t,4002,fail_id,save_wall,response_clock).error()!=s::UdpSessionError::storage ||
        failed_response.response_durable(key,packet.session_id,packet.address,packet.payload,{},t,4002,reserve,save_wall,response_clock).error()!=s::UdpSessionError::storage) return 62;
    s::UdpServerSessions collision(2,true);
    packet.session_id={0,0,0,0,0,0,0,0}; packet.packet_id=0; packet.timestamp=5000;
    if (!collision.restore_durable(key,{},5000,t,5000,{},1) ||
        !durable_receive(collision,key,wire(),first,t,5000,restored_save)) return 63;
    packet.session_id[7]=1;
    if (!durable_receive(collision,key,wire(),second,t,5000,restored_save)) return 66;
    packet.session_id[7]=0;
    bound={}; reservations=0;
    auto collision_clock=[&]() noexcept -> std::optional<s::UdpClockSample> { return s::UdpClockSample{t,5000}; };
    auto skip=collision.response_durable(key,packet.session_id,packet.address,packet.payload,{},t,5000,reserve,save_wall,collision_clock);
    if (!skip || reservations!=3 || bound!=s::UdpIdWatermark{3,false}) return 64;
    decoded_reply=s::decode_udp_packet(key,s::UdpDirection::server,skip->wire,5000,packet.session_id);
    if (!decoded_reply || decoded_reply->session_id==packet.session_id || decoded_reply->session_id[7]!=2) return 65;
    packet.session_id[7]=2;
    if (durable_receive(collision,key,wire(),first,t,5000,restored_save).error()!=s::UdpSessionError::session_id_conflict) return 67;
    s::UdpServerSessions collision_restart(2,true);
    if (!collision_restart.restore_durable(key,{},5000,t,5000,bound,1) ||
        durable_receive(collision_restart,key,wire(),first,t,5000,restored_save).error()!=s::UdpSessionError::session_id_conflict) return 68;
    s::UdpServerSessions delayed(1,true);
    packet.session_id={9,8,7,6,5,4,3,2}; packet.packet_id=0; packet.timestamp=6000;
    auto delayed_wire=wire();
    if (!delayed.restore_durable(key,{},6000,t,6000,{},4)) return 71;
    auto late=[&]() noexcept -> std::optional<s::UdpClockSample> { return s::UdpClockSample{t+31s,6031}; };
    if (delayed.receive_durable(key,delayed_wire,first,t,6000,restored_save,late).error()!=s::UdpSessionError::packet ||
        delayed.peer(packet.session_id)) return 72;
    auto current=[&]() noexcept -> std::optional<s::UdpClockSample> { return s::UdpClockSample{t+31s,6031}; };
    packet.timestamp=6031; delayed_wire=wire();
    if (delayed.receive_durable(key,delayed_wire,first,t+31s,6031,restored_save,current).error()!=s::UdpSessionError::duplicate) return 73;
    s::UdpServerSessions reversed(1,true);
    if (!reversed.restore_durable(key,{},6000,t,6000,{},4)) return 74;
    packet.timestamp=6000; delayed_wire=wire();
    auto backwards=[&]() noexcept -> std::optional<s::UdpClockSample> { return s::UdpClockSample{t+1s,5999}; };
    if (reversed.receive_durable(key,delayed_wire,first,t,6000,restored_save,backwards).error()!=s::UdpSessionError::time_reversed ||
        reversed.receive_durable(key,delayed_wire,first,t,6000,restored_save,backwards).error()!=s::UdpSessionError::storage) return 75;
    s::UdpServerSessions boundary(1,true);
    if (!boundary.restore_durable(key,{},6000,t,6000,{},4)) return 76;
    auto edge=[&]() noexcept -> std::optional<s::UdpClockSample> { return s::UdpClockSample{t+30s,6030}; };
    if (!boundary.receive_durable(key,delayed_wire,first,t,6000,restored_save,edge)) return 77;
    s::UdpServerSessions clock_failure(1,true);
    if (!clock_failure.restore_durable(key,{},6000,t,6000,{},4)) return 78;
    auto missing=[]() noexcept -> std::optional<s::UdpClockSample> { return {}; };
    if (clock_failure.receive_durable(key,delayed_wire,first,t,6000,restored_save,missing).error()!=s::UdpSessionError::time_reversed ||
        clock_failure.receive_durable(key,delayed_wire,first,t,6000,restored_save,missing).error()!=s::UdpSessionError::storage) return 79;
    // The ID reservation can block: response timestamp and inactivity use a
    // fresh sample, and an unusable clock permanently closes the owner.
    s::UdpServerSessions response_delay(1,true);
    if (!response_delay.restore_durable(key,{},6000,t,6000,{},4) ||
        !durable_receive(response_delay,key,delayed_wire,first,t,6000,restored_save)) return 80;
    auto delayed_reply=response_delay.response_durable(key,packet.session_id,packet.address,packet.payload,{},t,6000,reserve,save_wall,late);
    if (!delayed_reply) return 81;
    auto decoded_late=s::decode_udp_packet(key,s::UdpDirection::server,delayed_reply->wire,6031,packet.session_id);
    if (!decoded_late || decoded_late->timestamp!=6031) return 82;
    if (response_delay.response_durable(key,packet.session_id,packet.address,packet.payload,{},t+31s,6031,reserve,save_wall,missing).error()!=s::UdpSessionError::time_reversed ||
        response_delay.response_durable(key,packet.session_id,packet.address,packet.payload,{},t+31s,6031,reserve,save_wall,late).error()!=s::UdpSessionError::storage) return 83;
    s::UdpServerSessions response_reverse(1,true);
    if (!response_reverse.restore_durable(key,{},6000,t,6000,{},4) ||
        !durable_receive(response_reverse,key,delayed_wire,first,t,6000,restored_save)) return 84;
    if (response_reverse.response_durable(key,packet.session_id,packet.address,packet.payload,{},t,6000,reserve,save_wall,backwards).error()!=s::UdpSessionError::time_reversed ||
        response_reverse.response_durable(key,packet.session_id,packet.address,packet.payload,{},t,6000,reserve,save_wall,edge).error()!=s::UdpSessionError::storage) return 85;
    // Durable watermarks cover the post-commit sample and prevent a restart
    // with a wall clock earlier than the time used by an emitted response.
    s::UdpServerSessions timed(1,true);
    if (!timed.restore_durable(key,{},6000,t,6000,{},4)) return 86;
    std::uint64_t stored_wall=0;
    auto store_timed=[&](auto const&, auto const&, std::uint64_t w) noexcept { stored_wall=w; return true; };
    if (!timed.receive_durable(key,delayed_wire,first,t,6000,store_timed,edge) || stored_wall!=6060) return 87;
    auto store_wall=[&](std::uint64_t w) noexcept { stored_wall=std::max(stored_wall,w); return true; };
    auto sample_later=[&]() noexcept -> std::optional<s::UdpClockSample> { return s::UdpClockSample{t+61s,6061}; };
    if (!timed.response_durable(key,packet.session_id,packet.address,packet.payload,{},t+30s,6030,reserve,store_wall,sample_later) || stored_wall!=6090) return 88;
    s::UdpServerSessions timed_restart(1,true);
    if (timed_restart.restore_durable(key,{},stored_wall,t,6089,{},4).error()!=s::UdpSessionError::time_reversed ||
        !timed_restart.restore_durable(key,{},stored_wall,t,6090,{},4)) return 89;
    s::UdpServerSessions overrun(1,true);
    if (!overrun.restore_durable(key,{},6000,t,6000,{},4)) return 90;
    if (overrun.receive_durable(key,delayed_wire,first,t,6000,store_timed,sample_later).error()!=s::UdpSessionError::time_reversed ||
        overrun.receive_durable(key,delayed_wire,first,t,6000,store_timed,edge).error()!=s::UdpSessionError::storage) return 91;
    s::UdpServerSessions wall_failure(1,true);
    if (!wall_failure.restore_durable(key,{},6000,t,6000,{},4) ||
        !durable_receive(wall_failure,key,delayed_wire,first,t,6000,store_timed)) return 92;
    auto reject_wall=[](std::uint64_t) noexcept { return false; };
    if (wall_failure.response_durable(key,packet.session_id,packet.address,packet.payload,{},t,6000,reserve,reject_wall,edge).error()!=s::UdpSessionError::storage ||
        wall_failure.response_durable(key,packet.session_id,packet.address,packet.payload,{},t,6000,reserve,store_wall,edge).error()!=s::UdpSessionError::storage) return 93;
    s::UdpServerSessions response_overrun(1,true);
    if (!response_overrun.restore_durable(key,{},6000,t,6000,{},4) ||
        !durable_receive(response_overrun,key,delayed_wire,first,t,6000,store_timed)) return 94;
    if (response_overrun.response_durable(key,packet.session_id,packet.address,packet.payload,{},t,6000,reserve,store_wall,sample_later).error()!=s::UdpSessionError::time_reversed ||
        response_overrun.response_durable(key,packet.session_id,packet.address,packet.payload,{},t,6000,reserve,store_wall,edge).error()!=s::UdpSessionError::storage) return 95;
    s::UdpServerSessions queued(1,true);
    if (!queued.restore_durable(key,{},6000,t,6000,{},4)) return 96;
    auto queued_packet=durable_receive(queued,key,delayed_wire,first,t,6000,store_timed);
    if (!queued_packet || queued.authorize_durable(*queued_packet,edge).has_value()==false ||
        timed.authorize_durable(*queued_packet,edge).error()!=s::UdpSessionError::missing) return 97;
    if (queued.authorize_durable(*queued_packet,late).error()!=s::UdpSessionError::packet || !queued.current(*queued_packet)) return 98;
    if (queued.authorize_durable(*queued_packet,sample_later).error()!=s::UdpSessionError::time_reversed ||
        queued.current(*queued_packet) || queued.authorize_durable(*queued_packet,edge).error()!=s::UdpSessionError::storage) return 99;
    std::println("SS-2022 UDP server sessions passed");
}
