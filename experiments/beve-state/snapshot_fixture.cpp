#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include "../state-owner/owner_lock.hpp"
import std;
import nexus.thirdparty.glaze;
import shadowsocks.udp_replay;
import shadowsocks.udp_sessions;
import shadowsocks.udp_packet;
import shadowsocks.udp_id_reservation;
import crypto;
namespace g=nex::glaze;
namespace s=shadowsocks;
#include "profile.hpp"

// Experimental snapshot; the caller owns a stable private directory. This is
// not a trusted or rollback-protected storage format.
struct SnapshotEntry { std::array<std::uint8_t,8> id{}; std::vector<std::uint8_t> replay; };
struct Snapshot {
    std::uint32_t version=1; std::uint64_t wall=0; std::uint64_t id_next=0; bool id_exhausted=false;
    std::vector<SnapshotEntry> sessions;
};
struct Limits : g::Context { std::size_t max_array_size=256; std::size_t max_string_length=256; };
std::array<std::uint8_t,32> mac_key{};
std::array<std::uint8_t,32> client_key{};
std::size_t client_key_size=0;
struct KeyCleanup { ~KeyCleanup() { ::crypto::cleanse(mac_key); ::crypto::cleanse(client_key); } };
bool read_private(int dir,char const* name,std::span<std::uint8_t> output,std::size_t* variable_size=nullptr) {
    int fd=::openat(dir,name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
    if (fd<0) return false;
    struct stat info{};
    if (::fstat(fd,&info)<0 || !S_ISREG(info.st_mode) || info.st_uid!=::geteuid() ||
        (info.st_mode&07777)!=0600 || info.st_nlink!=1 ||
        (variable_size ? (info.st_size!=16 && info.st_size!=32) : info.st_size!=static_cast<off_t>(output.size()))) {
        ::close(fd); return false;
    }
    auto length=static_cast<std::size_t>(info.st_size);
    if (length>output.size()) { ::close(fd); return false; }
    output=output.first(length);
    std::size_t offset=0;
    while (offset<output.size()) {
        auto n=::read(fd,output.data()+offset,output.size()-offset);
        if (n<0 && errno==EINTR) continue;
        if (n<=0) { ::close(fd); return false; }
        offset+=static_cast<std::size_t>(n);
    }
    if (::close(fd)!=0) return false;
    if (variable_size) *variable_size=length;
    return true;
}
bool derive_key(int dir) {
    std::array<std::uint8_t,32> secret{};
    std::array<std::uint8_t,16> instance{};
    bool ok=read_private(dir,"auth.key",secret) && read_private(dir,"instance.id",instance) &&
            read_private(dir,"proxy.key",client_key,&client_key_size);
    if (!ok) { ::crypto::cleanse(secret); return false; }
    constexpr std::string_view domain="nexus/beve-snapshot/v1";
    auto salt=std::span{reinterpret_cast<std::uint8_t const*>(domain.data()),domain.size()};
    auto prk=::crypto::hkdf_extract(::crypto::Hash::sha256,salt,secret);
    ::crypto::cleanse(secret);
    if (!prk) return false;
    std::array<std::uint8_t,49> context{};
    std::ranges::copy(instance,context.begin());
    context[instance.size()]=static_cast<std::uint8_t>(client_key_size);
    std::ranges::copy(std::span{client_key}.first(client_key_size),context.begin()+instance.size()+1);
    auto derived=::crypto::hkdf_expand(::crypto::Hash::sha256,*prk,
        std::span{context}.first(instance.size()+1+client_key_size),mac_key.size());
    ::crypto::cleanse(context);
    ::crypto::cleanse(*prk);
    if (!derived || derived->size()!=mac_key.size()) return false;
    std::ranges::copy(*derived,mac_key.begin()); ::crypto::cleanse(*derived);
    return true;
}

bool write_all(int fd,std::string_view bytes) {
    while (!bytes.empty()) {
        auto n=::write(fd,bytes.data(),bytes.size());
        if (n<0 && errno==EINTR) continue;
        if (n<=0) return false;
        bytes.remove_prefix(static_cast<std::size_t>(n));
    }
    return true;
}
[[noreturn]] void crash_point() { (void)::write(STDOUT_FILENO,"ready\n",6); for (;;) ::pause(); }
bool save(int dir,Snapshot const& state,int point) {
    std::string payload;
    if (g::write_beve(state,payload) || payload.size()>4096-36) return false;
    std::string frame="NXB1"; frame+=payload;
    auto bytes=std::span{reinterpret_cast<std::uint8_t const*>(frame.data()),frame.size()};
    auto mac=::crypto::hmac(::crypto::Hash::sha256,mac_key,bytes);
    if (!mac || mac->size()!=32) return false;
    frame.append(reinterpret_cast<char const*>(mac->data()),mac->size());
    // Under the exclusive owner, discard an orphan from a prior failed write.
    if (::unlinkat(dir,"next.beve",0)<0 && errno!=ENOENT) return false;
    int fd=::openat(dir,"next.beve",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if (fd<0) return false;
    bool ok;
    if (point==7) { (void)write_all(fd,std::string_view{frame}.substr(0,frame.size()/2)); ok=false; }
    else ok=write_all(fd,frame) && point!=4 && ::fsync(fd)==0;
    if (::close(fd)!=0) ok=false;
    if (!ok) return false;
    if (point==1) crash_point();
    if (point==5) return false;
    if (::renameat(dir,"next.beve",dir,"state.beve")<0) return false;
    if (point==2) crash_point();
    if (point==6) return false;
    if (::fsync(dir)<0) return false;
    if (point==3) crash_point();
    return true;
}
std::optional<Snapshot> load(int dir) {
    int fd=::openat(dir,"state.beve",O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
    if (fd<0) return {};
    struct stat info{};
    if (::fstat(fd,&info)<0 || !S_ISREG(info.st_mode) || info.st_size<=36 || info.st_size>4096) { ::close(fd); return {}; }
    std::string bytes(static_cast<std::size_t>(info.st_size),'\0');
    std::size_t offset=0;
    while (offset<bytes.size()) {
        auto n=::read(fd,bytes.data()+offset,bytes.size()-offset);
        if (n<0 && errno==EINTR) continue;
        if (n<=0) { ::close(fd); return {}; }
        offset+=static_cast<std::size_t>(n);
    }
    ::close(fd);
    if (!bytes.starts_with("NXB1")) return {};
    auto content=std::span{reinterpret_cast<std::uint8_t const*>(bytes.data()),bytes.size()-32};
    auto tag=std::span{reinterpret_cast<std::uint8_t const*>(bytes.data()+bytes.size()-32),std::size_t{32}};
    auto mac=::crypto::hmac(::crypto::Hash::sha256,mac_key,content);
    if (!mac || !::crypto::constant_time_equal(*mac,tag)) return {};
    auto payload=std::string_view{bytes}.substr(4,bytes.size()-36);
    if (!SnapshotProfile(payload).valid()) return {};
    Snapshot snapshot;
    Limits context;
    constexpr g::opts options{.error_on_unknown_keys=true,.error_on_missing_keys=true};
    auto used=g::read_beve_at<options>(snapshot,payload,0,context);
    if (!used || *used!=payload.size() || snapshot.version!=1 || snapshot.sessions.size()>16 ||
        (snapshot.id_exhausted && snapshot.id_next!=0)) return {};
    std::set<std::array<std::uint8_t,8>> ids;
    for (auto const& entry:snapshot.sessions) {
        auto decoded=s::decode_udp_replay(entry.replay);
        if (!decoded || !decoded->initialized || !ids.insert(entry.id).second) return {};
    }
    return snapshot;
}
int session_experiment(int dir) {
    auto key=std::span{client_key}.first(client_key_size);
    s::UdpPeer peer{4,{127,0,0,1},1234};
    s::UdpPacket packet{{1,2,3,4,5,6,7,8},0,1000,{}, {1,127,0,0,1,0,80},{42}};
    auto t=std::chrono::steady_clock::time_point{};
    Snapshot state{}; state.wall=1000;
    std::array<std::uint8_t,8> old_server{};
    for (unsigned round=0;round<2;++round) {
        auto now=round ? std::uint64_t{1060} : std::uint64_t{1000};
        if (round) {
            auto recovered=load(dir);
            if (!recovered || recovered->sessions.size()!=2 || recovered->wall!=1060 || recovered->id_next!=4) return 10;
            state=std::move(*recovered);
        }
        std::vector<s::UdpStoredSession> records;
        for (auto const& entry:state.sessions) {
            auto replay=s::decode_udp_replay(entry.replay);
            if (!replay) return 11;
            records.push_back({entry.id,*replay});
        }
        s::UdpServerSessions owner(2,true);
        if (!owner.restore_durable(key,records,state.wall,t,now,{state.id_next,state.id_exhausted},4)) return 12;
        auto commit=[&](auto const& id,auto const& replay,std::uint64_t wall) noexcept {
            try {
                auto bytes=s::encode_udp_replay(replay);
                if (!bytes) return false;
                auto next=state;
                auto it=std::ranges::find(next.sessions,id,&SnapshotEntry::id);
                if (it==next.sessions.end()) {
                    if (next.sessions.size()>=16) return false;
                    next.sessions.push_back({id,{}}); it=std::prev(next.sessions.end());
                }
                it->replay.assign(bytes->begin(),bytes->end()); next.wall=std::max(next.wall,wall);
                if (!save(dir,next,0)) return false;
                state=std::move(next); return true;
            } catch (...) { return false; }
        };
        auto ids=[&](s::UdpIdWatermark mark) noexcept {
            try {
                if (state.id_exhausted || (mark.exhausted && mark.next!=0) ||
                    (!mark.exhausted && mark.next<=state.id_next)) return false;
                auto next=state; next.id_next=mark.next; next.id_exhausted=mark.exhausted;
                if (!save(dir,next,0)) return false;
                state=std::move(next); return true;
            } catch (...) { return false; }
        };
        auto wall=[&](std::uint64_t value) noexcept {
            try {
                auto next=state; next.wall=std::max(next.wall,value);
                if (!save(dir,next,0)) return false;
                state=std::move(next); return true;
            } catch (...) { return false; }
        };
        auto clock=[&]() noexcept -> std::optional<s::UdpClockSample> { return s::UdpClockSample{t,now}; };
        packet.timestamp=now;
        for (std::uint8_t id:{1,9}) {
            packet.session_id[0]=id; packet.packet_id=0;
            auto wire=s::encode_udp_packet(key,s::UdpDirection::client,packet,{});
            if (!wire) return 13;
            auto received=owner.receive_durable(key,*wire,peer,t,now,commit,clock);
            if (round && (received || received.error()!=s::UdpSessionError::duplicate)) return 14;
            if (!round && !received) return 15;
            if (round) {
                packet.packet_id=1; wire=s::encode_udp_packet(key,s::UdpDirection::client,packet,{});
                if (!wire || !owner.receive_durable(key,*wire,peer,t,now,commit,clock)) return 16;
            }
        }
        packet.session_id[0]=1;
        auto reply=owner.response_durable(key,packet.session_id,packet.address,packet.payload,{},t,now,ids,wall,clock);
        if (!reply) return 17;
        auto decoded=s::decode_udp_packet(key,s::UdpDirection::server,reply->wire,now,packet.session_id);
        if (!decoded || (round && decoded->session_id==old_server)) return 18;
        old_server=decoded->session_id;
    }
    auto final=load(dir);
    return final && final->sessions.size()==2 && final->wall==1120 && final->id_next==8 ? 0 : 19;
}
int session_crash_experiment(int dir,std::string_view mode) {
    if (mode=="session-init") { Snapshot empty{}; empty.wall=1000; return save(dir,empty,0) ? 0 : 20; }
    auto stored=load(dir);
    if (!stored) return 21;
    bool verify=mode.starts_with("session-verify-");
    bool after=mode.ends_with("new");
    auto now=verify && after ? std::uint64_t{1060} : std::uint64_t{1000};
    if (verify && (stored->wall!=now || stored->sessions.size()!=(after ? 1U : 0U))) return 22;
    std::vector<s::UdpStoredSession> records;
    for (auto const& entry:stored->sessions) {
        auto replay=s::decode_udp_replay(entry.replay);
        if (!replay) return 23;
        records.push_back({entry.id,*replay});
    }
    auto t=std::chrono::steady_clock::time_point{};
    auto key=std::span{client_key}.first(client_key_size);
    s::UdpPeer peer{4,{127,0,0,1},1234};
    s::UdpPacket packet{{1,2,3,4,5,6,7,8},0,now,{}, {1,127,0,0,1,0,80},{42}};
    s::UdpServerSessions owner(2,true);
    if (!owner.restore_durable(key,records,stored->wall,t,now,{stored->id_next,stored->id_exhausted},4)) return 24;
    int point=mode=="session-before-rename" ? 1 : mode=="session-after-rename" ? 2 : mode=="session-after-sync" ? 3 :
              mode=="session-fail-file-sync" ? 4 : mode=="session-fail-rename" ? 5 : mode=="session-fail-dir-sync" ? 6 :
              mode=="session-fail-write" ? 7 : 0;
    auto commit=[&](auto const& id,auto const& replay,std::uint64_t wall) noexcept {
        try {
            auto bytes=s::encode_udp_replay(replay);
            if (!bytes) return false;
            auto next=*stored;
            next.sessions.push_back({id,{bytes->begin(),bytes->end()}});
            next.wall=std::max(next.wall,wall);
            return save(dir,next,point);
        } catch (...) { return false; }
    };
    auto clock=[&]() noexcept -> std::optional<s::UdpClockSample> { return s::UdpClockSample{t,now}; };
    auto wire=s::encode_udp_packet(key,s::UdpDirection::client,packet,{});
    if (!wire) return 25;
    auto result=owner.receive_durable(key,*wire,peer,t,now,commit,clock);
    if (mode.starts_with("session-fail-")) {
        if (result || result.error()!=s::UdpSessionError::storage || owner.peer(packet.session_id)) return 45;
        auto retry=owner.receive_durable(key,*wire,peer,t,now,commit,clock);
        return !retry && retry.error()==s::UdpSessionError::storage ? 0 : 46;
    }
    if (!verify) return 26; // injected crash points do not return
    return after ? (!result && result.error()==s::UdpSessionError::duplicate ? 0 : 27) : (result ? 0 : 28);
}
int id_crash_experiment(int dir,std::string_view mode) {
    std::array<std::uint8_t,8> client{1,2,3,4,5,6,7,8};
    if (mode=="id-init") {
        s::UdpReplayWindow window; (void)window.commit(0);
        auto replay=s::encode_udp_replay(window.snapshot());
        if (!replay) return 29;
        Snapshot initial{1,1060,0,false,{{client,{replay->begin(),replay->end()}}}};
        return save(dir,initial,0) ? 0 : 30;
    }
    auto stored=load(dir);
    if (!stored || stored->sessions.size()!=1) return 31;
    bool verify=mode.starts_with("id-verify-");
    bool after=mode.ends_with("new");
    bool ambiguous=mode=="id-ambiguous";
    if (verify && (stored->wall!=1120 || stored->id_next!=(after ? 4U : 0U))) return 32;
    auto now=verify ? std::uint64_t{1120} : std::uint64_t{1060};
    auto replay=s::decode_udp_replay(stored->sessions[0].replay);
    if (!replay) return 33;
    s::UdpStoredSession record{client,*replay};
    s::UdpServerSessions owner(1,true);
    auto t=std::chrono::steady_clock::time_point{};
    auto key=std::span{client_key}.first(client_key_size);
    if (!owner.restore_durable(key,std::span{&record,1},stored->wall,t,now,{stored->id_next,stored->id_exhausted},4)) return 34;
    auto commit=[&](auto const&,auto const& snapshot,std::uint64_t wall) noexcept {
        try {
            auto bytes=s::encode_udp_replay(snapshot); if (!bytes) return false;
            auto next=*stored; next.sessions[0].replay.assign(bytes->begin(),bytes->end()); next.wall=std::max(next.wall,wall);
            if (!save(dir,next,0)) return false;
            *stored=std::move(next); return true;
        } catch (...) { return false; }
    };
    auto clock=[&]() noexcept -> std::optional<s::UdpClockSample> { return s::UdpClockSample{t,now}; };
    s::UdpPacket packet{client,verify ? 2U : 1U,now,{}, {1,127,0,0,1,0,80},{42}};
    auto wire=s::encode_udp_packet(key,s::UdpDirection::client,packet,{});
    s::UdpPeer peer{4,{127,0,0,1},1234};
    if (!wire || !owner.receive_durable(key,*wire,peer,t,now,commit,clock)) return 35;
    int point=mode=="id-before-rename" ? 1 : mode=="id-after-rename" ? 2 : mode=="id-after-sync" ? 3 :
              mode=="id-fail-file-sync" ? 4 : mode=="id-fail-rename" ? 5 : mode=="id-fail-dir-sync" ? 6 :
              mode=="id-fail-write" ? 7 : 0;
    auto reserve=[&](s::UdpIdWatermark mark) noexcept {
        try {
            auto next=*stored; next.id_next=mark.next; next.id_exhausted=mark.exhausted;
            if (!save(dir,next,point)) return false;
            *stored=std::move(next); return !ambiguous;
        } catch (...) { return false; }
    };
    auto wall=[&](std::uint64_t value) noexcept {
        try {
            auto next=*stored; next.wall=std::max(next.wall,value);
            if (!save(dir,next,0)) return false;
            *stored=std::move(next); return true;
        } catch (...) { return false; }
    };
    auto response=owner.response_durable(key,client,packet.address,packet.payload,{},t,now,reserve,wall,clock);
    if (mode.starts_with("id-fail-")) {
        if (response || response.error()!=s::UdpSessionError::storage) return 47;
        auto retry=owner.response_durable(key,client,packet.address,packet.payload,{},t,now,reserve,wall,clock);
        return !retry && retry.error()==s::UdpSessionError::storage ? 0 : 48;
    }
    if (ambiguous) return !response && response.error()==s::UdpSessionError::storage && stored->id_next==4 ? 0 : 36;
    if (!verify || !response) return 37;
    auto decoded=s::decode_udp_packet(key,s::UdpDirection::server,response->wire,now,client);
    std::array<std::uint8_t,8> expected{}; expected[7]=after ? 4 : 0;
    return decoded && decoded->session_id==expected ? 0 : 38;
}
int benchmark(int dir) {
    Snapshot state{}; state.wall=1000;
    for (std::uint8_t i=0;i<16;++i) {
        s::UdpReplayWindow window; (void)window.commit(0);
        auto encoded=s::encode_udp_replay(window.snapshot());
        if (!encoded) return 40;
        std::array<std::uint8_t,8> id{}; id[7]=i;
        state.sessions.push_back({id,{encoded->begin(),encoded->end()}});
    }
    if (!save(dir,state,0)) return 41;
    std::vector<std::uint64_t> times;
    for (std::uint64_t i=1;i<=200;++i) {
        s::UdpReplaySnapshot replay{true,i,{}}; replay.seen[0]=1;
        auto encoded=s::encode_udp_replay(replay);
        if (!encoded) return 42;
        auto& target=state.sessions[(i-1)%state.sessions.size()];
        target.replay.assign(encoded->begin(),encoded->end()); state.wall=1000+i;
        auto start=std::chrono::steady_clock::now();
        if (!save(dir,state,0)) return 43;
        times.push_back(static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now()-start).count()));
    }
    std::ranges::sort(times);
    std::println("BEVE 16 sessions, 200 commits, microseconds: p50={} p95={} max={}",times[99],times[189],times.back());
    auto recovered=load(dir);
    return recovered && recovered->sessions.size()==16 && recovered->wall==1200 ? 0 : 44;
}
int main(int argc,char** argv) {
    if (argc!=3) return 1;
    auto [lock,error]=OwnerLock::acquire(argv[1]);
    if (error) return 2;
    int dir=lock.directory_fd();
    KeyCleanup cleanup;
    if (!derive_key(dir)) return 39;
    std::string_view mode=argv[2];
    if (mode=="bench") return benchmark(dir);
    if (mode=="session") return session_experiment(dir);
    if (mode.starts_with("session-")) return session_crash_experiment(dir,mode);
    if (mode.starts_with("id-")) return id_crash_experiment(dir,mode);
    if (mode=="verify-old" || mode=="verify-new") {
        auto state=load(dir);
        if (!state || state->wall!=(mode=="verify-old" ? 1000U : 1060U)) return 4;
        if (state->sessions.size()!=1) return 4;
        auto replay=s::decode_udp_replay(state->sessions[0].replay);
        s::UdpReplayWindow window;
        if (!replay || !window.restore(*replay) || window.check(0)!=s::UdpReplayResult::duplicate ||
            window.check(1)!=(mode=="verify-old" ? s::UdpReplayResult::fresh : s::UdpReplayResult::duplicate)) return 5;
        return 0;
    }
    s::UdpReplayWindow window;
    (void)window.commit(0);
    if (mode!="init") (void)window.commit(1);
    auto encoded=s::encode_udp_replay(window.snapshot());
    if (!encoded) return 6;
    Snapshot state{1,mode=="init" ? 1000U : 1060U,0,false,{{{}, {encoded->begin(),encoded->end()}}}};
    int point=mode=="before-rename" ? 1 : mode=="after-rename" ? 2 : mode=="after-sync" ? 3 : 0;
    bool ok=save(dir,state,point);
    return ok && (mode=="init" || mode=="update") ? 0 : 7;
}
