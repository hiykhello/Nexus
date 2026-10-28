#include <sqlite3.h>
#include <unistd.h>
#include "../state-owner/owner_lock.hpp"
import std;
import nexus.shadowsocks.udp_sessions;
import nexus.shadowsocks.udp_packet;
import nexus.shadowsocks.udp_replay;
import nexus.shadowsocks.udp_id_reservation;
namespace s=nexus::shadowsocks;

// A test fixture with multiple sessions and full-width watermarks, not a
// production store. Transactions use the real session callbacks.
struct Store {
    sqlite3* db=nullptr;
    explicit Store(char const* path) {
        if (sqlite3_open(path,&db)!=SQLITE_OK) std::abort();
        exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;"
             "CREATE TABLE IF NOT EXISTS state(id INTEGER PRIMARY KEY, wall BLOB NOT NULL CHECK(typeof(wall)='blob' AND length(wall)=8), ids BLOB NOT NULL CHECK(typeof(ids)='blob' AND length(ids)=9));"
             "CREATE TABLE IF NOT EXISTS sessions(id BLOB PRIMARY KEY, snapshot BLOB NOT NULL);"
             "INSERT OR IGNORE INTO state VALUES(1,X'00000000000003e8',X'000000000000000000');");
    }
    ~Store() { sqlite3_close(db); }
    void exec(char const* sql) { if (sqlite3_exec(db,sql,nullptr,nullptr,nullptr)!=SQLITE_OK) std::abort(); }
    static void crash_point() noexcept {
        (void)::write(STDOUT_FILENO,"ready\n",6);
        for (;;) ::pause();
    }
    bool save(std::array<std::uint8_t,8> const& id,s::UdpReplaySnapshot const& snapshot,std::uint64_t wall,bool fail=false,int crash=0) noexcept {
        auto encoded=s::encode_udp_replay(snapshot);
        if (!encoded) return false;
        if (sqlite3_exec(db,"BEGIN IMMEDIATE",nullptr,nullptr,nullptr)!=SQLITE_OK) return false;
        sqlite3_stmt* st=nullptr;
        bool ok=sqlite3_prepare_v2(db,"INSERT INTO sessions VALUES(?,?) ON CONFLICT(id) DO UPDATE SET snapshot=excluded.snapshot",-1,&st,nullptr)==SQLITE_OK;
        if (ok) ok=sqlite3_bind_blob(st,1,id.data(),id.size(),SQLITE_TRANSIENT)==SQLITE_OK &&
                   sqlite3_bind_blob(st,2,encoded->data(),encoded->size(),SQLITE_TRANSIENT)==SQLITE_OK && sqlite3_step(st)==SQLITE_DONE;
        sqlite3_finalize(st);
        if (ok && !fail) ok=update("UPDATE state SET wall=max(wall,?) WHERE id=1",wall);
        if (!ok || fail) { sqlite3_exec(db,"ROLLBACK",nullptr,nullptr,nullptr); return false; }
        if (crash==1) crash_point();
        auto committed=sqlite3_exec(db,"COMMIT",nullptr,nullptr,nullptr)==SQLITE_OK;
        if (committed && crash==2) crash_point();
        return committed;
    }
    static std::array<std::uint8_t,8> bytes(std::uint64_t value) noexcept {
        std::array<std::uint8_t,8> out{};
        for (std::size_t i=0;i<out.size();++i) out[i]=static_cast<std::uint8_t>(value>>(56-8*i));
        return out;
    }
    static std::uint64_t value(std::span<std::uint8_t const,8> bytes) noexcept {
        std::uint64_t out=0;
        for (auto byte:bytes) out=(out<<8)|byte;
        return out;
    }
    bool update(char const* sql,std::uint64_t value) noexcept {
        auto data=bytes(value);
        sqlite3_stmt* st=nullptr;
        bool ok=sqlite3_prepare_v2(db,sql,-1,&st,nullptr)==SQLITE_OK;
        if (ok) ok=sqlite3_bind_blob(st,1,data.data(),data.size(),SQLITE_TRANSIENT)==SQLITE_OK && sqlite3_step(st)==SQLITE_DONE;
        sqlite3_finalize(st); return ok;
    }
    bool reserve(s::UdpIdWatermark mark,int crash=0) noexcept {
        if (mark.exhausted && mark.next!=0) return false;
        if (sqlite3_exec(db,"BEGIN IMMEDIATE",nullptr,nullptr,nullptr)!=SQLITE_OK) return false;
        std::array<std::uint8_t,9> data{};
        data[0]=mark.exhausted ? 1 : 0;
        auto number=bytes(mark.next); std::ranges::copy(number,data.begin()+1);
        sqlite3_stmt* st=nullptr;
        bool ok=sqlite3_prepare_v2(db,"UPDATE state SET ids=?1 WHERE id=1 AND ids<?1",-1,&st,nullptr)==SQLITE_OK;
        if (ok) ok=sqlite3_bind_blob(st,1,data.data(),data.size(),SQLITE_TRANSIENT)==SQLITE_OK &&
                   sqlite3_step(st)==SQLITE_DONE && sqlite3_changes(db)==1;
        sqlite3_finalize(st);
        if (!ok) { sqlite3_exec(db,"ROLLBACK",nullptr,nullptr,nullptr); return false; }
        if (crash==1) crash_point();
        auto committed=sqlite3_exec(db,"COMMIT",nullptr,nullptr,nullptr)==SQLITE_OK;
        if (committed && crash==2) crash_point();
        return committed;
    }
    struct State { std::vector<s::UdpStoredSession> records; std::uint64_t wall; s::UdpIdWatermark ids; };
    State read() {
        sqlite3_stmt* st=nullptr;
        if (sqlite3_prepare_v2(db,"SELECT wall,ids FROM state WHERE id=1",-1,&st,nullptr)!=SQLITE_OK ||
            sqlite3_step(st)!=SQLITE_ROW) std::abort();
        if (sqlite3_column_type(st,0)!=SQLITE_BLOB || sqlite3_column_bytes(st,0)!=8 ||
            sqlite3_column_type(st,1)!=SQLITE_BLOB || sqlite3_column_bytes(st,1)!=9) std::abort();
        auto wallbytes=static_cast<std::uint8_t const*>(sqlite3_column_blob(st,0));
        auto idbytes=static_cast<std::uint8_t const*>(sqlite3_column_blob(st,1));
        auto wall=value(std::span<std::uint8_t const,8>{wallbytes,8});
        auto next=value(std::span<std::uint8_t const,8>{idbytes+1,8});
        if (idbytes[0]>1 || (idbytes[0]==1 && next!=0)) std::abort();
        s::UdpIdWatermark ids{next,idbytes[0]==1};
        sqlite3_finalize(st);
        State state{{},wall,ids};
        if (sqlite3_prepare_v2(db,"SELECT id,snapshot FROM sessions ORDER BY id",-1,&st,nullptr)!=SQLITE_OK) std::abort();
        int status;
        while ((status=sqlite3_step(st))==SQLITE_ROW) {
            if (state.records.size()>=16 || sqlite3_column_bytes(st,0)!=8 ||
                sqlite3_column_bytes(st,1)!=s::udp_replay_encoded_size) std::abort();
            s::UdpStoredSession record{};
            std::memcpy(record.id.data(),sqlite3_column_blob(st,0),record.id.size());
            auto bytes=std::span{static_cast<std::uint8_t const*>(sqlite3_column_blob(st,1)),s::udp_replay_encoded_size};
            auto snapshot=s::decode_udp_replay(bytes);
            if (!snapshot || !snapshot->initialized) std::abort();
            record.replay=*snapshot; state.records.push_back(record);
        }
        if (status!=SQLITE_DONE) std::abort();
        sqlite3_finalize(st); return state;
    }

};
int benchmark(Store& db) {
    for (std::uint8_t i=0;i<16;++i) {
        std::array<std::uint8_t,8> id{}; id[7]=i;
        s::UdpReplaySnapshot replay{true,0,{}}; replay.seen[0]=1;
        if (!db.save(id,replay,1000)) return 40;
    }
    std::vector<std::uint64_t> times;
    for (std::uint64_t i=1;i<=200;++i) {
        std::array<std::uint8_t,8> id{}; id[7]=static_cast<std::uint8_t>((i-1)%16);
        s::UdpReplaySnapshot replay{true,i,{}}; replay.seen[0]=1;
        auto start=std::chrono::steady_clock::now();
        if (!db.save(id,replay,1000+i)) return 41;
        times.push_back(static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now()-start).count()));
    }
    std::ranges::sort(times);
    std::println("SQLite 16 sessions, 200 commits, microseconds: p50={} p95={} max={}",times[99],times[189],times.back());
    auto state=db.read();
    return state.records.size()==16 && state.wall==1200 ? 0 : 42;
}
int main(int argc,char** argv) {
    if (argc!=2 && argc!=3) return 1;
    auto directory=std::filesystem::path(argv[1]).parent_path();
    if (directory.empty()) directory=".";
    auto [owner_lock,lock_error]=OwnerLock::acquire(directory.c_str());
    if (lock_error) return lock_error==EWOULDBLOCK ? 35 : 36;
    if (argc==3 && std::string_view{argv[2]}=="hold-owner") {
        Store db(argv[1]);
        Store::crash_point();
    }
    if (argc==3 && std::string_view{argv[2]}=="bench") { Store db(argv[1]); return benchmark(db); }
    using namespace std::chrono_literals;
    std::array<std::uint8_t,16> key{}; std::iota(key.begin(),key.end(),0);
    s::UdpPeer peer{4,{127,0,0,1},1234};
    s::UdpPacket packet{{1,2,3,4,5,6,7,8},0,1000,{}, {1,127,0,0,1,0,80},{42}};
    auto t=std::chrono::steady_clock::time_point{};
    auto wire=*s::encode_udp_packet(key,s::UdpDirection::client,packet,{});
    if (argc==3) {
        std::string_view mode=argv[2];
        Store db(argv[1]);
        auto state=db.read();
        if (mode.starts_with("crash-id-") || mode.starts_with("verify-id-") || mode=="ambiguous-id") {
            bool verify=mode.starts_with("verify-id-");
            bool ambiguous=mode=="ambiguous-id";
            bool after=mode.ends_with("after");
            auto now=verify ? std::uint64_t{1060} : std::uint64_t{1000};
            if (verify && (state.records.size()!=1 || state.wall!=1060 ||
                state.ids!=s::UdpIdWatermark{after ? 4U : 0U,false})) return 29;
            s::UdpServerSessions owner(2,true);
            if (!owner.restore_durable(key,state.records,state.wall,t,now,state.ids,4)) return 30;
            packet.timestamp=now; packet.packet_id=verify ? 1 : 0;
            wire=*s::encode_udp_packet(key,s::UdpDirection::client,packet,{});
            auto save=[&](auto const& id,auto const& snapshot,std::uint64_t wall) noexcept { return db.save(id,snapshot,wall); };
            auto clock=[&]() noexcept -> std::optional<s::UdpClockSample> { return s::UdpClockSample{t,now}; };
            if (!owner.receive_durable(key,wire,peer,t,now,save,clock)) return 31;
            auto reserve=[&](s::UdpIdWatermark mark) noexcept {
                auto written=db.reserve(mark,(verify || ambiguous) ? 0 : after ? 2 : 1);
                return ambiguous ? false : written;
            };
            auto wall=[&](std::uint64_t value) noexcept { return db.update("UPDATE state SET wall=max(wall,?) WHERE id=1",value); };
            auto response=owner.response_durable(key,packet.session_id,packet.address,packet.payload,{},t,now,reserve,wall,clock);
            if (ambiguous) return !response && response.error()==s::UdpSessionError::storage &&
                db.read().ids==s::UdpIdWatermark{4,false} ? 0 : 34;
            if (!verify || !response) return 32;
            auto decoded=s::decode_udp_packet(key,s::UdpDirection::server,response->wire,now,packet.session_id);
            if (!decoded || Store::value(decoded->session_id)!=(after ? 4U : 0U)) return 33;
            return 0;
        }
        auto now=mode=="verify-after" ? std::uint64_t{1060} : std::uint64_t{1000};
        if ((mode=="verify-after" && (state.records.size()!=1 || state.wall!=1060)) ||
            (mode=="verify-before" && (!state.records.empty() || state.wall!=1000))) return 24;
        s::UdpServerSessions owner(2,true);
        if (!owner.restore_durable(key,state.records,state.wall,t,now,state.ids,4)) return 25;
        packet.timestamp=now;
        wire=*s::encode_udp_packet(key,s::UdpDirection::client,packet,{});
        int crash=mode=="crash-before" ? 1 : mode=="crash-after" ? 2 : 0;
        auto save=[&](auto const& id,auto const& snapshot,std::uint64_t wall) noexcept { return db.save(id,snapshot,wall,false,crash); };
        auto clock=[&]() noexcept -> std::optional<s::UdpClockSample> { return s::UdpClockSample{t,now}; };
        auto result=owner.receive_durable(key,wire,peer,t,now,save,clock);
        if (mode=="verify-before") return result ? 0 : 26;
        if (mode=="verify-after") return !result && result.error()==s::UdpSessionError::duplicate ? 0 : 27;
        return 28; // crash modes must block in the callback
    }
    std::array<std::uint8_t,8> server_id{};
    {
        Store db(argv[1]); s::UdpServerSessions owner(2,true);
        if (!owner.restore_durable(key,{},1000,t,1000,{},4)) return 2;
        auto save=[&](auto const& id,auto const& snapshot,std::uint64_t wall) noexcept { return db.save(id,snapshot,wall); };
        auto clock=[&]() noexcept -> std::optional<s::UdpClockSample> { return s::UdpClockSample{t,1000}; };
        auto accepted=owner.receive_durable(key,wire,peer,t,1000,save,clock);
        if (!accepted || !owner.authorize_durable(*accepted,clock)) return 3;
        auto other=packet; other.session_id[0]=9;
        auto other_wire=*s::encode_udp_packet(key,s::UdpDirection::client,other,{});
        if (!owner.receive_durable(key,other_wire,peer,t,1000,save,clock)) return 12;
        auto ids=[&](s::UdpIdWatermark mark) noexcept { return db.reserve(mark); };
        auto wall=[&](std::uint64_t value) noexcept { return db.update("UPDATE state SET wall=max(wall,?) WHERE id=1",value); };
        auto response=owner.response_durable(key,packet.session_id,packet.address,packet.payload,{},t,1000,ids,wall,clock);
        if (!response) return 4;
        auto decoded=s::decode_udp_packet(key,s::UdpDirection::server,response->wire,1000,packet.session_id);
        if (!decoded) return 5;
        server_id=decoded->session_id;
    }
    {
        Store db(argv[1]); auto [records,watermark,idmark]=db.read();
        s::UdpServerSessions owner(2,true);
        if (watermark!=1060 || idmark!=s::UdpIdWatermark{4,false} || records.size()!=2 || !owner.restore_durable(key,records,watermark,t,1060,idmark,4)) return 6;
        auto save=[&](auto const& id,auto const& next,std::uint64_t wall) noexcept { return db.save(id,next,wall); };
        auto clock=[&]() noexcept -> std::optional<s::UdpClockSample> { return s::UdpClockSample{t,1060}; };
        packet.timestamp=1060;
        auto repeated=*s::encode_udp_packet(key,s::UdpDirection::client,packet,{});
        if (owner.receive_durable(key,repeated,peer,t,1060,save,clock).error()!=s::UdpSessionError::duplicate) return 7;
        auto other=packet; other.session_id[0]=9;
        auto other_wire=*s::encode_udp_packet(key,s::UdpDirection::client,other,{});
        if (owner.receive_durable(key,other_wire,peer,t,1060,save,clock).error()!=s::UdpSessionError::duplicate) return 13;
        other.packet_id=1;
        other_wire=*s::encode_udp_packet(key,s::UdpDirection::client,other,{});
        if (!owner.receive_durable(key,other_wire,peer,t,1060,save,clock)) return 14;
        packet.packet_id=1;
        auto next=*s::encode_udp_packet(key,s::UdpDirection::client,packet,{});
        if (!owner.receive_durable(key,next,peer,t,1060,save,clock)) return 8;
        auto ids=[&](s::UdpIdWatermark mark) noexcept { return db.reserve(mark); };
        auto wall=[&](std::uint64_t value) noexcept { return db.update("UPDATE state SET wall=max(wall,?) WHERE id=1",value); };
        auto response=owner.response_durable(key,packet.session_id,packet.address,packet.payload,{},t,1060,ids,wall,clock);
        if (!response) return 9;
        auto decoded=s::decode_udp_packet(key,s::UdpDirection::server,response->wire,1060,packet.session_id);
        if (!decoded || decoded->session_id==server_id) return 10;
        auto before=db.read();
        auto failure=[&](auto const& id,auto const& next_state,std::uint64_t wall_time) noexcept { return db.save(id,next_state,wall_time,true); };
        packet.packet_id=2; packet.timestamp=1061;
        auto failwire=*s::encode_udp_packet(key,s::UdpDirection::client,packet,{});
        auto later=[&]() noexcept -> std::optional<s::UdpClockSample> { return s::UdpClockSample{t+1s,1061}; };
        if (owner.receive_durable(key,failwire,peer,t+1s,1061,failure,later).error()!=s::UdpSessionError::storage) return 11;
        auto after=db.read();
        if (after.wall!=before.wall || after.ids!=before.ids || after.records.size()!=before.records.size()) return 15;
        for (std::size_t i=0;i<before.records.size();++i)
            if (after.records[i].id!=before.records[i].id || after.records[i].replay!=before.records[i].replay) return 16;
    }
    {
        Store db(argv[1]); auto state=db.read();
        if (state.records.size()!=2 || state.wall!=1120 || state.ids!=s::UdpIdWatermark{8,false}) return 17;
        for (auto const& record:state.records) {
            s::UdpReplayWindow replay;
            if (!replay.restore(record.replay) || replay.check(0)!=s::UdpReplayResult::duplicate ||
                replay.check(1)!=s::UdpReplayResult::duplicate || replay.check(2)!=s::UdpReplayResult::fresh) return 18;
        }
        constexpr auto maximum=std::numeric_limits<std::uint64_t>::max();
        if (!db.update("UPDATE state SET wall=max(wall,?) WHERE id=1",maximum) ||
            !db.update("UPDATE state SET wall=max(wall,?) WHERE id=1",0) ||
            !db.reserve({maximum,false}) || db.reserve({maximum-1,false}) ||
            db.reserve({maximum,false}) || db.reserve({1,true})) return 19;
        auto allocator=s::UdpIdReservation::create({maximum,false},4);
        auto commit=[&](s::UdpIdWatermark mark) noexcept { return db.reserve(mark); };
        if (!allocator) return 22;
        auto last=(*allocator)->take(commit);
        if (!last || *last!=maximum || (*allocator)->take(commit).error()!=s::UdpIdError::exhausted ||
            db.reserve({maximum,false}) || db.reserve({0,true})) return 23;
    }
    {
        Store db(argv[1]); auto state=db.read();
        if (state.wall!=std::numeric_limits<std::uint64_t>::max() || state.ids!=s::UdpIdWatermark{0,true}) return 20;
        auto allocator=s::UdpIdReservation::create(state.ids,4);
        auto commit=[](s::UdpIdWatermark) noexcept { return true; };
        if (!allocator || (*allocator)->take(commit).error()!=s::UdpIdError::exhausted) return 21;
    }
    std::println("SQLite {} session callback and reopen experiment passed",sqlite3_libversion());
}
