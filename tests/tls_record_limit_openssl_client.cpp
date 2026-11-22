#include <unistd.h>
#include <errno.h>
import std;
import tls.profiles;
import tls.fingerprint;
import tls.client_handshake_io;
namespace t=tls;namespace c = ::crypto;using Bytes=c::Bytes;
auto transfer(bool writing,std::span<std::uint8_t> bytes) -> bool {
    while(!bytes.empty()){auto n=writing ? ::write(1,bytes.data(),bytes.size()) : ::read(0,bytes.data(),bytes.size());
        if(n<0 && errno==EINTR)continue;if(n<=0)return false;bytes=bytes.subspan(static_cast<std::size_t>(n));}return true;
}
auto read_record() -> std::optional<Bytes> {
    Bytes record(5);if(!transfer(false,record))return {};auto n=(std::size_t{record[3]}<<8)|record[4];if(n>16640)return {};
    record.resize(5+n);if(!transfer(false,std::span(record).subspan(5)))return {};return record;
}
int main(int argc,char** argv) {
    if(argc!=3)return 1;bool failure=std::string_view(argv[2])!="valid";bool overflow=std::string_view(argv[2])=="overflow";
    auto profile=t::ClientProfile::load("localhost",argv[1]);if(!profile)return 2;
    t::FingerprintConfig config;config.profile=t::Fingerprint::tls13_randomized;config.record_size_limit=overflow ? 64 : 1024;
    auto now=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    auto client=profile->handshake(0,1000,now,config);if(!client)return 3;
    auto flush=[&]() -> bool {while(!client->pending_output().empty()){
        auto chunk=client->pending_output().first(std::min<std::size_t>(13,client->pending_output().size()));
        Bytes owned(chunk.begin(),chunk.end());if(!transfer(true,owned))return false;
        if(!client->written(owned.size(),0))return false;}return true;};
    if(!flush())return 4;
    while(!client->complete()){
        auto record=read_record();if(!record)return 5;std::size_t offset=0;
        while(offset<record->size()){
            auto result=client->feed(std::span(*record).subspan(offset),0);if(!result || !result->consumed)return 6;
            offset+=result->consumed;
            if(!client->pending_output().empty() && !flush())return failure ? 0 : 7;
        }
    }
    if(failure)return 8;auto selected=client->negotiated();
    if(!selected || selected->peer_record_size_limit!=512)return 9;
    auto records=client->take_application_records();if(!records || records->max_write_size()!=511)return 10;
    Bytes payload(2048);for(std::size_t i=0;i<payload.size();++i)payload[i]=static_cast<std::uint8_t>(i);
    for(std::size_t offset=0;offset<payload.size();){auto n=std::min(records->max_write_size(),payload.size()-offset);
        auto wire=records->seal(std::span(payload).subspan(offset,n));if(!wire || !transfer(true,*wire))return 11;offset+=n;}
    Bytes echoed;bool closed=false;
    while(!closed){auto wire=read_record();if(!wire)return 12;auto event=records->open_event(*wire);if(!event)return 13;
        if(event->kind==t::ApplicationEventKind::data)echoed.insert(echoed.end(),event->data.begin(),event->data.end());
        else if(event->kind==t::ApplicationEventKind::close_notify)closed=true;
        else if(event->kind!=t::ApplicationEventKind::ticket_discarded && event->kind!=t::ApplicationEventKind::handshake_fragment)return 14;
        if(echoed.size()>payload.size())return 15;
    }
    if(echoed!=payload || !records->finish_input())return 16;auto close=records->close_notify();if(!close || !transfer(true,*close))return 17;
}
