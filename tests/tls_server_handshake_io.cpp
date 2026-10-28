import std;
import nexus.tls.server_handshake_io;
import nexus.tls.client_keys;
import nexus.tls.handshake;
import nexus.tls.key_share;
import nexus.tls.server_hello;
static thread_local int fail_after=-1;
static void* watched_hello=nullptr;
static void* watched_flight=nullptr;
static bool hello_released=false, flight_released=false;
void* operator new(std::size_t size) {
    if (fail_after==0) { fail_after=-1; throw std::bad_alloc{}; }
    if (fail_after>0) --fail_after;
    if (auto p=std::malloc(size ? size : 1)) return p;
    throw std::bad_alloc{};
}
void operator delete(void* p) noexcept {
    if (p && p==watched_hello) { hello_released=true; watched_hello=nullptr; }
    if (p && p==watched_flight) { flight_released=true; watched_flight=nullptr; }
    std::free(p);
}
void operator delete(void* p,std::size_t) noexcept { ::operator delete(p); }
namespace t=nexus::tls; namespace c=nexus::crypto;
auto read_file(char const* p) -> c::Bytes { std::ifstream in(p,std::ios::binary); return {std::istreambuf_iterator<char>(in),{}}; }
int main(int argc,char** argv) {
    if (argc<3 || argc>5) return 1; auto cert=read_file(argv[1]), priv=read_file(argv[2]);
    auto credential=[&] { return t::ServerCredential::create(cert,priv); };
    auto check_limit=[](t::ServerCredential&& cred) {
        auto size=cred.certificate().size()+5;
        for (auto const& item:cred.chain()) size+=item.size()+5;
        fail_after=0;
        auto rejected=t::ServerHandshakeIo::create(std::move(cred),1,100,{},size-1);
        auto no_allocation=fail_after==0; fail_after=-1;
        if (!no_allocation || rejected || rejected.error()!=t::ServerHandshakeIoError::certificate_limit || !cred.scheme()) return false;
        auto zero=t::ServerHandshakeIo::create(std::move(cred),1,100,{},0);
        if (zero || zero.error()!=t::ServerHandshakeIoError::certificate_limit || !cred.scheme()) return false;
        auto accepted=t::ServerHandshakeIo::create(std::move(cred),1,100,{},size);
        return accepted.has_value() && !cred.scheme();
    };
    auto limited=credential(); if (!limited || !check_limit(std::move(*limited))) return 69;
    if (argc==5) {
        auto chain=t::ServerCredential::create_file_contents(read_file(argv[4]),priv);
        if (!chain || chain->chain().size()!=1 || !check_limit(std::move(*chain))) return 70;
    }
    auto creds=credential(); if (!creds) return 2;
    auto scheme=*creds->scheme(); auto handshake_budget=std::make_shared<nexus::memory::Budget>(4*1024*1024);
    auto server=t::ServerHandshakeIo::create(std::move(*creds),100,1000,"h2",t::ServerCredential::max_certificate_list_size,handshake_budget); if (!server) return 3;
    if (server->tick(99).error()!=t::ServerHandshakeIoError::time_reversed || server->take_application_records()) return 4;
    auto key=c::X25519Private::generate(); if (!key) return 5; auto pub=key->public_key(); if (!pub) return 6;
    auto share=t::KeyShare::encode_client(std::array{t::KeyShareEntry{29,{pub->begin(),pub->end()}}}); if (!share) return 7;
    t::ClientHello hello; hello.cipher_suites={0x1301}; hello.compression_methods={0};
    hello.extensions={{43,{2,3,4}},{10,{0,2,0,29}},{13,{0,2,static_cast<std::uint8_t>(scheme>>8),static_cast<std::uint8_t>(scheme)}},{51,*share},{16,{0,12,2,'h','2',8,'h','t','t','p','/','1','.','1'}}};
    auto body=hello.encode(); auto wire=t::HandshakeDecoder::encode(1,*body); if (!body || !wire) return 8;
    c::Bytes input{22,3,1,static_cast<std::uint8_t>(wire->size()>>8),static_cast<std::uint8_t>(wire->size())}; input.insert(input.end(),wire->begin(),wire->end());
    auto small_credential=credential(); auto small_budget=std::make_shared<nexus::memory::Budget>(t::ServerHandshakeIo::hello_input_charge-1);
    if (!small_credential) return 71;
    auto small=t::ServerHandshakeIo::create(std::move(*small_credential),1,100,"h2",t::ServerCredential::max_certificate_list_size,small_budget);
    if (small || small.error()!=t::ServerHandshakeIoError::budget_exceeded || !small_credential->scheme() || small_budget->reserved()) return 72;
    small_budget=std::make_shared<nexus::memory::Budget>(t::ServerHandshakeIo::hello_input_charge);
    small=t::ServerHandshakeIo::create(std::move(*small_credential),1,100,"h2",t::ServerCredential::max_certificate_list_size,small_budget);
    if (!small || small_budget->reserved()!=t::ServerHandshakeIo::hello_input_charge) return 81;
    auto denied=small->feed(input,2);
    if (denied || denied.error()!=t::ServerHandshakeIoError::budget_exceeded || small_budget->reserved() || small->tick(2)) return 73;
    int failures=0; bool success=false;
    for (int index=0;index<256;++index) {
        auto c=credential(); if (!c) return 62;
        auto fault_budget=std::make_shared<nexus::memory::Budget>(4*1024*1024);
        auto candidate=t::ServerHandshakeIo::create(std::move(*c),1,100,"h2",t::ServerCredential::max_certificate_list_size,fault_budget); if (!candidate) return 63;
        bool threw=false; fail_after=index;
        try { auto result=candidate->feed(input,2); if (result && !candidate->pending_output().empty()) success=true; }
        catch (std::bad_alloc const&) { threw=true; }
        fail_after=-1;
        if (threw) {
            ++failures; auto again=candidate->feed(input,2);
            if (again || again.error()!=t::ServerHandshakeIoError::invalid_state || !candidate->pending_output().empty() || candidate->tick(2) || candidate->take_application_records() || fault_budget->reserved()) return 64;
        } else if (success) break;
    }
    if (failures<5 || !success) return 65;
    for (auto byte:input) { auto result=server->feed(std::span{&byte,1},101); if (!result || result->consumed!=1) return 9; }
    if (server->pending_output().empty() || server->feed(input,102)->consumed!=0 || server->take_application_records()) return 10;
    auto output_credential=credential(); auto output_budget=std::make_shared<nexus::memory::Budget>(t::ServerHandshakeIo::hello_input_charge+server->pending_output().size());
    if (!output_credential) return 76;
    auto output_limited=t::ServerHandshakeIo::create(std::move(*output_credential),1,100,"h2",t::ServerCredential::max_certificate_list_size,output_budget);
    if (!output_limited) return 77;
    auto output_denied=output_limited->feed(input,2);
    if (output_denied || output_denied.error()!=t::ServerHandshakeIoError::budget_exceeded || output_budget->reserved()) return 78;
    for (bool deny_input:{false,true}) {
        auto input_credential=credential(); auto input_budget=std::make_shared<nexus::memory::Budget>(4*1024*1024);
        if (!input_credential) return 83;
        auto candidate=t::ServerHandshakeIo::create(std::move(*input_credential),1,100,"h2",t::ServerCredential::max_certificate_list_size,input_budget);
        if (!candidate || !candidate->feed(input,2)) return 84;
        while (!candidate->pending_output().empty()) if (!candidate->written(candidate->pending_output().size(),2)) return 85;
        std::optional<nexus::memory::Budget::Reservation> blocker;
        if (deny_input) blocker=nexus::memory::Budget::reserve(input_budget,input_budget->limit()-t::ServerHandshakeIo::finished_input_charge+1);
        std::uint8_t first=23; auto part=candidate->feed(std::span{&first,1},3);
        if (deny_input) {
            if (!blocker || part || part.error()!=t::ServerHandshakeIoError::budget_exceeded || input_budget->reserved()!=blocker->size()) return 86;
        } else if (!part || input_budget->reserved()!=t::ServerHandshakeIo::finished_input_charge || !candidate->cancel() || input_budget->reserved()) return 87;
    }
    if (server->written(server->pending_output().size()+1,102).error()!=t::ServerHandshakeIoError::invalid_argument) return 11;
    watched_hello=const_cast<std::uint8_t*>(server->pending_output().data());
    std::vector<c::Bytes> records;
    while (!server->pending_output().empty()) {
        if (records.size()==1) watched_flight=const_cast<std::uint8_t*>(server->pending_output().data());
        auto held_before=handshake_budget->reserved();
        c::Bytes record;
        while (!server->pending_output().empty()) {
            auto bytes=server->pending_output(); auto n=std::min(bytes.size(),std::size_t{7}); record.insert(record.end(),bytes.begin(),bytes.begin()+n);
            if (!server->written(n,103)) return 12;
            if (records.size()==1 && n<bytes.size() && flight_released) return 68;
            if (n<bytes.size() && handshake_budget->reserved()!=held_before) return 74;
            if (record.size()>=5 && record.size()==5+((std::size_t{record[3]}<<8)|record[4])) break;
        }
        if (held_before<record.size() || handshake_budget->reserved()!=held_before-record.size()) return 75;
        records.push_back(std::move(record));
    }
    if (records.size()<(argc>=4 ? 3u : 2u) || records[0].size()<6 || !hello_released || !flight_released || watched_flight || handshake_budget->reserved()) return 13;
    auto client=t::client_handshake_keys(*wire,std::span{records[0]}.subspan(5),std::move(*key)); if (!client) return 14;
    auto decoder=t::HandshakeDecoder::create(1048584); if (!decoder) return 15; bool server_finished=false, alpn_seen=false;
    for (std::size_t i=1;i<records.size();++i) {
        auto plain=client->read.open(records[i]); if (!plain) return 16;
        auto messages=decoder->feed(plain->content); if (!messages) return 17;
        for (auto const& msg:*messages) {
            auto encoded=t::HandshakeDecoder::encode(msg.type,msg.body,1048584); if (!encoded) return 18;
            if (msg.type==8) {
                alpn_seen=msg.body==c::Bytes{0,9,0,16,0,5,0,3,2,'h','2'};
            }
            if (msg.type==20) {
                auto hash=client->transcript.snapshot(); auto expected=t::finished_verify_data(client->hash,client->server_traffic.view(),*hash);
                if (!expected || !c::constant_time_equal(expected->view(),msg.body)) return 19; server_finished=true;
            }
            if (!client->transcript.append(*encoded)) return 20;
        }
    }
    if (!server_finished || !alpn_seen) return 21;
    auto hash=client->transcript.snapshot(); auto verify=t::finished_verify_data(client->hash,client->client_traffic.view(),*hash);
    if (!verify) return 22; auto finished=t::HandshakeDecoder::encode(20,verify->view()); if (!finished) return 23;
    auto a=client->write.seal(t::ContentType::handshake,std::span{*finished}.first(3));
    auto b=client->write.seal(t::ContentType::handshake,std::span{*finished}.subspan(3)); if (!a || !b) return 24;
    c::Bytes ccs{20,3,3,0,1,1}; for (auto const* record:{&ccs,&*a,&*b}) for (std::size_t i=0;i<record->size();++i) {
        auto byte=(*record)[i]; auto result=server->feed(std::span{&byte,1},104); if (!result || result->consumed!=1) return 25;
        auto expected=i+1==record->size() ? 0 : t::ServerHandshakeIo::finished_input_charge;
        if (handshake_budget->reserved()!=expected) return 82;
    }
    if (!server->complete() || server->feed(input,105)->consumed!=0 ||
        !std::ranges::equal(server->negotiated_alpn(),c::Bytes{'h','2'})) return 26;
    auto app=server->take_application_records(); if (!app || server->take_application_records() || !flight_released ||
        !std::ranges::equal(server->negotiated_alpn(),c::Bytes{'h','2'})) return 27;
    auto master=t::master_secret(client->hash,client->handshake_secret.view()); auto traffic=t::derive_secret(client->hash,master->view(),"c ap traffic",*hash);
    auto appkey=t::expand_label(client->hash,traffic->view(),"key",{},16), iv=t::expand_label(client->hash,traffic->view(),"iv",{},12);
    auto send=t::RecordLayer::create(t::RecordDirection::send,c::Aead::aes_128_gcm,appkey->view(),iv->view());
    c::Bytes data{'o','k'}; auto encrypted=send->seal(t::ContentType::application_data,data); auto opened=app->open(*encrypted);
    if (!opened || *opened!=data) return 28;
    c::Bytes ticket{4,0,0,14,0,0,0,1,0,0,0,2,0,0,1,7,0,0};
    auto client_ticket=send->seal(t::ContentType::handshake,ticket);
    if (!client_ticket || app->open_event(*client_ticket) || app->seal(data)) return 61;
    auto c2=credential(); auto timeout=t::ServerHandshakeIo::create(std::move(*c2),1,5); if (!timeout || timeout->tick(5).error()!=t::ServerHandshakeIoError::timeout || timeout->tick(6)) return 29;
    auto c3=credential(); auto cancel=t::ServerHandshakeIo::create(std::move(*c3),1,5); if (!cancel || !cancel->cancel() || cancel->feed(input,2)) return 30;
    auto c4=credential(); auto eof=t::ServerHandshakeIo::create(std::move(*c4),1,5); if (!eof || eof->finish_input(2).error()!=t::ServerHandshakeIoError::protocol_error) return 31;
    auto c5=credential(); auto blocked=t::ServerHandshakeIo::create(std::move(*c5),1,5);
    if (!blocked || !blocked->feed(input,2) || blocked->pending_output().empty()) return 32;
    if (blocked->written(1,1).error()!=t::ServerHandshakeIoError::time_reversed || blocked->tick(5).error()!=t::ServerHandshakeIoError::timeout || !blocked->pending_output().empty()) return 33;
    auto c6=credential(); auto cancel_output=t::ServerHandshakeIo::create(std::move(*c6),1,5);
    if (!cancel_output || !cancel_output->feed(input,2) || cancel_output->pending_output().empty()) return 34;
    hello_released=false; flight_released=false;
    watched_hello=const_cast<std::uint8_t*>(cancel_output->pending_output().data());
    if (!cancel_output->written(cancel_output->pending_output().size(),2) || cancel_output->pending_output().empty()) return 66;
    watched_flight=const_cast<std::uint8_t*>(cancel_output->pending_output().data());
    if (!cancel_output->cancel() || !cancel_output->pending_output().empty() || !hello_released || !flight_released) return 67;
    for (int scenario=0;scenario<3;++scenario) {
        auto c7=credential(); auto required=t::ServerHandshakeIo::create(std::move(*c7),1,50,"h2");
        if (!required || !required->negotiated_alpn().empty()) return 48;
        auto offer=hello;
        if (scenario==0) offer.extensions.pop_back();
        if (scenario==1) offer.extensions.back().data={0,3,2,'h','3'};
        if (scenario==2) offer.extensions.back().data={0,4,2,'h','2',0};
        auto encoded=t::HandshakeDecoder::encode(1,*offer.encode()); if (!encoded) return 49;
        c::Bytes frame{22,3,3,static_cast<std::uint8_t>(encoded->size()>>8),static_cast<std::uint8_t>(encoded->size())};
        frame.insert(frame.end(),encoded->begin(),encoded->end());
        auto rejected=required->feed(frame,2);
        if (rejected || rejected.error()!=t::ServerHandshakeIoError::protocol_error || !required->pending_output().empty()) return 50;
    }
    auto initial=hello; initial.extensions[3].data={0,0};
    auto initial_wire=t::HandshakeDecoder::encode(1,*initial.encode()); if (!initial_wire) return 35;
    auto frame=[](c::Bytes const& msg) { c::Bytes out{22,3,3,static_cast<std::uint8_t>(msg.size()>>8),static_cast<std::uint8_t>(msg.size())}; out.insert(out.end(),msg.begin(),msg.end()); return out; };
    auto first_record=frame(*initial_wire);
    for (int scenario=0;scenario<6;++scenario) {
        auto retry_budget=std::make_shared<nexus::memory::Budget>(4*1024*1024);
        auto retained=credential(); auto retrying=t::ServerHandshakeIo::create(std::move(*retained),1,50,"h2",t::ServerCredential::max_certificate_list_size,retry_budget); if (!retrying) return 36;
        for (auto byte:first_record) { auto result=retrying->feed(std::span{&byte,1},2); if (!result || result->consumed!=1) return 37; }
        if (retrying->pending_output().empty() || retry_budget->reserved()!=retrying->pending_output().size() || retrying->feed(first_record,2)->consumed!=0) return 38;
        std::optional<nexus::memory::Budget::Reservation> retry_blocker;
        if (scenario==5) {
            retry_blocker=nexus::memory::Budget::reserve(retry_budget,retry_budget->limit()-t::ServerHandshakeIo::hello_input_charge+1);
            if (!retry_blocker) return 88;
        }
        c::Bytes retry_record;
        while (!retrying->pending_output().empty()) {
            retry_record.push_back(retrying->pending_output()[0]); auto written=retrying->written(1,3);
            if (!written) {
                if (scenario!=5 || written.error()!=t::ServerHandshakeIoError::budget_exceeded) return 39;
                break;
            }
        }
        if (scenario==5) { if (!retrying->pending_output().empty() || retry_budget->reserved()!=retry_blocker->size()) return 89; continue; }
        if (retry_budget->reserved()!=t::ServerHandshakeIo::hello_input_charge) return 79;
        if (scenario==3) { if (retrying->tick(50).error()!=t::ServerHandshakeIoError::timeout) return 40; continue; }
        if (scenario==4) { if (!retrying->cancel() || retrying->feed(first_record,4)) return 41; continue; }
        auto hrr=t::ServerHello::parse(std::span{retry_record}.subspan(9)); if (!hrr || !hrr->is_retry()) return 42;
        auto second=hrr->retry_client_hello(initial,t::KeyShareEntry{29,{pub->begin(),pub->end()}}); if (!second) return 43;
        if (scenario==1) second->random[0]^=1;
        auto second_wire=t::HandshakeDecoder::encode(1,*second->encode()); if (!second_wire) return 44;
        auto second_record=frame(*second_wire);
        for (auto byte:ccs) { auto result=retrying->feed(std::span{&byte,1},4); if (!result || result->consumed!=1) return 45; }
        if (scenario==2) {
            bool rejected=false; for (auto byte:ccs) if (!retrying->feed(std::span{&byte,1},4)) { rejected=true; break; }
            if (!rejected) return 46; continue;
        }
        bool rejected=false; for (auto byte:second_record) if (!retrying->feed(std::span{&byte,1},5)) { rejected=true; break; }
        if ((scenario==1 && (!rejected || retry_budget->reserved())) || (scenario==0 && (rejected || retrying->pending_output().empty() || !retry_budget->reserved()))) return 47;
        if (scenario==0) {
            auto held=retry_budget->reserved(); auto moved=std::move(*retrying);
            if (!held || retry_budget->reserved()!=held || retrying->tick(5) || !moved.cancel() || retry_budget->reserved()) return 80;
        }
    }
    std::cout << "TLS server incremental handshake, fragmentation and lifetime passed\n";
}
