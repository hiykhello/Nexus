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
static nexus::memory::Budget* seal_budget=nullptr;
static std::size_t seal_expected=0;
static bool inner_charged=false, ciphertext_charged=false;
static std::size_t certificate_body_size=0;
static bool certificate_body_charged=false;
static bool capture_allocations=false;
static std::pair<void*,std::size_t> captured[512];
static std::size_t captured_count=0;
void* operator new(std::size_t size) {
    if (fail_after==0) { fail_after=-1; throw std::bad_alloc{}; }
    if (fail_after>0) --fail_after;
    if (auto p=std::malloc(size ? size : 1)) {
        if (seal_budget && size==16385) inner_charged=seal_budget->reserved()>=seal_expected;
        if (seal_budget && size==16401) ciphertext_charged=seal_budget->reserved()>=seal_expected;
        if (seal_budget && size==certificate_body_size) certificate_body_charged=seal_budget->reserved()>=seal_expected;
        if (capture_allocations && captured_count<std::size(captured)) captured[captured_count++]={p,size};
        return p;
    }
    throw std::bad_alloc{};
}
void operator delete(void* p) noexcept {
    if (p && p==watched_hello) { hello_released=true; watched_hello=nullptr; }
    if (p && p==watched_flight) { flight_released=true; watched_flight=nullptr; }
    std::free(p);
}
void operator delete(void* p,std::size_t) noexcept { ::operator delete(p); }
namespace t=nexus::tls; namespace c=nexus::crypto;
auto exact_output_allocation(std::span<std::uint8_t const> output) -> bool {
    return std::ranges::any_of(std::span{captured}.first(captured_count),[&](auto const& entry) {
        return entry.first==output.data() && entry.second==output.size();
    });
}
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
        if (!chain || chain->chain().size()!=1) return 70;
        fail_after=0; auto shared_chain=chain->clone(); auto no_allocation=fail_after==0; fail_after=-1;
        if (!shared_chain || !no_allocation || shared_chain->certificate().data()!=chain->certificate().data() ||
            shared_chain->chain()[0].data()!=chain->chain()[0].data() || !check_limit(std::move(*chain))) return 70;
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
    auto parsed_charge=body->size()+(body->size()/4)*sizeof(t::Extension);
    c::Bytes input{22,3,1,static_cast<std::uint8_t>(wire->size()>>8),static_cast<std::uint8_t>(wire->size())}; input.insert(input.end(),wire->begin(),wire->end());
    if (t::ServerHandshakeIo::hello_reassembly_charge!=16389+5+65539+4096+65535) return 100;
    auto old_limit_credential=credential();
    auto old_limit_budget=std::make_shared<nexus::memory::Budget>(16389+65539+t::ServerHandshakeIo::hello_encoded_charge);
    if (!old_limit_credential) return 101;
    auto old_limit=t::ServerHandshakeIo::create(std::move(*old_limit_credential),1,100,"h2",t::ServerCredential::max_certificate_list_size,old_limit_budget);
    if (old_limit || old_limit.error()!=t::ServerHandshakeIoError::budget_exceeded || old_limit_budget->reserved() || !old_limit_credential->scheme()) return 102;
    {
        auto large=hello; large.extensions.push_back({21,c::Bytes(60000,0)});
        auto large_body=large.encode(); if (!large_body) return 103;
        auto large_wire=t::HandshakeDecoder::encode(1,*large_body); if (!large_wire) return 104;
        auto c=credential(); auto budget=std::make_shared<nexus::memory::Budget>(4*1024*1024);
        if (!c) return 105;
        auto candidate=t::ServerHandshakeIo::create(std::move(*c),1,100,"h2",t::ServerCredential::max_certificate_list_size,budget);
        if (!candidate || budget->reserved()!=t::ServerHandshakeIo::hello_input_charge) return 106;
        for (std::size_t pos=0;pos<large_wire->size();) {
            auto count=std::min<std::size_t>(16384,large_wire->size()-pos);
            c::Bytes record{22,3,3,static_cast<std::uint8_t>(count>>8),static_cast<std::uint8_t>(count)};
            record.insert(record.end(),large_wire->begin()+static_cast<std::ptrdiff_t>(pos),large_wire->begin()+static_cast<std::ptrdiff_t>(pos+count));
            auto part=candidate->feed(record,2);
            if (!part || part->consumed!=record.size()) return 107;
            pos+=count;
            if (pos<large_wire->size() && budget->reserved()!=t::ServerHandshakeIo::hello_input_charge) return 108;
        }
        if (candidate->pending_output().empty() || !candidate->cancel() || budget->reserved()) return 109;
    }
    auto small_credential=credential(); auto small_budget=std::make_shared<nexus::memory::Budget>(t::ServerHandshakeIo::hello_input_charge-1);
    if (!small_credential) return 71;
    auto small=t::ServerHandshakeIo::create(std::move(*small_credential),1,100,"h2",t::ServerCredential::max_certificate_list_size,small_budget);
    if (small || small.error()!=t::ServerHandshakeIoError::budget_exceeded || !small_credential->scheme() || small_budget->reserved()) return 72;
    small_budget=std::make_shared<nexus::memory::Budget>(t::ServerHandshakeIo::hello_input_charge);
    small=t::ServerHandshakeIo::create(std::move(*small_credential),1,100,"h2",t::ServerCredential::max_certificate_list_size,small_budget);
    if (!small || small_budget->reserved()!=t::ServerHandshakeIo::hello_input_charge) return 81;
    auto denied=small->feed(input,2);
    if (denied || denied.error()!=t::ServerHandshakeIoError::budget_exceeded || small_budget->reserved() || small->tick(2)) return 73;
    // Deny stream parse, key-parser copy, generated hello and construction scratch.
    for (auto extra:{parsed_charge-1,2*parsed_charge-1,2*parsed_charge+t::ServerHandshakeIo::generated_hello_charge-1,2*parsed_charge+t::ServerHandshakeIo::generated_hello_charge+t::ServerHandshakeIo::generated_hello_scratch_charge-1}) {
        auto c=credential(); if (!c) return 95;
        auto budget=std::make_shared<nexus::memory::Budget>(t::ServerHandshakeIo::hello_input_charge+extra);
        auto candidate=t::ServerHandshakeIo::create(std::move(*c),1,100,"h2",t::ServerCredential::max_certificate_list_size,budget);
        if (!candidate) return 96;
        auto result=candidate->feed(input,2);
        if (result || result.error()!=t::ServerHandshakeIoError::budget_exceeded || budget->reserved() || candidate->tick(2)) return 97;
    }
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
    for (bool enough:{false,true}) {
        auto bounded_credential=credential(); if (!bounded_credential) return 90;
        auto signature=bounded_credential->max_signature_size(); if (!signature) return 91;
        auto list=bounded_credential->certificate().size()+5;
        auto extensions=std::size_t{15}; // h2 EncryptedExtensions handshake message
        auto plaintext=list+8+extensions+8+*signature+52;
        auto output=plaintext+(22+sizeof(c::Bytes))*((plaintext+16383)/16384);
        auto scratch=2*(list+8)+16384+t::ServerHandshakeIo::flight_seal_scratch_charge+(8+*signature)+extensions+52;
        auto peak=std::max(t::ServerHandshakeIo::generated_hello_scratch_charge,server->pending_output().size()+output+scratch+t::ServerFlight::finished_decoder_charge);
        auto limit=t::ServerHandshakeIo::hello_input_charge+2*parsed_charge+t::ServerHandshakeIo::generated_hello_charge+peak-(enough ? 0 : 1);
        auto bounded_budget=std::make_shared<nexus::memory::Budget>(limit);
        auto candidate=t::ServerHandshakeIo::create(std::move(*bounded_credential),1,100,"h2",t::ServerCredential::max_certificate_list_size,bounded_budget);
        if (!candidate) return 92;
        if (enough) { captured_count=0; capture_allocations=true; }
        if (argc==5 && enough) { seal_budget=bounded_budget.get(); seal_expected=limit; certificate_body_size=list+4; inner_charged=ciphertext_charged=certificate_body_charged=false; }
        auto result=candidate->feed(input,2);
        seal_budget=nullptr; capture_allocations=false;
        if (enough && (!result || !exact_output_allocation(candidate->pending_output()))) return 111;
        if (argc==5 && enough && (!inner_charged || !ciphertext_charged || !certificate_body_charged)) return 110;
        if (argc==5 && enough && std::ranges::count_if(std::span{captured}.first(captured_count),[&](auto const& entry) { return entry.second==certificate_body_size; })!=1) return 113;
        if (!enough) {
            if (result || result.error()!=t::ServerHandshakeIoError::budget_exceeded || bounded_budget->reserved()) return 93;
        } else {
            if (!result || candidate->pending_output().empty() || bounded_budget->reserved()>=limit || !candidate->cancel() || bounded_budget->reserved()) return 94;
        }
    }
    for (bool deny_input:{false,true}) {
        auto input_credential=credential(); auto input_budget=std::make_shared<nexus::memory::Budget>(4*1024*1024);
        if (!input_credential) return 83;
        auto candidate=t::ServerHandshakeIo::create(std::move(*input_credential),1,100,"h2",t::ServerCredential::max_certificate_list_size,input_budget);
        if (!candidate || !candidate->feed(input,2)) return 84;
        while (!candidate->pending_output().empty()) if (!candidate->written(candidate->pending_output().size(),2)) return 85;
        std::optional<nexus::memory::Budget::Reservation> blocker;
        if (deny_input) blocker=nexus::memory::Budget::reserve(input_budget,input_budget->limit()-t::ServerHandshakeIo::finished_input_charge+1-t::ServerFlight::finished_decoder_charge);
        std::uint8_t first=23; auto part=candidate->feed(std::span{&first,1},3);
        if (deny_input) {
            if (!blocker || part || part.error()!=t::ServerHandshakeIoError::budget_exceeded || input_budget->reserved()!=blocker->size()) return 86;
        } else if (!part || input_budget->reserved()!=t::ServerHandshakeIo::finished_input_charge+t::ServerFlight::finished_decoder_charge || !candidate->cancel() || input_budget->reserved()) return 87;
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
        auto index_charge=server->pending_output().empty() ? records.size()*sizeof(c::Bytes) : 0;
        if (held_before<record.size()+index_charge || handshake_budget->reserved()!=held_before-record.size()-index_charge) return 75;
        records.push_back(std::move(record));
    }
    if (records.size()<(argc>=4 ? 3u : 2u) || records[0].size()<6 || !hello_released || !flight_released || watched_flight || handshake_budget->reserved()!=t::ServerFlight::finished_decoder_charge) return 13;
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
        auto expected=server->complete() ? 0 : t::ServerFlight::finished_decoder_charge+(i+1==record->size() ? 0 : t::ServerHandshakeIo::finished_input_charge);
        if (handshake_budget->reserved()!=expected) return 82;
        if (record==&*a && i+1==record->size()) {
            auto moved=std::move(*server);
            if (server->tick(104) || handshake_budget->reserved()!=t::ServerFlight::finished_decoder_charge) return 110;
            *server=std::move(moved);
            if (moved.tick(104) || handshake_budget->reserved()!=t::ServerFlight::finished_decoder_charge) return 111;
        }
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
    for (int scenario=0;scenario<8;++scenario) {
        auto retry_budget=std::make_shared<nexus::memory::Budget>(4*1024*1024);
        auto retained=credential(); auto retrying=t::ServerHandshakeIo::create(std::move(*retained),1,50,"h2",t::ServerCredential::max_certificate_list_size,retry_budget); if (!retrying) return 36;
        if (scenario==0) { captured_count=0; capture_allocations=true; }
        for (auto byte:first_record) { auto result=retrying->feed(std::span{&byte,1},2); if (!result || result->consumed!=1) return 37; }
        capture_allocations=false;
        if (scenario==0 && !exact_output_allocation(retrying->pending_output())) return 112;
        if (retrying->pending_output().size()<5) return 38;
        auto retained_charge=initial_wire->size()+retrying->pending_output().size()-5;
        if (retry_budget->reserved()!=retrying->pending_output().size()+retained_charge || retrying->feed(first_record,2)->consumed!=0) return 38;
        std::optional<nexus::memory::Budget::Reservation> retry_blocker;
        if (scenario==5) {
            retry_blocker=nexus::memory::Budget::reserve(retry_budget,retry_budget->limit()-t::ServerHandshakeIo::hello_input_charge+1-retained_charge);
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
        if (retry_budget->reserved()!=t::ServerHandshakeIo::hello_input_charge+retained_charge) return 79;
        if (scenario==3) { if (retrying->tick(50).error()!=t::ServerHandshakeIoError::timeout) return 40; continue; }
        if (scenario==4) { if (!retrying->cancel() || retrying->feed(first_record,4)) return 41; continue; }
        auto hrr=t::ServerHello::parse(std::span{retry_record}.subspan(9)); if (!hrr || !hrr->is_retry()) return 42;
        auto second=hrr->retry_client_hello(initial,t::KeyShareEntry{29,{pub->begin(),pub->end()}}); if (!second) return 43;
        if (scenario==1) second->random[0]^=1;
        auto second_wire=t::HandshakeDecoder::encode(1,*second->encode()); if (!second_wire) return 44;
        auto second_record=frame(*second_wire);
        for (auto byte:ccs) { auto result=retrying->feed(std::span{&byte,1},4); if (!result || result->consumed!=1) return 45; }
        if (scenario==6 || scenario==7) {
            auto charge=[](std::size_t n) { return n+(n/4)*sizeof(t::Extension); };
            auto needed=2*charge(second_wire->size()-4)+charge(initial_wire->size()-4);
            if (scenario==7) needed+=t::ServerHandshakeIo::generated_hello_charge+t::ServerHandshakeIo::generated_hello_scratch_charge;
            auto available=retry_budget->limit()-retry_budget->reserved();
            auto blocker=nexus::memory::Budget::reserve(retry_budget,available-needed+1);
            if (!blocker) return 98;
            auto result=retrying->feed(second_record,5);
            if (result || result.error()!=t::ServerHandshakeIoError::budget_exceeded || retry_budget->reserved()!=blocker->size()) return 99;
            continue;
        }
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
