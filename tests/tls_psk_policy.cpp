import std;
import nexus.compat;
import tls.psk_client_policy;
import tls.psk_server_policy;
import tls.hello_config;
import tls.post_handshake;
import tls.server_hello;
namespace t=tls;namespace c = ::crypto;using Bytes=c::Bytes;using View=std::span<std::uint8_t const>;
struct Clock {static inline std::uint64_t value=1000;static auto now()noexcept->std::uint64_t{return value;}};
using CP=t::PskClientPolicy<t::ResumptionTicket,Clock>;using Store=t::ServerTicketStore<2>;using SP=t::PskServerPolicy<Store,Clock>;
auto body(unsigned tag=1)->Bytes {Bytes out{0,0,0,1,0xff,0xff,0xff,0xf0,1,3,0,32};for(unsigned i=0;i<32;++i)out.push_back(static_cast<std::uint8_t>(i+tag));out.insert(out.end(),{0,0});return out;}
auto binding()->t::TicketBinding {return {"server.example",{'h','2'},{},{}};}
auto material(unsigned tag=1)->t::ResumptionTicket {auto value=t::ResumptionTicket::from_message(body(tag),c::Hash::sha256,Bytes(32,0xa5),binding(),1000);if(!value)std::abort();return std::move(*value);}
auto client()->CP {nexus::inplace_vector<t::ResumptionTicket,8> offers;offers.push_back(material());auto policy=CP::create(binding(),std::move(offers));if(!policy)std::abort();return std::move(*policy);}
auto hello()->t::ClientHello {std::array<std::uint16_t,1> groups{29};std::array<std::string_view,1> alpn{"h2"};auto value=t::make_client_hello({},alpn,groups);if(!value)std::abort();return std::move(*value);}
auto frame(t::ClientHello const& hello)->Bytes {auto b=hello.encode();if(!b)std::abort();auto n=b->size();Bytes out{1,static_cast<std::uint8_t>(n>>16),static_cast<std::uint8_t>(n>>8),static_cast<std::uint8_t>(n)};out.insert(out.end(),b->begin(),b->end());return out;}
auto server_binding()->t::ServerTicketBinding {t::ServerTicketBinding b{{},{'h','2'},{}};b.credential_context[0]=9;return b;}
auto publish(Store& store,unsigned tag=1)->void {auto ticket=material(tag);auto offer=ticket.offer(Clock::now());if(!offer)std::abort();std::array<std::uint8_t,32> id{};std::ranges::copy(offer->identity,id.begin());if(!store.publish({t::Secret(Bytes(offer->secret.begin(),offer->secret.end())),id,server_binding(),c::Hash::sha256,1000,1},Clock::now()))std::abort();}
int main() {
 Store store;publish(store);auto cp=client();auto ch=hello();if(!cp.prepare(ch))return 1;auto wire=frame(ch);if(!cp.seal(ch,wire))return 2;
 SP sp(store,server_binding());if(sp.take_issuer().error()!=t::PskError::invalid_state)return 3;
 auto selected=sp.select(ch,wire,0x1301);if(!selected||!*selected||!sp.selected()||sp.selected_index()!=0)return 4;
 t::ServerHello sh;sh.cipher_suite=0x1301;sh.extensions={{41,{0,0}}};auto client_selected=cp.select(ch,sh);if(!client_selected||!*client_selected||!c::constant_time_equal(**client_selected,**selected))return 5;
 cp.offer_consumed();if(!cp.extensions(Bytes{'h','2'})||cp.extensions(Bytes{'h','3'}).error()!=t::PskError::identity_mismatch)return 6;
 if(cp.take_receiver().error()!=t::PskError::invalid_state)return 7;
 if(!cp.retain_master(t::Secret(Bytes(32,1)),c::Hash::sha256)||!cp.client_finished(Bytes(32,2))||cp.complete()||cp.take_receiver().error()!=t::PskError::invalid_state)return 8;
 if(!cp.finished_sent()||!cp.complete()||!cp.take_receiver()||cp.take_receiver().error()!=t::PskError::invalid_state)return 9;
 if(!sp.retain_master(t::Secret(Bytes(32,1)),c::Hash::sha256)||sp.take_issuer().error()!=t::PskError::invalid_state||!sp.client_finished(Bytes(32,2)))return 10;
 auto issuer=sp.take_issuer();if(!issuer||sp.take_issuer().error()!=t::PskError::invalid_state)return 11;
 auto pending=issuer->prepare();auto second=issuer->prepare();if(!pending||!second||store.size()!=1)return 12;
 auto first_body=t::parse_new_session_ticket(pending->body()),second_body=t::parse_new_session_ticket(second->body());
 if(!first_body||!second_body||std::ranges::equal(first_body->nonce,second_body->nonce)||std::ranges::equal(first_body->ticket,second_body->ticket))return 13;
 if(!pending->publish(store,Clock::now())||store.size()!=2||pending->publish(store,Clock::now()))return 14;
 for(auto index:{1u,255u,65535u}) {
  auto policy=client();auto h=hello();if(!policy.prepare(h))return 15;auto bad=sh;bad.extensions[0].data={static_cast<std::uint8_t>(index>>8),static_cast<std::uint8_t>(index)};
  if(policy.select(h,bad).error()!=t::PskError::invalid_selection)return 16;
 }
 {auto policy=client();auto h=hello();if(!policy.prepare(h))return 17;auto bad=sh;bad.cipher_suite=0x1302;if(policy.select(h,bad).error()!=t::PskError::invalid_selection)return 18;}
 {auto policy=CP::create(binding());auto h=hello();if(!policy||!policy->prepare(h)||policy->select(h,sh).error()!=t::PskError::invalid_selection)return 19;}
 {auto h=ch;h.extensions.back().data.back()^=1;auto bad_wire=frame(h);SP policy(store,server_binding());if(policy.select(h,bad_wire,0x1301).error()!=t::PskError::invalid_selection)return 20;}
 {auto h=ch;h.extensions.back().data[4]^=0x80;auto unknown=frame(h);SP policy(store,server_binding());auto accepted=policy.select(h,unknown,0x1301);if(!accepted||*accepted||policy.selected())return 21;}
 {auto h=ch;h.extensions.insert(h.extensions.begin(),{0,{0,4,0,0,1,'x'}});auto changed=frame(h);SP policy(store,server_binding());auto accepted=policy.select(h,changed,0x1301);if(!accepted||*accepted)return 32;}
 {auto changed=server_binding();changed.alpn={'h','3'};SP policy(store,changed);auto accepted=policy.select(ch,wire,0x1301);if(!accepted||*accepted)return 22;}
 {auto changed=server_binding();changed.credential_context[1]^=1;SP policy(store,changed);auto accepted=policy.select(ch,wire,0x1301);if(!accepted||*accepted)return 23;}
 {auto h=ch;h.extensions.push_back({21,{}});SP policy(store,server_binding());if(policy.select(h,frame(h),0x1301).error()!=t::PskError::invalid_offer)return 24;}
 {auto value=material();auto b=binding();b.authentication_context[0]=1;nexus::inplace_vector<t::ResumptionTicket,8> offers;offers.push_back(std::move(value));if(CP::create(b,std::move(offers)).error()!=t::PskError::identity_mismatch)return 25;}
 Clock::value=2000;
 {SP policy(store,server_binding());auto accepted=policy.select(ch,wire,0x1301);if(!accepted||*accepted)return 26;}
 {auto expired=client();auto h=hello();if(!expired.prepare(h)||h.extension(41))return 27;}
 Clock::value=1000;
 {auto policy=client();auto h=hello();if(!policy.prepare(h))return 28;Clock::value=2000;if(!policy.retry(h,0x1301)||h.extension(41))return 29;Clock::value=1000;}
 {auto policy=client();auto h=hello();if(!policy.prepare(h)||!policy.retry(h,0x1302)||h.extension(41))return 30;}
 {auto policy=client();auto h=hello();h.extensions.push_back({42,{}});if(policy.prepare(h).error()!=t::PskError::invalid_offer)return 31;}
 std::println("PSK policy index/hash/identity/SNI/ALPN/credential/age negatives, before-Finished publication rejection, bounded store and nonce renewal passed");
}
