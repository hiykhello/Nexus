import std;
import hysteria2.auth;
import hysteria2.credential;
import hysteria2.transport_options;
namespace h=hysteria2;
auto bytes(std::string_view x){return std::span(reinterpret_cast<std::uint8_t const*>(x.data()),x.size());}
auto main()->int{
    for(auto invalid:{""," bad","bad ","bad\nheader","bad\rheader"})if(h::Password::create(bytes(invalid)))return 1;
    std::string large(4097,'x');if(h::Password::create(bytes(large)))return 2;large.pop_back();if(!h::Password::create(bytes(large)))return 3;
    auto a=h::Password::create(bytes("first-password")),b=h::Password::create(bytes("second-password"));if(!a || !b)return 4;
    std::array<h::Password,2> users{std::move(*a),std::move(*b)};
    if(h::authenticate(users,"first-password")!=0 || h::authenticate(users,"second-password")!=1 || h::authenticate(users,"first-passwore"))return 5;
    auto headers=h::ClientAuthHeaders::create(users[1].view(),0);if(!headers)return 6;
    auto parsed=h::parse_client_auth(headers->fields());if(!parsed || h::authenticate(users,parsed->credential)!=1)return 7;
    h::TransportOptions options;using Profile=h::TransportProfile<16,16384>;
    auto parameters=Profile::parameters(options);auto settings=Profile::settings(options);if(!parameters || !settings)return 8;
    if(parameters->initial_max_streams_bidi!=16 || parameters->initial_max_stream_data_bidi_remote!=16384 || parameters->initial_max_streams_uni!=3 || parameters->max_datagram_frame_size!=65535)return 9;
    options.udp=false;if(Profile::parameters(options)->max_datagram_frame_size)return 10;
    options.handshake_timeout=std::chrono::milliseconds(0);if(Profile::settings(options) || Profile::parameters(options))return 11;
    options.handshake_timeout=std::chrono::seconds(10);options.native_bytes=65535;if(Profile::settings(options))return 12;
    std::println("Production Hy2 raw-credential lifetime/HTTP3 auth/static windows/QUIC timeout/UDP capability/budget validation pass");
}
