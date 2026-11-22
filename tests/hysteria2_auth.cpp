import std;
import http.header;
import hysteria2.auth;
namespace h=hysteria2;
using Field=http::HeaderField;
auto request() -> std::vector<Field> {
    return {{":method","POST"},{":scheme","https"},{":authority","hysteria"},{":path","/auth"},
        {"hysteria-auth","secret"},{"hysteria-cc-rx","0"},{"hysteria-padding","x"},{"unknown","opaque"}};
}
auto main() -> int {
    auto fields=request(); auto client=h::parse_client_auth(fields);
    if (!client || client->credential!="secret" || client->receive_bps) return 1;
    std::string password(4096,'p');
    for (auto rate:{std::uint64_t{0},std::uint64_t{1},std::numeric_limits<std::uint64_t>::max()}) {
        auto headers=h::ClientAuthHeaders::create(password,rate,"padding");
        if (!headers) return 2;
        auto values=headers->fields(); auto parsed=h::parse_client_auth(values);
        if (!parsed || parsed->credential.data()!=password.data() || parsed->receive_bps!=rate) return 3;
        for (bool automatic:{false,true}) for (bool udp:{false,true}) {
            auto response=h::ServerAuthHeaders::create({udp,automatic,rate});
            if (!response) return 4;
            auto values=response->fields(); auto parsed=h::parse_server_auth(values);
            if (!parsed || parsed->udp!=udp || parsed->automatic!=automatic || parsed->receive_bps!=(automatic ? 0 : rate)) return 5;
        }
    }
    for (auto field:std::vector<Field>{{"hysteria-auth","other"},{":path","/auth"},{"hysteria-cc-rx","1"},{"hysteria-padding","x"}}) {
        auto bad=request(); bad.push_back(field); if (h::parse_client_auth(bad)) return 6;
    }
    for (auto name:{":host",":status","Hysteria-Auth","bad name","",":protocol"}) {
        auto bad=request(); bad[2].name=name; if (h::parse_client_auth(bad)) return 7;
    }
    for (auto rate:{"","auto","-1","+1","1 "," 1","1\t","18446744073709551616","1.5"}) {
        auto bad=request(); bad[5].value=rate; if (h::parse_client_auth(bad)) return 8;
    }
    for (auto value:{std::string_view{"a\r\nx"},std::string_view{"a\0x",3},std::string_view{"a\x7f",2}}) {
        auto bad=request(); bad[4].value=value;
        if (h::parse_client_auth(bad) || h::ClientAuthHeaders::create(value,0)) return 9;
    }
    for (auto forbidden:{"connection","transfer-encoding","upgrade","keep-alive","proxy-connection","te"}) {
        auto bad=request(); bad.push_back({forbidden,"x"}); if (h::parse_client_auth(bad)) return 10;
    }
    auto host=request(); host.erase(host.begin()+2); host.push_back({"host","hysteria"});
    if (!h::parse_client_auth(host)) return 11;
    host.push_back({":authority","hysteria"}); if (h::parse_client_auth(host)) return 12;
    auto ordinary=request(); ordinary[1].value="http";
    auto cover=h::parse_client_auth(ordinary); if (cover || cover.error()!=h::AuthError::not_auth) return 13;
    auto duplicate=request(); duplicate.push_back({"host","other"});
    if (h::parse_client_auth(duplicate)) return 14;
    auto bytes=request(); std::string large(16384,'x'); bytes.push_back({"ignored",large});
    if (h::parse_client_auth(bytes) || h::ClientAuthHeaders::create(std::string(4097,'p'),0)) return 15;
    auto count=request(); while (count.size()<=64) count.push_back({"ignored",""});
    if (h::parse_client_auth(count)) return 16;
    auto good=h::ServerAuthHeaders::create({true,false,1}); auto raw=good->fields();
    for (auto status:{"200","401","503"}) {
        raw[0].value=status; auto parsed=h::parse_server_auth(raw);
        if (parsed || parsed.error()!=h::AuthError::rejected) return 17;
    }
    raw[0].value="233";
    for (auto value:{"1","TRUE","false ",""}) { raw[1].value=value; if (h::parse_server_auth(raw)) return 18; }
    raw[1].value="true";
    for (auto value:{"-1","+1","AUTO","18446744073709551616",""}) { raw[2].value=value; if (h::parse_server_auth(raw)) return 19; }
    h::CongestionPolicy policy{2000000,3000000,false,false};
    if(h::server_congestion(policy,0)!=0 || h::server_congestion(policy,1000000)!=1000000 || h::server_congestion(policy,4000000)!=2000000)return 20;
    if(h::client_congestion(policy,{true,true,0})!=0 || h::client_congestion(policy,{true,false,0})!=2000000 || h::client_congestion(policy,{true,false,1000000})!=1000000)return 21;
    policy.send_bps=0;if(h::server_congestion(policy,1000000)!=1000000 || h::client_congestion(policy,{true,false,1000000})!=0)return 22;
    policy.ignore_client_bandwidth=true;if(h::server_congestion(policy,0) || h::server_congestion(policy,1000000)!=1000000)return 23;
    policy.send_bps=500000;if(h::server_congestion(policy,1000000)!=500000)return 24;
    policy.receive_bps=0;if(h::server_congestion(policy,0)!=0 || h::server_congestion(policy,1000000)!=0)return 25;
    std::println("Hy2 bounded HTTP3 auth fields, lowercase/pseudo rules, credential views, 233 and rate semantics passed");
}

