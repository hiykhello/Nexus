import std;
import grpc.headers;
namespace g=grpc;
auto main() -> int {
    auto profile=g::RequestProfile::create("nexus.Service","cover.example",false);
    if (!profile || profile->path()!="/nexus.Service/Tun") return 1;
    auto fields=profile->request_fields();
    if (g::parse_request_headers(fields,*profile).status!=g::HeaderStatus::accepted) return 2;
    for (std::size_t i=0;i<fields.size();++i) {
        auto invalid=fields;
        if (i==6) continue;
        invalid[i].value="invalid";
        if (g::parse_request_headers(invalid,*profile).status==g::HeaderStatus::accepted) return 3;
    }
    auto empty=g::RequestProfile::create("","[::1]:443",true);
    if (!empty || empty->path()!="//Tun" || g::RequestProfile::create("a/b","host",false) ||
        g::RequestProfile::create("service","bad\r\nhost",false)) return 4;
    std::vector<g::FieldView> extra(fields.begin(),fields.end());
    extra.push_back({"user-agent","client"}); extra.push_back({"grpc-timeout","150m"});
    auto request=g::parse_request_headers(extra,*profile);
    if (request.status!=g::HeaderStatus::accepted || !request.timeout || request.timeout->count()!=150000000) return 5;
    extra.push_back({"grpc-timeout","1S"}); if (g::parse_request_headers(extra,*profile).status==g::HeaderStatus::accepted) return 6;
    for (auto timeout:{"", "1", "123456789m", "1d", "-1S", "+1S", "xS"}) if (g::parse_timeout(timeout)) return 7;
    if (g::parse_timeout("99999999H")!=std::chrono::nanoseconds::max() || g::parse_timeout("0n")!=std::chrono::nanoseconds{0}) return 8;
    auto response=g::response_fields(); auto trailers=g::success_trailers();
    g::ResponseHeaders normal;
    if (normal.receive(response,false)!=g::HeaderStatus::accepted || normal.ended() ||
        normal.receive(trailers,true)!=g::HeaderStatus::accepted || !normal.ended() || normal.remote_status()!=0) return 9;
    if (normal.receive(trailers,true)!=g::HeaderStatus::ended) return 10;
    g::ResponseHeaders missing;
    if (missing.receive(response,false)!=g::HeaderStatus::accepted || missing.data_end()!=g::HeaderStatus::malformed || missing.ended()) return 11;
    g::ResponseHeaders lite(g::ResponsePolicy::sing_box_lite);
    if (lite.receive(response,false)!=g::HeaderStatus::accepted || lite.data_end()!=g::HeaderStatus::accepted || !lite.ended() || lite.remote_status()) return 12;
    std::array<g::FieldView,3> trailers_only{{response[0],response[1],trailers[0]}};
    g::ResponseHeaders immediate;
    if (immediate.receive(trailers_only,true)!=g::HeaderStatus::accepted || !immediate.ended()) return 13;
    trailers_only[2].value="12"; g::ResponseHeaders rejected;
    if (rejected.receive(trailers_only,true)!=g::HeaderStatus::status || rejected.remote_status()!=12) return 14;
    for (auto code:{"", "00", "-1", "4294967296", "0x0"}) {
        auto invalid=trailers_only; invalid[2].value=code; g::ResponseHeaders parser;
        if (parser.receive(invalid,true)==g::HeaderStatus::accepted) return 15;
    }
    for (auto name:{"Connection", "connection", "transfer-encoding", "upgrade"}) {
        auto invalid=std::vector<g::FieldView>(fields.begin(),fields.end()); invalid.push_back({name,"x"});
        if (g::parse_request_headers(invalid,*profile).status==g::HeaderStatus::accepted) return 16;
    }
    auto secure=g::RequestProfile::create("nexus.Service","cover.example",true);
    if (!secure) return 17;
    std::array<g::FieldView,5> no_te_http_scheme{{{":method","POST"},{":scheme","http"},{":path","/nexus.Service/Tun"},{":authority","cover.example"},{"content-type","application/grpc"}}};
    if (g::parse_request_headers(no_te_http_scheme,*secure).status!=g::HeaderStatus::accepted) return 18;
    std::println("gRPC request path/headers, compression policy, bounded timeout and strict status/trailers-only/lite termination passed");
}
