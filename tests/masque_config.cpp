import std;
import config;
auto replace(std::string text,std::string_view from,std::string_view to) -> std::string {auto at=text.find(from);if(at==text.npos)throw std::runtime_error("fixture");text.replace(at,from.size(),to);return text;}
auto main() -> int {
    std::string config=R"(schema-version 1
role "server"
inbound "masque" type="masque" {
  listen host="127.0.0.1" port=9443
  authority "localhost"
  authentication { bearer-file "/tmp/secret"; }
  tls { certificate-file "/tmp/cert"; private-key-file "/tmp/key"; }
  allow cidr="127.0.0.0/8" first-port=1 last-port=65535
}
outbound "direct" type="direct"
routing { default-outbound "direct"; }
)";
    auto valid=config::parse_kdl(config);if(!valid || valid->inbounds.size()!=1 || !valid->inbounds[0].masque || valid->inbounds[0].masque->destinations.size()!=1)return 1;
    for(auto text:{replace(config,"127.0.0.0/8","127.0.0.1/8"),replace(config,"127.0.0.0/8","127.0.0.0/33"),replace(config,"first-port=1","first-port=0"),replace(config,"bearer-file \"/tmp/secret\"","bearer-file \"relative\""),replace(config,"  allow cidr=\"127.0.0.0/8\" first-port=1 last-port=65535\n","")})if(config::parse_kdl(text))return 2;
    auto grouped=replace(replace(config,"inbound \"masque\" type=\"masque\" {","inbounds { masque \"masque\" {"),"}\noutbound", "} }\noutbound");
    if(!config::parse_kdl(grouped))return 3;
    auto overlap=config+R"(inbound "hy" type="hysteria2" { listen host="127.0.0.1" port=9443; authentication { user "a" password-file="/tmp/pass"; }; tls { certificate-file "/tmp/cert"; private-key-file "/tmp/key"; }; })";
    if(config::parse_kdl(overlap))return 4;
    std::println("MASQUE KDL limits, policy and UDP overlap passed");
}
