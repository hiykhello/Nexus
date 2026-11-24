import std;
import relay;
import rules;
using namespace std::chrono_literals;
auto main() -> int {
    namespace r = ::rules;
    relay::Server server;
    std::vector<r::ProgramRule> rules{
        {r::RuleSet{{},2},{r::ProgramActionKind::sniff}},
        {r::RuleSet{{{"domain","blocked.example"}},2},{r::ProgramActionKind::reject},r::DomainSource::sniffed},
        {r::RuleSet{{},2},{r::ProgramActionKind::route,0}}
    };
    if(!server.set_ordered_tcp(rules,0,100,true))return 2;
    auto port=server.start(0,relay::Inbound::mixed);
    if(!port)return 3;
    std::cout << *port << std::endl;
    for(;;)server.poll(100ms);
}
