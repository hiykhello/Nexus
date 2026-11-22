import std;
import rules;

namespace {
    auto check(bool good,std::string_view test) -> void {
        if (!good) throw std::runtime_error(std::string(test));
    }
}

int main() {
    using namespace rules;
    using Truth=Matcher::Truth;
    auto parsed=parse_kdl(R"kdl(schema-version 2
kind "predicate"
all {
    rule-set "corp"
    not { port 443; }
}
)kdl");
    check(parsed.has_value(),"decode shorthand");
    auto beve=write_beve(*parsed);
    check(beve && parse_beve(*beve) && *parse_beve(*beve)==*parsed,"BEVE reference round trip");
    auto kdl=write_kdl(*parsed);
    check(kdl && parse_kdl(*kdl) && *parse_kdl(*kdl)==*parsed,"canonical KDL reference round trip");
    check(!Matcher::compile(*parsed),"unbound reference rejected");

    auto corp=RuleSet{{{"ip-cidr","192.0.2.0/24",{}},{"domain","inside.test",{}}},2};
    auto lookup=[&](std::string_view tag) -> RuleSet const* {return tag=="corp" ? &corp : nullptr;};
    std::size_t remaining=max_rules;
    auto expanded=expand_rule_sets(*parsed,lookup,remaining);
    check(expanded.has_value(),"bind reference");
    auto matcher=Matcher::compile(*expanded);
    check(matcher.has_value(),"compile expanded tree");
    check(matcher->match_truth_mapped({.ip="192.0.2.3"})==Truth::unknown,"NOT missing port remains unknown");
    check(matcher->match_truth_mapped({.ip="192.0.2.3",.port=443})==Truth::no,"negative port filter");
    check(matcher->match_truth_mapped({.ip="192.0.2.3",.port=80})==Truth::yes,"CIDR branch");
    check(matcher->match_truth_mapped({.domain="inside.test",.port=80})==Truth::yes,"alternate set branch");
    check(!expand_rule_sets(*parsed,[](auto) -> RuleSet const* {return nullptr;},remaining),"unknown tag");
    remaining=3;
    check(!expand_rule_sets(*parsed,lookup,remaining) && remaining==3,"expanded budget rollback");
    corp.rules={{"rule-set","corp",{}}};
    remaining=max_rules;
    auto cyclic=expand_rule_sets(*parsed,lookup,remaining);
    check(!cyclic && cyclic.error().message.contains("cyclic"),"cycle refused");
    std::vector<RuleSet> chain(max_rule_depth+1);
    for (std::size_t i=0;i<chain.size();++i)
        chain[i]={{i+1==chain.size() ? Rule{"port","80",{}} : Rule{"rule-set",std::to_string(i+1),{}}},2};
    auto deep=expand_rule_sets(chain.front(),[&](std::string_view tag) -> RuleSet const* {
        return &chain[std::stoul(std::string(tag))];
    },remaining);
    check(!deep && deep.error().code==ErrorCode::limit,"reference depth limit");

    auto tls=Matcher::compile({{{"protocol","tls",{}}},2});
    auto ech=Matcher::compile({{{"protocol","tls-ech",{}}},2});
    auto plain=Matcher::compile({{{"tls-ech","false",{}}},2});
    auto offered=parse_kdl("schema-version 2\nkind \"predicate\"\ntls-ech #true\n");
    check(tls && ech && plain && offered,"compile TLS predicates");
    auto wire=write_beve(*offered);
    check(wire && parse_beve(*wire) && *parse_beve(*wire)==*offered,"ECH BEVE round trip");
    for (bool has_ech:{false,true}) {
        MatchInput input{.protocol=Protocol::tls,.tls_ech=has_ech};
        check(tls->match_truth_mapped(input)==Truth::yes,"TLS matches either ClientHello");
        check(ech->match_truth_mapped(input)==(has_ech ? Truth::yes : Truth::no),"ECH shorthand");
        check(plain->match_truth_mapped(input)==(has_ech ? Truth::no : Truth::yes),"explicit false");
    }
    check(ech->match_truth_mapped({.protocol=Protocol::tls})==Truth::unknown,"missing ECH metadata");
    check(plain->match_truth_mapped({.protocol=Protocol::http})==Truth::unknown,"outside TLS is unknown");

    std::array instructions{ProgramRule{.action={ProgramActionKind::resolve,0,0,true}}};
    auto program=RouteProgram::compile(instructions,2);
    check(program.has_value(),"route-only resolve compiles");
    auto step=program->next({});
    check(step && *step && (**step).action.route_only,"route-only preserved through compile");
    instructions[0].action.kind=ProgramActionKind::route;
    check(!RouteProgram::compile(instructions,2),"route-only rejected on terminal action");
    std::cout << "PASS KDL/BEVE, rule-set expansion and budgets, TLS ECH three-state, route-only action\n";
}
