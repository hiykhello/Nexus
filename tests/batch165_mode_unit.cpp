import std;
import rules;
import rules.kdl_predicate;
import glaze;

namespace {
    auto expect(bool ok, std::string_view msg) -> void {
        if (!ok) {
            std::cerr << "FAIL: " << msg << '\n';
            std::exit(1);
        }
    }
}

int main() {
    using namespace rules;
    expect(parse_route_mode("rule") == RouteMode::rule, "parse rule");
    expect(parse_route_mode("global") == RouteMode::global, "parse global");
    expect(parse_route_mode("direct") == RouteMode::direct, "parse direct");
    expect(!parse_route_mode("other").has_value(), "reject invalid mode");
    expect(route_mode_name(RouteMode::global) == "global", "mode name");

    RuleSet r1;
    r1.version = 2;
    r1.rules.push_back(Rule{"domain-suffix", "blocked.test", {}});
    RuleSet r2;
    r2.version = 2;
    r2.rules.push_back(Rule{"route-mode", "rule", {}});
    r2.rules.push_back(Rule{"domain", "example.com", {}});

    std::vector<rules::RouteRule> routes{
        rules::RouteRule{r1, 1, 0},
        rules::RouteRule{r2, 2, 1},
    };
    auto compiled = RouteMatcher::compile(routes, 0, 4);
    expect(compiled.has_value(), "compile RouteMatcher");
    auto matcher = std::move(*compiled);

    auto dist = std::make_shared<OutboundDistribution>(4, std::vector<std::vector<std::size_t>>{{2, 3}});
    matcher.set_distribution(dist);

    auto state = std::make_shared<RuntimeRouteMode>();
    state->mode.store(RouteMode::rule, std::memory_order_release);
    state->global_outbound.store(2, std::memory_order_release);
    matcher.set_runtime_mode(state);

    // 1. rule mode evaluates normal predicates + route-mode="rule"
    auto m_block = matcher.match_with_rule(MatchInput{.domain = "sub.blocked.test", .port = 443, .network = Network::tcp});
    expect(m_block && m_block->outbound == 1, "rule mode matches block");
    auto m_ex = matcher.match_with_rule(MatchInput{.domain = "example.com", .port = 443, .network = Network::tcp});
    expect(m_ex && m_ex->outbound == 2, "rule mode matches example.com");
    auto pf_rule = matcher.preflight("example.com");
    expect(pf_rule && *pf_rule == 2, "preflight in rule mode");

    // 2. direct mode overrides rules -> outbound 0 (no recompile)
    state->mode.store(RouteMode::direct, std::memory_order_release);
    auto m_dir = matcher.match_with_rule(MatchInput{.domain = "sub.blocked.test", .port = 443, .network = Network::tcp});
    expect(m_dir && m_dir->outbound == 0 && !m_dir->rule.has_value(), "direct mode bypasses block");
    auto pf_dir = matcher.preflight("sub.blocked.test");
    expect(pf_dir && *pf_dir == 0, "preflight in direct mode returns 0");

    // 3. global mode sends to configured global outbound (including distributed group index >= 4)
    state->mode.store(RouteMode::global, std::memory_order_release);
    state->global_outbound.store(3, std::memory_order_release);
    auto m_glob = matcher.match_with_rule(MatchInput{.domain = "sub.blocked.test", .port = 443, .network = Network::tcp});
    expect(m_glob && m_glob->outbound == 3 && !m_glob->rule.has_value(), "global mode routes to outbound 3");
    state->global_outbound.store(4, std::memory_order_release);
    auto m_lb = matcher.match_with_rule(MatchInput{.domain = "host.example", .port = 443, .network = Network::tcp});
    expect(m_lb && (m_lb->outbound == 2 || m_lb->outbound == 3), "global mode distributes across load-balance group");

    // 4. RouteProgram supports route-mode predicate & KDL predicate decoding
    auto doc = glaze::read_kdl<glaze::KdlDocument>("route-mode \"rule\"");
    expect(doc && doc->size() == 1, "parse KDL route-mode");
    std::size_t kcount = 0;
    auto kpred = decode_kdl_predicate((*doc)[0], 1, kcount);
    expect(kpred && kpred->type == "route-mode" && kpred->value == "rule", "decode KDL route-mode");

    std::vector<ProgramRule> prog_rules{
        ProgramRule{RuleSet{{*kpred}, 2}, ProgramAction{ProgramActionKind::route, 2}, DomainSource::explicit_target},
    };
    auto prog = RouteProgram::compile(prog_rules, 4);
    expect(prog.has_value(), "compile RouteProgram with route-mode");
    auto s_rule = prog->next(ProgramInput{.port = 443, .network = Network::tcp, .route_mode = RouteMode::rule});
    expect(s_rule && *s_rule && (*s_rule)->action.outbound == 2, "program matches route_mode=rule");
    auto s_glob = prog->next(ProgramInput{.port = 443, .network = Network::tcp, .route_mode = RouteMode::global});
    expect(s_glob && !s_glob->has_value(), "program skips route_mode=rule when global");

    std::cout << "BATCH 165 RUNTIME ROUTE MODE UNIT TESTS PASSED\n";
    return 0;
}
