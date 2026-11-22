import std;
import rules;

// Linux/glibc allocator accounting. Values include chunk rounding and may
// include transient blocks held by glibc's thread cache after compilation.
extern "C" {
    struct MallocInfo {
        std::size_t arena, ordblks, smblks, hblks, hblkhd, usmblks, fsmblks, uordblks, fordblks, keepcost;
    };
    auto mallinfo2() noexcept -> MallocInfo;
}

int main(int argc, char** argv) {
    using namespace ::rules;
    if (argc!=4) return 1;
    auto count=static_cast<unsigned>(std::strtoul(argv[1],nullptr,10));
    std::string_view mode=argv[2], kind=argv[3];
    if (!count || count>4000 || (mode!="matcher" && mode!="program")) return 1;
    auto predicate=[&](unsigned i) -> Rule {
        if (kind=="domain") return {"domain-suffix",std::format("subdomain-{:04}.long-example-domain.example",i),{}};
        if (kind=="ip") return {"ip-cidr",std::format("10.{}.{}.0/24",i/256,i%256),{}};
        if (kind=="mixed") {
            if (i%2) return {"ip-cidr",std::format("10.{}.{}.0/24",i/256,i%256),{}};
            return {"domain",std::format("subdomain-{:04}.long-example-domain.example",i),{}};
        }
        if (kind=="logical") return {"and","",{{"domain-suffix",std::format("site-{:04}.example",i),{}},{"port","443",{}}}};
        std::terminate();
    };
    RuleSet source{{},2};
    std::vector<ProgramRule> program_source;
    for (unsigned i=0;i<count;++i) {
        if (mode=="matcher") source.rules.push_back(predicate(i));
        else program_source.push_back({RuleSet{{predicate(i)},2},{ProgramActionKind::route,0}});
    }
    auto before=mallinfo2();
    std::optional<Matcher> matcher;
    std::optional<RouteProgram> program;
    if (mode=="matcher") {
        auto result=Matcher::compile(source);
        if (!result) return 2;
        matcher.emplace(std::move(*result));
    } else {
        auto result=RouteProgram::compile(program_source,1);
        if (!result) return 2;
        program.emplace(std::move(*result));
    }
    auto after=mallinfo2();
    std::cout << "mode=" << mode << " kind=" << kind << " count=" << count
              << " source_live_bytes=" << (before.uordblks+before.hblkhd)
              << " retained_delta_bytes=" << static_cast<std::int64_t>(after.uordblks+after.hblkhd)-static_cast<std::int64_t>(before.uordblks+before.hblkhd)
              << " rule_object_bytes=" << sizeof(Rule) << " matcher_object_bytes=" << sizeof(Matcher)
              << " program_object_bytes=" << sizeof(RouteProgram) << '\n';
}
