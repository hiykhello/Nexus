import std;
import rules;

int main() {
    using namespace ::rules;
    std::size_t checksum=0;
    for (unsigned count : {16U,512U,4000U}) {
        std::vector<ProgramRule> rules;
        for (unsigned i=0;i<count;++i) {
            Rule predicate=i%2 ? Rule{"ip-cidr",std::format("10.{}.{}.0/24",i/256,i%256),{}} :
                                  Rule{"domain",std::format("host-{:04}.long-example-domain.example",i),{}};
            rules.push_back({RuleSet{{std::move(predicate)},2},{ProgramActionKind::route,i%2}});
        }
        auto program=RouteProgram::compile(rules,2);
        if (!program) return 1;
        std::vector<std::string> names,ips;
        for (unsigned i=0;i<64;++i) {
            auto value=i%3==0 ? count+2*i : ((i*37)%count);
            names.push_back(std::format("host-{:04}.long-example-domain.example",value));
            ips.push_back(std::format("10.{}.{}.1",value/256,value%256));
        }
        constexpr unsigned iterations=4000;
        auto start=std::chrono::steady_clock::now();
        for (unsigned i=0;i<iterations;++i) {
            auto result=program->next({.explicit_domain=names[i%64],.ip=ips[i%64]});
            if (!result) return 2;
            checksum+=*result ? (**result).rule_index : count;
        }
        auto ns=std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now()-start).count()/iterations;
        std::cout << "rules=" << count << " ns=" << ns << '\n';
    }
    std::cout << "checksum=" << checksum << '\n';
}
