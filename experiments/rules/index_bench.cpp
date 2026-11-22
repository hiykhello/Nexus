import std;
import rules;

int main() {
    using namespace ::rules;
    constexpr unsigned iterations=20000;
    std::uint64_t checksum=0;
    for (unsigned count : {16U,512U,4000U}) {
        RuleSet indexed{{},2},linear{{},2};
        for (unsigned i=0;i<count;++i) {
            Rule rule=i%2 ? Rule{"ip-cidr",std::format("10.{}.{}.0/24",(i/2)/256,(i/2)%256),{}} :
                            Rule{"domain-suffix",std::format("site{}.example",i/2),{}};
            indexed.rules.push_back(rule);
            linear.rules.push_back({"and","",{std::move(rule)}});
        }
        auto fast=Matcher::compile(indexed),reference=Matcher::compile(linear);
        if (!fast || !reference) return 1;
        std::vector<std::string> names,ips;
        for (unsigned i=0;i<64;++i) {
            auto value=i%3==0 ? count/2+100+i : (i*37)%(count/2);
            names.push_back(std::format("www.site{}.example",value));
            ips.push_back(std::format("10.{}.{}.1",value/256,value%256));
        }
        for (unsigned i=0;i<64;++i) {
            MatchInput input{.domain=names[i],.ip=ips[(i*13)%64]};
            auto a=fast->match(input), b=reference->match(input);
            if (!a || !b || *a!=*b) return 2;
        }
        auto run=[&](Matcher const& matcher) {
            auto start=std::chrono::steady_clock::now();
            for (unsigned i=0;i<iterations;++i) {
                auto result=matcher.match({.domain=names[i%64],.ip=ips[(i*13)%64]});
                if (!result) std::terminate();
                checksum+=result->value_or(count);
            }
            return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now()-start).count()/iterations;
        };
        for (unsigned repeat=0;repeat<3;++repeat) {
            auto first=repeat%2 ? run(*reference) : run(*fast);
            auto second=repeat%2 ? run(*fast) : run(*reference);
            auto index_ns=repeat%2 ? second : first,linear_ns=repeat%2 ? first : second;
            std::cout << "rules=" << count << " repeat=" << repeat << " indexed_ns=" << index_ns
                      << " linear_ns=" << linear_ns << '\n';
        }
    }
    std::cout << "checksum=" << checksum << '\n';
}
