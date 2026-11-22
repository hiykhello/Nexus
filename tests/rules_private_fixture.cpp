import std;
import rules;

int main() {
    using namespace ::rules;
    auto matcher=Matcher::compile(RuleSet{{{"ip-is-private","true",{}}},2});
    if (!matcher) return 1;
    std::string line;
    while (std::getline(std::cin,line)) {
        auto result=matcher->match({.ip=line});
        if (!result) return 2;
        std::cout << (result->has_value() ? '1' : '0') << '\n';
    }
}
