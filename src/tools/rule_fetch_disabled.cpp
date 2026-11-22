import std;

auto nexus_rule_fetch(int,char**) -> int {
    std::cerr << "HTTP rule fetch is unavailable in this build\n";
    return 1;
}

auto nexus_rule_watch(int,char**) -> int {
    std::cerr << "HTTP rule watch is unavailable in this build\n";
    return 1;
}
