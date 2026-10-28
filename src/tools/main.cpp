#include <meta>

import std;

auto nexus_run(int argc, char** argv) -> int;
auto nexus_rule_convert(int argc, char** argv) -> int;

namespace {
    enum class Command { run, rule };
    enum class RuleCommand { convert };

    template<class T>
    auto command(std::string_view text) -> std::optional<T> {
        template for (constexpr auto item : std::define_static_array(std::meta::enumerators_of(^^T))) {
            if (text == std::meta::identifier_of(item)) return [:item:];
        }
        return {};
    }

    template<class T>
    auto list_commands(std::ostream& out) -> void {
        template for (constexpr auto item : std::define_static_array(std::meta::enumerators_of(^^T))) {
            out << "  " << std::meta::identifier_of(item) << '\n';
        }
    }

    auto help(std::ostream& out) -> void {
        out << "usage: nexus <command> [arguments]\ncommands:\n";
        list_commands<Command>(out);
        out << "Use nexus <command> --help for details.\n";
    }

    auto rule(int argc, char** argv) -> int {
        if (argc == 1 || (argc == 2 && std::string_view(argv[1]) == "--help")) {
            auto& out = argc == 1 ? std::cerr : std::cout;
            out << "usage: nexus rule <command> [arguments]\ncommands:\n";
            list_commands<RuleCommand>(out);
            return argc == 1 ? 2 : 0;
        }
        auto selected = command<RuleCommand>(argv[1]);
        if (!selected) { std::cerr << "unknown rule command: " << argv[1] << '\n'; return 2; }
        switch (*selected) {
        case RuleCommand::convert: return nexus_rule_convert(argc - 1, argv + 1);
        }
        return 2;
    }
}

int main(int argc, char** argv) {
    if (argc == 1 || (argc == 2 && std::string_view(argv[1]) == "--help")) {
        help(argc == 1 ? std::cerr : std::cout);
        return argc == 1 ? 2 : 0;
    }
    auto selected = command<Command>(argv[1]);
    if (!selected) { std::cerr << "unknown command: " << argv[1] << '\n'; help(std::cerr); return 2; }
    switch (*selected) {
    case Command::run: return nexus_run(argc - 1, argv + 1);
    case Command::rule: return rule(argc - 1, argv + 1);
    }
    return 2;
}
