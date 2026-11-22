import std;
import rules;
import rules.rule_input;
import rulefile;

auto nexus_rule_convert(int argc, char** argv) -> int {
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
        std::cout << "usage: nexus rule convert <kdl|beve|srs> <beve|kdl> <input> <new-output>\n";
        return 0;
    }
    if (argc != 5 || !((std::string_view(argv[1]) == "kdl" && std::string_view(argv[2]) == "beve") ||
                       (std::string_view(argv[1]) == "beve" && std::string_view(argv[2]) == "kdl") ||
                       (std::string_view(argv[1]) == "srs" && (std::string_view(argv[2]) == "kdl" || std::string_view(argv[2]) == "beve")))) {
        std::cerr << "usage: nexus rule convert <kdl|beve|srs> <beve|kdl> <input> <new-output>\n";
        return 2;
    }
    auto input = ::rulefile::read_regular_file(argv[3]);
    if (!input) {
        std::cerr << argv[3] << ": " << input.error() << '\n';
        return 1;
    }
    auto source=std::string_view(argv[1]);
    auto format=source=="kdl" ? ::rules::InputFormat::kdl : source=="beve" ? ::rules::InputFormat::beve : ::rules::InputFormat::srs;
    auto rules = ::rules::parse_rule_input(*input,format);
    if (!rules) {
        std::cerr << argv[3] << ": " << rules.error().message << '\n';
        return 1;
    }
    bool to_beve=std::string_view(argv[2])=="beve";
    auto output = to_beve ? ::rules::write_beve(*rules) : ::rules::write_kdl(*rules);
    if (!output) {
        std::cerr << "encode: " << output.error().message << '\n';
        return 1;
    }
    auto verified = to_beve ? ::rules::parse_beve(*output) : ::rules::parse_kdl(*output);
    if (!verified || !(*verified == *rules)) {
        std::cerr << "output verification failed\n";
        return 1;
    }
    auto published = ::rulefile::publish_new_file(argv[4], *output);
    if (!published) {
        std::cerr << argv[4] << ": " << published.error() << '\n';
        return 1;
    }
    return 0;
}
