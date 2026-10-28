import std;
import nexus.rules;
import nexus.rulefile;

auto nexus_rule_convert(int argc, char** argv) -> int {
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
        std::cout << "usage: nexus rule convert <kdl|beve> <beve|kdl> <input> <new-output>\n";
        return 0;
    }
    if (argc != 5 || !((std::string_view(argv[1]) == "kdl" && std::string_view(argv[2]) == "beve") ||
                       (std::string_view(argv[1]) == "beve" && std::string_view(argv[2]) == "kdl"))) {
        std::cerr << "usage: nexus rule convert <kdl|beve> <beve|kdl> <input> <new-output>\n";
        return 2;
    }
    auto input = nexus::rulefile::read_regular_file(argv[3]);
    if (!input) {
        std::cerr << argv[3] << ": " << input.error() << '\n';
        return 1;
    }
    bool from_kdl = std::string_view(argv[1]) == "kdl";
    auto rules = from_kdl ? nexus::rules::parse_kdl(*input) : nexus::rules::parse_beve(*input);
    if (!rules) {
        std::cerr << argv[3] << ": " << rules.error().message << '\n';
        return 1;
    }
    auto output = from_kdl ? nexus::rules::write_beve(*rules) : nexus::rules::write_kdl(*rules);
    if (!output) {
        std::cerr << "encode: " << output.error().message << '\n';
        return 1;
    }
    auto verified = from_kdl ? nexus::rules::parse_beve(*output) : nexus::rules::parse_kdl(*output);
    if (!verified || !(*verified == *rules)) {
        std::cerr << "output verification failed\n";
        return 1;
    }
    auto published = nexus::rulefile::publish_new_file(argv[4], *output);
    if (!published) {
        std::cerr << argv[4] << ": " << published.error() << '\n';
        return 1;
    }
    return 0;
}
