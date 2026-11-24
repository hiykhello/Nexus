import std;
import rules;
import rules.rule_input;
import rules.convert_external;
import rulefile;

namespace {
    auto parse_format(std::string_view name) -> std::optional<::rules::InputFormat> {
        using enum ::rules::InputFormat;
        if (name == "kdl") return kdl;
        if (name == "beve") return beve;
        if (name == "srs") return srs;
        if (name == "nxmm") return nxmm;
        if (name == "json") return json;
        if (name == "domain-list") return domain_list;
        if (name == "ipcidr-list") return ipcidr_list;
        if (name == "classical") return classical;
        if (name == "adguard") return adguard;
        return {};
    }

    auto valid_target_format(std::string_view fmt) noexcept -> bool {
        return fmt == "beve" || fmt == "kdl" || fmt == "nxmm";
    }

    auto read_source(std::string_view path) -> std::expected<std::string, std::string> {
        if (path == "-") {
            std::string data;
            std::array<char, 8192> chunk{};
            while (std::cin.read(chunk.data(), static_cast<std::streamsize>(chunk.size())) || std::cin.gcount() > 0) {
                auto n = static_cast<std::size_t>(std::cin.gcount());
                if (n > ::rules::max_input_bytes - data.size())
                    return std::unexpected("stdin input exceeds 32 MiB");
                data.append(chunk.data(), n);
                if (std::cin.eof()) break;
            }
            if (std::cin.bad()) return std::unexpected("failed reading stdin");
            return data;
        }
        return ::rulefile::read_regular_file(path);
    }

    auto write_target(std::string_view path, std::string_view output, bool overwrite) -> std::expected<void, std::string> {
        if (path == "-") {
            std::cout.write(output.data(), static_cast<std::streamsize>(output.size()));
            if (!std::cout) return std::unexpected("failed writing stdout");
            return {};
        }
        return overwrite ? ::rulefile::replace_file(path, output) : ::rulefile::publish_new_file(path, output);
    }

    auto encode_verified(::rules::RuleSet const& rules, std::string_view target_fmt) -> std::expected<std::string, std::string> {
        if (target_fmt == "nxmm") {
            auto output = ::rules::compile_nxmm(rules);
            if (!output) return std::unexpected("encode: " + output.error().message);
            auto mapped = ::rules::MmapMatcher::open_bytes(*output);
            if (!mapped) return std::unexpected("output verification failed: " + mapped.error());
            auto roundtrip = ::rules::nxmm_to_ruleset(*mapped);
            if (!roundtrip || !::rules::Matcher::compile(*roundtrip))
                return std::unexpected("output verification failed");
            return *std::move(output);
        }
        bool to_beve = target_fmt == "beve";
        auto output = to_beve ? ::rules::write_beve(rules) : ::rules::write_kdl(rules);
        if (!output) return std::unexpected("encode: " + output.error().message);
        auto verified = to_beve ? ::rules::parse_beve(*output) : ::rules::parse_kdl(*output);
        if (!verified || !(*verified == rules)) return std::unexpected("output verification failed");
        return *std::move(output);
    }
}

auto nexus_rule_convert(int argc, char** argv) -> int {
    constexpr std::string_view usage =
        "usage: nexus rule convert [--overwrite] [--lenient] "
        "<kdl|beve|srs|nxmm|json|domain-list|ipcidr-list|classical|adguard> <beve|kdl|nxmm> <input|-> <output|->\n";
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
        std::cout << usage;
        return 0;
    }
    bool overwrite = false, lenient = false;
    std::vector<std::string_view> pos;
    for (int i = 1; i < argc; ++i) {
        std::string_view arg(argv[i]);
        if (arg == "--overwrite") overwrite = true;
        else if (arg == "--lenient") lenient = true;
        else pos.push_back(arg);
    }
    if (pos.size() != 4 || !valid_target_format(pos[1]) || pos[0] == pos[1]) {
        std::cerr << usage;
        return 2;
    }
    auto format = parse_format(pos[0]);
    if (!format) {
        std::cerr << usage;
        return 2;
    }
    auto input = read_source(pos[2]);
    if (!input) {
        std::cerr << pos[2] << ": " << input.error() << '\n';
        return 1;
    }
    auto rules = ::rules::parse_rule_input(*input, *format, false, lenient);
    if (!rules) {
        std::cerr << pos[2] << ": " << rules.error().message << '\n';
        return 1;
    }
    auto output = encode_verified(*rules, pos[1]);
    if (!output) {
        std::cerr << output.error() << '\n';
        return 1;
    }
    auto published = write_target(pos[3], *output, overwrite);
    if (!published) {
        std::cerr << pos[3] << ": " << published.error() << '\n';
        return 1;
    }
    return 0;
}

auto nexus_rule_merge(int argc, char** argv) -> int {
    constexpr std::string_view usage =
        "usage: nexus rule merge [--overwrite] [--lenient] <beve|kdl|nxmm> <output|-> <format:path>...\n";
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
        std::cout << usage;
        return 0;
    }
    bool overwrite = false, lenient = false;
    std::vector<std::string_view> pos;
    for (int i = 1; i < argc; ++i) {
        std::string_view arg(argv[i]);
        if (arg == "--overwrite") overwrite = true;
        else if (arg == "--lenient") lenient = true;
        else pos.push_back(arg);
    }
    if (pos.size() < 3 || !valid_target_format(pos[0])) {
        std::cerr << usage;
        return 2;
    }
    std::vector<::rules::RuleSet> parsed_sets;
    parsed_sets.reserve(pos.size() - 2);
    for (std::size_t i = 2; i < pos.size(); ++i) {
        auto colon = pos[i].find(':');
        if (colon == std::string_view::npos) {
            std::cerr << "expected <format:path>, got: " << pos[i] << '\n';
            return 2;
        }
        auto fmt = parse_format(pos[i].substr(0, colon));
        auto path = pos[i].substr(colon + 1);
        if (!fmt || path.empty()) {
            std::cerr << "invalid input specification: " << pos[i] << '\n';
            return 2;
        }
        auto raw = read_source(path);
        if (!raw) {
            std::cerr << path << ": " << raw.error() << '\n';
            return 1;
        }
        auto parsed = ::rules::parse_rule_input(*raw, *fmt, false, lenient);
        if (!parsed) {
            std::cerr << path << ": " << parsed.error().message << '\n';
            return 1;
        }
        parsed_sets.push_back(std::move(*parsed));
    }
    auto merged = ::rules::merge_rule_sets(parsed_sets);
    if (!merged) {
        std::cerr << "merge: " << merged.error().message << '\n';
        return 1;
    }
    auto output = encode_verified(*merged, pos[0]);
    if (!output) {
        std::cerr << output.error() << '\n';
        return 1;
    }
    auto published = write_target(pos[1], *output, overwrite);
    if (!published) {
        std::cerr << pos[1] << ": " << published.error() << '\n';
        return 1;
    }
    return 0;
}
