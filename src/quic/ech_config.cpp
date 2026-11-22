module quic.ech_config;
import std;
import rulefile;

namespace quic {
    namespace {
        using Bytes = std::span<const std::uint8_t>;
        constexpr std::uint16_t ech_version = 0xfe0d;

        struct Reader {
            Bytes remaining;
            auto number(std::size_t width) -> std::optional<std::uint16_t> {
                if (remaining.size() < width) return {};
                std::uint16_t value = 0;
                for (auto byte : remaining.first(width)) value = static_cast<std::uint16_t>((value << 8) | byte);
                remaining = remaining.subspan(width);
                return value;
            }

            auto vector(std::size_t length_width) -> std::optional<Bytes> {
                auto length = number(length_width);
                if (!length || remaining.size() < *length) return {};
                auto bytes = remaining.first(*length);
                remaining = remaining.subspan(*length);
                return bytes;
            }
        };

        auto digit(char c) noexcept -> bool { return c >= '0' && c <= '9'; }

        auto valid_public_name(std::string_view name) noexcept -> bool {
            if (name.empty() || name.size() > 253 || name.back() == '.') return false;
            std::string_view final_label;
            for (auto part : name | std::views::split('.')) {
                std::string_view label(part);
                if (label.empty() || label.size() > 63 || label.front() == '-' || label.back() == '-' ||
                    !std::ranges::all_of(label, [](char c) {
                        return digit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-';
                    })) return false;
                final_label = label;
            }
            auto hex_digit = [](char c) { return digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); };
            return !std::ranges::all_of(final_label, digit) &&
                !((final_label.starts_with("0x") || final_label.starts_with("0X")) &&
                   std::ranges::all_of(final_label.substr(2), hex_digit));
        }

        auto parse_config(Bytes contents, Bytes wire) -> std::optional<EchConfig> {
            Reader reader{contents};
            auto id = reader.number(1);
            auto kem = reader.number(2);
            auto key = reader.vector(2);
            auto suites = reader.vector(2);
            auto max_name = reader.number(1);
            auto name = reader.vector(1);
            auto extensions = reader.vector(2);
            if (!id || kem != 0x0020 || !key || key->size() != 32 || !suites || suites->size() % 4 ||
                !max_name || !name || name->empty() || !extensions || !reader.remaining.empty()) return {};

            std::bitset<65536> seen;
            Reader ext{*extensions};
            while (!ext.remaining.empty()) {
                auto type = ext.number(2);
                if (!type || (*type & 0x8000) || seen.test(*type) || !ext.vector(2)) return {};
                seen.set(*type);
            }
            std::string_view public_name(reinterpret_cast<char const*>(name->data()), name->size());
            if (!valid_public_name(public_name)) return {};

            Reader suite{*suites};
            while (!suite.remaining.empty()) {
                auto kdf = *suite.number(2);
                auto aead = *suite.number(2);
                if (kdf != 1 || aead < 1 || aead > 3) continue;
                EchConfig chosen{static_cast<std::uint8_t>(*id), static_cast<std::uint8_t>(*max_name), aead,
                                 {}, std::string(public_name), {wire.begin(), wire.end()}};
                std::ranges::copy(*key, chosen.public_key.begin());
                return chosen;
            }
            return {};
        }
    }

    auto select_ech_config(Bytes list) -> std::expected<EchConfig, EchConfigError> {
        Reader outer{list};
        auto list_body = outer.vector(2);
        if (!list_body || list_body->empty() || !outer.remaining.empty())
            return std::unexpected(EchConfigError::malformed);
        Reader configs{*list_body};
        std::optional<EchConfig> chosen;
        while (!configs.remaining.empty()) {
            auto start = configs.remaining;
            auto version = configs.number(2);
            auto contents = configs.vector(2);
            if (!version || !contents) return std::unexpected(EchConfigError::malformed);
            if (!chosen && *version == ech_version) chosen = parse_config(*contents, start.first(contents->size() + 4));
        }
        if (!chosen) return std::unexpected(EchConfigError::unsupported);
        return std::move(*chosen);
    }

    auto read_ech_config(std::string_view path) -> std::expected<EchConfig, std::string> {
        auto file = rulefile::read_regular_file(path);
        if (!file) return std::unexpected("cannot read ECH configuration: " + file.error());
        auto bytes = Bytes(reinterpret_cast<const std::uint8_t*>(file->data()), file->size());
        auto config = select_ech_config(bytes);
        if (!config) return std::unexpected("ECHConfigList is malformed or has no supported configuration");
        return std::move(*config);
    }
}
