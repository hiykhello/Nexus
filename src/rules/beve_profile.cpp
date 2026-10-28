module nexus.rules;
import std;

namespace nexus::rules {
    namespace {
        // The v1 profile only uses these BEVE types. Glaze performs the actual decoding;
        // this pass rejects duplicate keys, which its object reader otherwise overwrites.
        constexpr std::uint8_t object_tag = 3;
        constexpr std::uint8_t array_tag = 5;
        constexpr std::uint8_t string_tag = 2;
        constexpr std::uint8_t u32_tag = 0x51;

        class ProfileReader {
            std::string_view input_;
            std::size_t offset_ = 0;

            auto byte() -> std::uint8_t {
                return static_cast<std::uint8_t>(input_[offset_++]);
            }

            auto tag(std::uint8_t expected) -> bool {
                return offset_ < input_.size() && byte() == expected;
            }

            auto count(std::uint64_t& value) -> bool {
                if (offset_ == input_.size()) return false;
                auto width = std::size_t{1} << (static_cast<std::uint8_t>(input_[offset_]) & 3U);
                if (width > input_.size() - offset_) return false;
                std::uint64_t packed = 0;
                for (std::size_t i = 0; i < width; ++i) packed |= std::uint64_t(byte()) << (8 * i);
                value = packed >> 2;
                return true;
            }

            auto raw_string(std::string_view& value) -> bool {
                std::uint64_t length = 0;
                if (!count(length) || length > 253 || length > input_.size() - offset_) return false;
                value = input_.substr(offset_, static_cast<std::size_t>(length));
                offset_ += static_cast<std::size_t>(length);
                return true;
            }

            auto string_value() -> bool {
                std::string_view value;
                return tag(string_tag) && raw_string(value);
            }

            auto rule() -> bool {
                std::uint64_t fields = 0;
                if (!tag(object_tag) || !count(fields) || fields != 2) return false;
                unsigned seen = 0;
                for (unsigned i = 0; i < fields; ++i) {
                    std::string_view key;
                    if (!raw_string(key)) return false;
                    unsigned bit = key == "type" ? 1U : key == "value" ? 2U : 0U;
                    if (bit == 0 || (seen & bit) || !string_value()) return false;
                    seen |= bit;
                }
                return seen == 3;
            }

            auto rules() -> bool {
                std::uint64_t entries = 0;
                if (!tag(array_tag) || !count(entries) || entries > max_rules) return false;
                for (std::uint64_t i = 0; i < entries; ++i) if (!rule()) return false;
                return true;
            }

            auto version() -> bool {
                if (!tag(u32_tag) || input_.size() - offset_ < 4) return false;
                offset_ += 4;
                return true;
            }

        public:
            explicit ProfileReader(std::string_view input) : input_(input) {}

            auto valid() -> bool {
                std::uint64_t fields = 0;
                if (!tag(object_tag) || !count(fields) || fields != 3) return false;
                unsigned seen = 0;
                for (unsigned i = 0; i < fields; ++i) {
                    std::string_view key;
                    if (!raw_string(key)) return false;
                    unsigned bit = key == "schema_version" ? 1U : key == "kind" ? 2U : key == "rules" ? 4U : 0U;
                    if (bit == 0 || (seen & bit)) return false;
                    seen |= bit;
                    if (bit == 1 && !version()) return false;
                    if (bit == 2 && !string_value()) return false;
                    if (bit == 4 && !rules()) return false;
                }
                return seen == 7 && offset_ == input_.size();
            }
        };
    }

    auto valid_beve_profile(std::string_view payload) -> bool {
        return ProfileReader(payload).valid();
    }
}
