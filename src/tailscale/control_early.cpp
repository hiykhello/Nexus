module tailscale.control_early;
import std;
import nexus.compat;
import tailscale.control;
import tailscale.control_http;
import nexus.thirdparty.glaze;

namespace tailscale::control_early {
    namespace detail {
        struct Options : nex::glaze::opts {bool validate_trailing_whitespace=true,validate_skipped=true;};
        inline constexpr auto options=[] {Options value;value.null_terminated=false;value.error_on_unknown_keys=true;return value;}();
        inline auto hex(char c) noexcept -> int {return c>='0' && c<='9' ? c-'0' : c>='a' && c<='f' ? c-'a'+10 : c>='A' && c<='F' ? c-'A'+10 : -1;}
    }
    // One narrow EarlyNoise schema. The public challenge is a hint for a
    // future node-key proof, never an authorization result. Unknown/duplicate
    // or escaped identity fields are a stricter local rejection than Go JSON.
    auto parse(std::span<std::uint8_t const> input) -> std::expected<Info,Error> {
        if (input.size()>control_http::max_early_payload) return std::unexpected(Error::capacity);
        std::string_view json(reinterpret_cast<char const*>(input.data()),input.size());
        auto space=[](char c) {return c==' ' || c=='\t' || c=='\r' || c=='\n';};
        while (!json.empty() && space(json.front())) json.remove_prefix(1);
        if (json.empty() || json.front()!='{') return std::unexpected(Error::json);
        nexus::inplace_vector<std::pair<std::string_view,std::string_view>,1> fields;
        if (nex::glaze::read<detail::options>(fields,json)) return std::unexpected(Error::json);
        Info result;
        if (fields.empty()) return result;
        if (fields[0].first!="nodeKeyChallenge") return std::unexpected(Error::schema);
        auto text=fields[0].second;constexpr std::string_view prefix="chalpub:";
        if (text.size()!=prefix.size()+64 || !text.starts_with(prefix)) return std::unexpected(Error::identity);
        control::KeyBytes bytes{};
        for (unsigned i=0;i<32;++i) {auto a=detail::hex(text[prefix.size()+i*2]),b=detail::hex(text[prefix.size()+i*2+1]);
            if (a<0 || b<0) return std::unexpected(Error::identity);bytes[i]=static_cast<std::uint8_t>(a*16+b);}
        auto key=ChallengePublic::from_bytes(bytes);if (!key) return std::unexpected(Error::identity);
        result.challenge=*key;result.present=true;return result;
    }
}
