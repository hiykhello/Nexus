module tailscale.derp_info;
import std;
import nexus.thirdparty.glaze;

namespace tailscale::derp {
    namespace detail {
        struct JsonServerInfo {
            std::int64_t version=0,TokenBucketBytesPerSecond=0,TokenBucketBytesBurst=0;
        };
    }
    namespace {
        using detail::JsonServerInfo;
        struct ReadOptions : nex::glaze::opts {
            bool validate_trailing_whitespace=true;
            bool validate_skipped=true;
        };
        inline constexpr auto options=[] {
            ReadOptions result;
            result.null_terminated=false;
            result.error_on_unknown_keys=false;
            return result;
        }();
    }
    auto parse_server_settings(std::span<std::uint8_t const> input) -> std::expected<ServerSettings,InfoError> {
        if (input.empty() || input.size()>max_info_plaintext) return std::unexpected(InfoError::size);
        auto text=std::string_view(reinterpret_cast<char const*>(input.data()),input.size());
        JsonServerInfo result;
        if (nex::glaze::read<options>(result,text)) return std::unexpected(InfoError::json);
        if (result.version!=2) return std::unexpected(InfoError::version);
        if (result.TokenBucketBytesPerSecond<0 || result.TokenBucketBytesBurst<0) return std::unexpected(InfoError::rate);
        return ServerSettings{2,static_cast<std::uint64_t>(result.TokenBucketBytesPerSecond),static_cast<std::uint64_t>(result.TokenBucketBytesBurst)};
    }
}

