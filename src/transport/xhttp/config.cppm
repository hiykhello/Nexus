export module xhttp.config;
import std;

export namespace xhttp {
    enum class Mode { automatic, stream_one, packet_up, stream_up };
    enum class HttpVersion { http1, http2, http3 };
    enum class Placement { referer, query, header };

    struct Padding {
        std::uint16_t minimum=100,maximum=1000;
        Placement placement=Placement::referer;
        std::string header="x-padding";
        auto operator==(Padding const&) const -> bool = default;
    };

    struct MuxLimits {
        std::uint16_t concurrency=8,connections=4;
        std::uint32_t reuse_times=0,lifetime_ms=0,requests=0,reusable_seconds=0;
        [[nodiscard]] auto valid() const noexcept -> bool {
            return concurrency>=1 && concurrency<=256 && connections>=1 && connections<=64 &&
                reuse_times<=1000000 && requests<=10000000 && lifetime_ms<=86400000 && reusable_seconds<=86400;
        }
        auto operator==(MuxLimits const&) const -> bool = default;
    };

    struct Limits {
        std::size_t post_bytes=1024*1024,buffer_bytes=8*1024*1024;
        std::uint16_t buffered_posts=30,sessions=64;
        std::chrono::milliseconds post_interval{30},pair_timeout{30000};
        [[nodiscard]] auto valid() const noexcept -> bool {
            return post_bytes>=1 && post_bytes<=8*1024*1024 && buffer_bytes>=post_bytes &&
                buffer_bytes<=64*1024*1024 && buffered_posts>=1 && buffered_posts<=256 &&
                sessions>=1 && sessions<=1024 && post_interval>=std::chrono::milliseconds::zero() &&
                post_interval<=std::chrono::seconds(1) && pair_timeout>=std::chrono::milliseconds(100) &&
                pair_timeout<=std::chrono::minutes(2);
        }
        auto operator==(Limits const&) const -> bool = default;
    };

    struct Endpoint {
        std::string authority,path="/";
        HttpVersion version=HttpVersion::http2;
        auto operator==(Endpoint const&) const -> bool = default;
    };

    struct Download {
        Endpoint endpoint;
        std::string host,server_name,ca_file;
        std::uint16_t port=0;
        auto operator==(Download const&) const -> bool = default;
    };

    struct Profile {
        Endpoint endpoint;
        std::optional<Download> download;
        Mode mode=Mode::automatic;
        Padding padding;
        MuxLimits mux;
        Limits limits;
        std::vector<std::pair<std::string,std::string>> headers;
        bool no_grpc_header=false;
        auto operator==(Profile const&) const -> bool = default;
    };

    // The pinned Xray reference defaults ordinary HTTP to packet-up and
    // selects streaming modes for REALITY according to downlink topology.
    [[nodiscard]] constexpr auto select_mode(Mode mode,HttpVersion version,bool reality,bool separate) noexcept -> Mode {
        if (mode!=Mode::automatic) return mode;
        if (version==HttpVersion::http1 || !reality) return Mode::packet_up;
        return separate ? Mode::stream_up : Mode::stream_one;
    }

    [[nodiscard]] constexpr auto mode_supported(Mode mode,HttpVersion up,HttpVersion down,bool separate) noexcept -> bool {
        if (mode==Mode::packet_up) return true;
        if (mode==Mode::stream_one) return !separate && up!=HttpVersion::http1;
        return mode==Mode::stream_up && up!=HttpVersion::http1 && down!=HttpVersion::http1;
    }
}
