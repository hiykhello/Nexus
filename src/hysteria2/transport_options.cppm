export module hysteria2.transport_options;
import std;
import quic.varint;
import quic.receive_windows;
import hysteria2.auth;
import ngtcp2;

export namespace hysteria2 {
    struct PortRange {
        std::uint16_t first = 0, last = 0;
    };
    struct TransportOptions {
        std::chrono::milliseconds handshake_timeout{10000},idle_timeout{300000};
        std::size_t native_bytes=8*1024*1024;
        bool udp=true;
        // Borrowed immutable secret; its owner must outlive the transport.
        std::optional<std::span<std::uint8_t const>> salamander_password;
        // Physical UDP payload limit, including the optional Salamander salt.
        std::optional<std::size_t> max_udp_payload_size;
        bool disable_path_mtu_discovery=false;
        std::size_t write_stream_data_thresh=0;
        CongestionPolicy congestion;
        quic::ReceiveWindows receive_windows;
        std::vector<PortRange> port_ranges;
        std::chrono::milliseconds hop_interval{0};
        std::chrono::milliseconds hop_interval_max{0};
        auto valid() const noexcept -> bool {
            bool hop_ok = port_ranges.empty()
                ? (hop_interval.count() == 0 && hop_interval_max.count() == 0)
                : (hop_interval >= std::chrono::milliseconds(500) && hop_interval <= std::chrono::hours(24) &&
                   (hop_interval_max.count() == 0 ||
                    (hop_interval_max >= hop_interval && hop_interval_max <= std::chrono::hours(24))) &&
                   std::ranges::all_of(port_ranges, [](PortRange r) { return r.first != 0 && r.first <= r.last; }));
            return hop_ok && handshake_timeout.count()>0 && handshake_timeout<=std::chrono::hours(1) && idle_timeout.count()>0 && idle_timeout<=std::chrono::hours(24) &&
                native_bytes>=65536 && native_bytes<=1024ull*1024*1024 && receive_windows.valid(native_bytes) &&
                write_stream_data_thresh<=65535 &&
                congestion.send_bps<=1000000000000ull && congestion.receive_bps<=1000000000000ull &&
                (!salamander_password || !salamander_password->empty()) &&
                (!max_udp_payload_size || (*max_udp_payload_size>=1200+(salamander_password ? 8 : 0) && *max_udp_payload_size<=1500));
        }
    };
    // Preserve the static default profile for existing users. Explicit
    // windows use the same bounded allocator as native QUIC and HTTP/3.
    template<std::size_t Streams,std::size_t Window>struct TransportProfile {
        static_assert(Streams>=4 && Streams<=65535 && Window>=512 && Window<=quic::max_varint/Streams);
        static auto settings(TransportOptions const& options) noexcept -> std::expected<ngtcp2::ngtcp2_settings,int> {
            namespace n = ::ngtcp2;if(!options.valid())return std::unexpected(n::err_invalid_argument);
            n::ngtcp2_settings result{};n::ngtcp2_settings_default_versioned(n::settings_version,&result);
            result.handshake_timeout=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(options.handshake_timeout).count());
            if(options.max_udp_payload_size)result.max_tx_udp_payload_size=*options.max_udp_payload_size;
            result.no_pmtud=options.disable_path_mtu_discovery;
            result.write_stream_data_thresh=options.write_stream_data_thresh;
            result.max_stream_window=options.receive_windows.max_stream;
            result.max_window=options.receive_windows.max_connection;
            // Reserve the outer salt within the physical UDP payload budget.
            if(options.salamander_password){
                if(result.max_tx_udp_payload_size<1208)return std::unexpected(n::err_invalid_argument);
                result.max_tx_udp_payload_size-=8;
            }
            return result;
        }
        static auto parameters(TransportOptions const& options) noexcept -> std::expected<ngtcp2::ngtcp2_transport_params,int> {
            namespace n = ::ngtcp2;if(!options.valid())return std::unexpected(n::err_invalid_argument);
            n::ngtcp2_transport_params result{};n::ngtcp2_transport_params_default_versioned(n::transport_params_version,&result);
            auto const& windows=options.receive_windows;
            result.initial_max_stream_data_bidi_local=result.initial_max_stream_data_bidi_remote=
                windows.configured() ? windows.initial_stream : Window;
            result.initial_max_stream_data_uni=16384;
            result.initial_max_data=windows.configured() ? windows.initial_connection : Streams*Window+3*16384;
            result.initial_max_streams_bidi=Streams;result.initial_max_streams_uni=3;result.active_connection_id_limit=4;
            result.max_idle_timeout=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(options.idle_timeout).count());
            result.max_datagram_frame_size=options.udp ? 65535 : 0;result.disable_active_migration=1;return result;
        }
    };
}
