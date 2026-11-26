export module tuic.transport_options;
import std;
import tuic.wire;
import ngtcp2;

export namespace tuic {
    enum class CongestionControl : std::uint8_t { cubic, reno, bbr };

    struct ClientTransportOptions {
        std::chrono::milliseconds handshake_timeout{10000};
        std::chrono::milliseconds idle_timeout{60000};
        std::chrono::milliseconds heartbeat{10000};
        std::size_t native_bytes = 8 * 1024 * 1024;
        CongestionControl cc = CongestionControl::cubic;
        bool udp_over_stream = false;
        bool zero_rtt_handshake = false;
        auto valid() const noexcept -> bool {
            return handshake_timeout.count() > 0 && handshake_timeout <= std::chrono::hours(1) &&
                idle_timeout.count() > 0 && idle_timeout <= std::chrono::hours(24) &&
                heartbeat.count() > 0 && heartbeat <= std::chrono::hours(1) &&
                native_bytes >= 65536 && native_bytes <= 1024ull * 1024 * 1024;
        }
    };

    inline auto apply_tuic_quic_config(
        ClientTransportOptions const& opts,
        std::size_t streams,
        std::size_t window,
        ngtcp2::ngtcp2_settings& settings,
        ngtcp2::ngtcp2_transport_params& params) noexcept -> void {
        namespace n = ::ngtcp2;
        n::ngtcp2_settings_default_versioned(n::settings_version, &settings);
        settings.handshake_timeout = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(opts.handshake_timeout).count());
        settings.cc_algo = opts.cc == CongestionControl::bbr ? n::NGTCP2_CC_ALGO_BBR :
                           opts.cc == CongestionControl::reno ? n::NGTCP2_CC_ALGO_RENO :
                           n::NGTCP2_CC_ALGO_CUBIC;
        n::ngtcp2_transport_params_default_versioned(n::transport_params_version, &params);
        params.initial_max_stream_data_bidi_local = window;
        params.initial_max_stream_data_bidi_remote = window;
        params.initial_max_stream_data_uni = 32768;
        params.initial_max_data = streams * window + 1024 * 16384ull;
        params.initial_max_streams_bidi = streams;
        params.initial_max_streams_uni = 1024;
        params.active_connection_id_limit = 4;
        params.max_idle_timeout = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(opts.idle_timeout).count());
        params.max_datagram_frame_size = 65535;
        params.disable_active_migration = 1;
    }
}
