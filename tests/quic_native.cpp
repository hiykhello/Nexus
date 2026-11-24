import std;
import ngtcp2;

namespace n = ::ngtcp2;
auto main() -> int {
    n::ngtcp2_settings settings{};
    n::ngtcp2_settings_default_versioned(n::settings_version,&settings);
    if (!settings.initial_rtt || settings.max_tx_udp_payload_size<1200 || !settings.handshake_timeout) return 1;
    n::ngtcp2_transport_params parameters{};
    n::ngtcp2_transport_params_default_versioned(n::transport_params_version,&parameters);
    if (parameters.active_connection_id_limit<2 || parameters.max_udp_payload_size<1200) return 2;
    std::array<std::uint8_t,8> bytes{0x83,0x94,0xc8,0xf0,0x3e,0x51,0x57,0x08};
    n::ngtcp2_cid cid{}; n::ngtcp2_cid_init(&cid,bytes.data(),bytes.size());
    if (cid.datalen!=bytes.size() || !std::ranges::equal(std::span(cid.data).first(cid.datalen),bytes)) return 3;
    n::ngtcp2_ccerr error{}; n::ngtcp2_ccerr_default(&error);
    n::ngtcp2_ccerr_set_application_error(&error,233,bytes.data(),bytes.size());
    if (error.error_code!=233 || error.reasonlen!=bytes.size() || !std::ranges::equal(std::span(error.reason,error.reasonlen),bytes)) return 4;
    n::ngtcp2_ccerr_set_liberr(&error,n::err_nomem,nullptr,0);
    if (!error.error_code || !std::string_view(n::ngtcp2_strerror(n::err_nomem)).size()) return 5;
    std::println("Pinned ngtcp2 native C defaults/CID/close-error calls passed; settings={} callbacks={} transport-parameters={}",
        sizeof(settings),sizeof(n::ngtcp2_callbacks),sizeof(parameters));
}
