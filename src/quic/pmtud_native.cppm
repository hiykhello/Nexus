export module quic.pmtud_native;
import std;
import ngtcp2;

// Implemented by the pinned ngtcp2 source patch. Call only at a quiescent
// connection boundary; the function restarts native PMTU discovery.
export namespace quic {
    extern "C" auto nexus_ngtcp2_set_brutal(ngtcp2::ngtcp2_conn*,std::uint64_t,int,std::uint64_t) -> int;
    extern "C" auto nexus_ngtcp2_restart_pmtud(ngtcp2::ngtcp2_conn*,int) -> int;
}
