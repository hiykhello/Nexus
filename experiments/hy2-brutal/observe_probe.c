/* Check the actual candidate's controller identity and observation boundary. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "ngtcp2_conn.h"

extern int nexus_ngtcp2_set_brutal(ngtcp2_conn *, uint64_t, int, ngtcp2_tstamp);
#ifdef NEXUS_TEST_UNINSTRUMENTED
extern int nexus_brutal_is_active(const ngtcp2_cc *);
#else
extern int nexus_brutal_skip_spurious(ngtcp2_cc *, ngtcp2_tstamp);
#endif

int main(void) {
  ngtcp2_conn c;
  memset(&c, 0, sizeof(c));
  c.cstat.max_tx_udp_payload_size = 1200;
  c.cstat.first_rtt_sample_ts = UINT64_MAX;
  c.tx.pacing.next_ts = UINT64_MAX;
  c.flags |= NGTCP2_CONN_FLAG_TLS_HANDSHAKE_COMPLETED;
  c.pktns.crypto.rx.ckm = (ngtcp2_crypto_km *)(uintptr_t)1;
  c.pktns.crypto.tx.ckm = (ngtcp2_crypto_km *)(uintptr_t)1;
#ifdef NEXUS_TEST_UNINSTRUMENTED
  assert(!nexus_brutal_is_active(&c.cc));
  assert(nexus_ngtcp2_set_brutal(&c, 10000, 1, 100) == 0);
  assert(nexus_brutal_is_active(&c.cc));
  c.cc.on_pkt_lost = NULL;
  assert(!nexus_brutal_is_active(&c.cc));
#else
  assert(nexus_ngtcp2_set_brutal(&c, 10000, 1, 100) == 0);
  assert(nexus_brutal_skip_spurious(&c.cc, 99) && c.brutal.late_acks == 0);
  assert(nexus_brutal_skip_spurious(&c.cc, 100) && c.brutal.late_acks == 1);
  c.cc.on_pkt_lost = NULL;
  assert(!nexus_brutal_skip_spurious(&c.cc, 101) && c.brutal.late_acks == 1);
#endif
#ifdef NEXUS_TEST_UNINSTRUMENTED
  puts("Brutal controller identity passed");
#else
  puts("Brutal identity and late-ACK observation boundary passed");
#endif
}
