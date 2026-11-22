/* Exercise both native pacing timer paths using the isolated candidate source. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "ngtcp2_conn.c"

int main(void) {
  ngtcp2_conn c;
  memset(&c, 0, sizeof(c));
  c.cstat.max_tx_udp_payload_size = 1200;
  c.cstat.first_rtt_sample_ts = UINT64_MAX;
  c.tx.pacing.next_ts = UINT64_MAX;
  c.flags |= NGTCP2_CONN_FLAG_TLS_HANDSHAKE_COMPLETED;
  c.pktns.crypto.rx.ckm = (ngtcp2_crypto_km *)(uintptr_t)1;
  c.pktns.crypto.tx.ckm = (ngtcp2_crypto_km *)(uintptr_t)1;
  assert(nexus_ngtcp2_set_brutal(&c, 10000, 1, 100) == 0);
  c.tx.pacing.next_ts = 200;
  assert(!conn_pacing_pkt_tx_allowed(&c, 199));
  assert(c.tx.pacing.next_ts == 200);
  assert(conn_pacing_pkt_tx_allowed(&c, 1000));
  assert(c.tx.pacing.next_ts == UINT64_MAX && c.tx.pacing.compensation == 0);
  c.tx.pacing.next_ts = 1100;
  conn_cancel_expired_pkt_tx_timer(&c, 1099);
  assert(c.tx.pacing.next_ts == 1100);
  conn_cancel_expired_pkt_tx_timer(&c, UINT64_MAX - 1);
  assert(c.tx.pacing.next_ts == UINT64_MAX && c.tx.pacing.compensation == 0);
  c.cc_algo = NGTCP2_CC_ALGO_RENO;
  assert(nexus_ngtcp2_restore_cc(&c, UINT64_MAX - 1) == 0);
  c.tx.pacing.next_ts = 100;
  assert(conn_pacing_pkt_tx_allowed(&c, 110));
  assert(c.tx.pacing.compensation == 10);
  c.tx.pacing.next_ts = 200;
  conn_cancel_expired_pkt_tx_timer(&c, 220);
  assert(c.tx.pacing.compensation == 30);
  puts("Brutal ignores native timer compensation; restored Reno keeps it");
}
