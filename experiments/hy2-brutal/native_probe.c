/* Narrow internal adapter probe, not a substitute for live QUIC traffic. */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "ngtcp2_conn.h"

extern int nexus_ngtcp2_set_brutal(ngtcp2_conn *, uint64_t, int, ngtcp2_tstamp);
extern int nexus_ngtcp2_restore_cc(ngtcp2_conn *, ngtcp2_tstamp);

int main(void) {
  ngtcp2_conn c;
  memset(&c, 0, sizeof(c));
  c.cstat.max_tx_udp_payload_size=1200;
  c.cstat.first_rtt_sample_ts=UINT64_MAX;
  c.tx.pacing.next_ts=UINT64_MAX;
  assert(nexus_ngtcp2_set_brutal(&c, 1000000, 1, 0)==NGTCP2_ERR_INVALID_STATE);
  c.flags|=NGTCP2_CONN_FLAG_TLS_HANDSHAKE_COMPLETED;
  c.pktns.crypto.rx.ckm=(ngtcp2_crypto_km *)(uintptr_t)1;
  c.pktns.crypto.tx.ckm=(ngtcp2_crypto_km *)(uintptr_t)1;
  assert(nexus_ngtcp2_set_brutal(&c, 1000000, 1, 100)==0);
  assert(c.cstat.cwnd==10240);
  assert(c.cc.on_pkt_acked && c.cc.on_pkt_lost && c.cc.on_ack_recv && c.cc.reset);
  c.cstat.first_rtt_sample_ts=100;
  c.cstat.smoothed_rtt=100000000;
  ngtcp2_cc_pkt pkt={.sent_ts=100};
  for (int i=0;i<40;++i) c.cc.on_pkt_acked(&c.cc,&c.cstat,&pkt,1000000000);
  for (int i=0;i<10;++i) c.cc.on_pkt_lost(&c.cc,&c.cstat,&pkt,1000000000);
  assert(c.cstat.cwnd==250000);
  for (int i=0;i<10;++i) {
    c.tx.pacing.pktlen=1200;
    ngtcp2_conn_update_pkt_tx_time(&c,1000000000);
  }
  assert(c.tx.pacing.next_ts>1000000000 && c.tx.pacing.next_ts!=UINT64_MAX);
  uint64_t until=c.tx.pacing.next_ts;
  c.cc.on_pkt_acked(&c.cc,&c.cstat,&pkt,until);
  assert(c.tx.pacing.next_ts==UINT64_MAX);
  c.tx.pacing.pktlen=1;
  assert(nexus_ngtcp2_set_brutal(&c, 2000000, 1, until)==NGTCP2_ERR_INVALID_STATE);
  assert(nexus_ngtcp2_restore_cc(&c, until)==NGTCP2_ERR_INVALID_STATE);
  c.tx.pacing.pktlen=0;
  assert(nexus_ngtcp2_set_brutal(&c, 2000000, 1, until)==0);
  assert(c.brutal.controller.bytes_per_second==2000000);
  assert(c.brutal.controller.samples[1].acked==41);
  c.cstat.max_tx_udp_payload_size=1300;
  c.cc.reset(&c.cc,&c.cstat,until);
  assert(c.brutal.controller.max_packet==1300 && c.cstat.cwnd==400000);
  c.cc_algo=NGTCP2_CC_ALGO_CUBIC;
  c.cstat.bytes_in_flight=1234;
  assert(nexus_ngtcp2_restore_cc(&c,until)==0);
  assert(c.cstat.bytes_in_flight==1234 && c.cstat.cwnd>=1300);
  assert(nexus_ngtcp2_restore_cc(&c,until)==NGTCP2_ERR_INVALID_STATE);
  for (int algo=NGTCP2_CC_ALGO_RENO;algo<=NGTCP2_CC_ALGO_BBR;++algo) {
    c.cc_algo=(ngtcp2_cc_algo)algo;
    assert(nexus_ngtcp2_set_brutal(&c, 1000000, 1, until)==0);
    c.cstat.bytes_in_flight=9876;
    assert(nexus_ngtcp2_restore_cc(&c,until)==0);
    assert(c.cstat.bytes_in_flight==9876 && c.cstat.cwnd>=1300 && c.cc.reset);
    if (algo==NGTCP2_CC_ALGO_RENO) assert(c.cc.on_pkt_acked==ngtcp2_cc_reno_cc_on_pkt_acked);
    if (algo==NGTCP2_CC_ALGO_CUBIC) assert(c.cc.on_ack_recv==ngtcp2_cc_cubic_cc_on_ack_recv);
    if (algo==NGTCP2_CC_ALGO_BBR) assert(c.cc.on_pkt_lost && c.cc.on_pkt_sent);
  }
  printf("native callbacks and pacing passed; conn size=%zu server offset=%zu\n",sizeof(c),offsetof(ngtcp2_conn,server));
}
