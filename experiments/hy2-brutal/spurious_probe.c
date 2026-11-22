/* Exercise ngtcp2's actual RTB ACK dispatch with a stub controller.
 * Compile against the isolated ngtcp2-spurious-candidate source tree. */
#include <assert.h>
#include <stdio.h>
#include "ngtcp2_rtb.c"

static int active, ack_calls, sample_calls;

#ifdef NEXUS_TEST_UNINSTRUMENTED
int nexus_brutal_is_active(const ngtcp2_cc *cc) {
  (void)cc;
  return active;
}
#else
int nexus_brutal_skip_spurious(ngtcp2_cc *cc, ngtcp2_tstamp ts) {
  (void)cc;
  (void)ts;
  return active;
}
#endif

void ngtcp2_rst_update_rate_sample(ngtcp2_rst *rst, const ngtcp2_rtb_entry *ent,
                                   ngtcp2_tstamp ts) {
  (void)rst; (void)ent; (void)ts; ++sample_calls;
}

ngtcp2_cc_pkt *ngtcp2_cc_pkt_init(ngtcp2_cc_pkt *pkt, int64_t pkt_num,
                                  size_t pktlen, ngtcp2_pktns_id pktns_id,
                                  ngtcp2_tstamp sent_ts, uint64_t lost,
                                  uint64_t tx_in_flight, int is_app_limited) {
  (void)pkt_num; (void)pktlen; (void)pktns_id; (void)sent_ts;
  (void)lost; (void)tx_in_flight; (void)is_app_limited;
  memset(pkt, 0, sizeof(*pkt));
  return pkt;
}

static void ack(ngtcp2_cc *cc, ngtcp2_conn_stat *cstat,
                const ngtcp2_cc_pkt *pkt, ngtcp2_tstamp ts) {
  (void)cc; (void)cstat; (void)pkt; (void)ts; ++ack_calls;
}

int main(void) {
  ngtcp2_cc cc = {.on_pkt_acked = ack};
  ngtcp2_rst rst = {0};
  ngtcp2_rtb rtb = {.cc = &cc, .rst = &rst};
  ngtcp2_rtb_entry ent = {0};
  ngtcp2_conn_stat stats = {0};
  ngtcp2_pktns pktns = {0};
  active = 1;
  rtb_on_pkt_acked(&rtb, &ent, &stats, &pktns, 1);
  assert(ack_calls == 1 && sample_calls == 1);
  ent.flags = NGTCP2_RTB_ENTRY_FLAG_LOST_RETRANSMITTED;
  rtb_on_pkt_acked(&rtb, &ent, &stats, &pktns, 2);
  assert(ack_calls == 1 && sample_calls == 2);
  active = 0;
  rtb_on_pkt_acked(&rtb, &ent, &stats, &pktns, 3);
  assert(ack_calls == 2 && sample_calls == 3);
  puts("RTB ACK dispatch: Brutal skips late ACK, standard CC retains it");
}
