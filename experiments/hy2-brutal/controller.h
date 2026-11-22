#ifndef NEXUS_EXPERIMENT_HY2_BRUTAL_CONTROLLER_H
#define NEXUS_EXPERIMENT_HY2_BRUTAL_CONTROLLER_H

/* QUIC-facing prototype: bytes, monotonic nanoseconds, fixed storage. */
#include <stdint.h>
#include <stddef.h>
#include <limits.h>

#define BRUTAL_SECOND UINT64_C(1000000000)
#define BRUTAL_MILLISECOND UINT64_C(1000000)
#define BRUTAL_NO_DEADLINE UINT64_MAX

typedef struct {
  uint64_t second, acked, lost;
  int valid;
} brutal_sample;

typedef struct {
  uint64_t bytes_per_second, max_packet, last_sent, budget;
  uint64_t acked_ratio, total_ratio;
  brutal_sample samples[5];
  int sent, compensate;
} brutal_controller;

static inline uint64_t brutal_saturate(unsigned __int128 value) {
  return value > UINT64_MAX ? UINT64_MAX : (uint64_t)value;
}

static inline uint64_t brutal_rate(const brutal_controller *c) {
  return brutal_saturate((unsigned __int128)c->bytes_per_second * c->total_ratio / c->acked_ratio);
}

static inline uint64_t brutal_burst(const brutal_controller *c) {
  uint64_t packets = brutal_saturate((unsigned __int128)c->max_packet * 10);
  uint64_t timed = brutal_saturate((unsigned __int128)brutal_rate(c) * 4 / 1000);
  return packets > timed ? packets : timed;
}

static inline int brutal_init(brutal_controller *c, uint64_t bps, uint64_t max_packet, int compensate) {
  if (!bps || !max_packet) return 0;
  *c = (brutal_controller){.bytes_per_second=bps, .max_packet=max_packet,
                           .acked_ratio=1, .total_ratio=1, .compensate=!!compensate};
  c->budget = brutal_burst(c);
  return 1;
}

static inline void brutal_refresh(brutal_controller *c, uint64_t now) {
  uint64_t second = now / BRUTAL_SECOND;
  unsigned __int128 a=0, l=0;
  for (size_t i=0;i<5;++i) {
    brutal_sample *item=&c->samples[i];
    if (item->valid && item->second<=second && second-item->second<5) {a+=item->acked;l+=item->lost;}
  }
  if (!c->compensate || a+l<50) {c->acked_ratio=1;c->total_ratio=1;return;}
  if (a*5 < (a+l)*4) {c->acked_ratio=4;c->total_ratio=5;return;}
  /* Bound the ratio operands so later window arithmetic fits in 128 bits. */
  while (a+l>UINT32_MAX) {a=(a+1)/2;l=(l+1)/2;}
  c->acked_ratio=(uint64_t)a;c->total_ratio=(uint64_t)(a+l);
}

/* Count the native loss and acknowledgement callbacks, not their bytes. */
static inline void brutal_observe(brutal_controller *c, uint64_t now, int lost) {
  uint64_t second = now / BRUTAL_SECOND;
  brutal_sample *slot = &c->samples[second % 5];
  if (!slot->valid || slot->second != second) *slot = (brutal_sample){.second=second,.valid=1};
  uint64_t *count = lost ? &slot->lost : &slot->acked;
  if (*count != UINT64_MAX) ++*count;
  brutal_refresh(c,now);
}

static inline uint64_t brutal_cwnd(const brutal_controller *c, uint64_t rtt, int has_rtt) {
  if (!has_rtt || !rtt) return c->max_packet>10240 ? c->max_packet : 10240;
  unsigned __int128 product=(unsigned __int128)c->bytes_per_second*rtt;
  uint64_t factor=2*c->total_ratio, divisor=BRUTAL_SECOND*c->acked_ratio;
  /* Compare before multiplying to avoid overflowing the wide intermediate. */
  if (product>(unsigned __int128)UINT64_MAX*divisor/factor) return UINT64_MAX;
  unsigned __int128 window=product*factor/divisor;
  uint64_t result=brutal_saturate(window);
  return result>c->max_packet ? result : c->max_packet;
}

static inline uint64_t brutal_budget_at(const brutal_controller *c, uint64_t now) {
  uint64_t burst=brutal_burst(c);
  if (!c->sent) return burst;
  if (now<=c->last_sent) return c->budget<burst ? c->budget : burst;
  unsigned __int128 available=(unsigned __int128)brutal_rate(c)*(now-c->last_sent)/BRUTAL_SECOND+c->budget;
  return available>=burst ? burst : (uint64_t)available;
}

static inline void brutal_sent(brutal_controller *c, uint64_t now, uint64_t size) {
  uint64_t available=brutal_budget_at(c,now);
  c->budget=size>=available ? 0 : available-size;
  if (!c->sent || now>c->last_sent) c->last_sent=now;
  c->sent=1;
}

/* Keep the accrued budget and sampling history when changing the target. */
static inline int brutal_reconfigure(brutal_controller *c, uint64_t bps, int compensate, uint64_t now) {
  if (!bps || (c->sent && now<c->last_sent)) return 0;
  uint64_t available=brutal_budget_at(c,now);
  if (c->sent) {c->budget=available;c->last_sent=now;}
  c->bytes_per_second=bps;c->compensate=!!compensate;
  brutal_refresh(c,now);
  uint64_t burst=brutal_burst(c);
  if (c->sent && c->budget>burst) c->budget=burst;
  return 1;
}

/* Earliest time a maximum-size packet can be sent. UINT64_MAX is saturated. */
static inline uint64_t brutal_next(const brutal_controller *c, uint64_t now) {
  uint64_t available=brutal_budget_at(c,now);
  if (available>=c->max_packet) return now;
  uint64_t rate=brutal_rate(c);
  /* Anchor the deadline to the last send, not to each timer recheck. */
  uint64_t at_send=c->budget<brutal_burst(c) ? c->budget : brutal_burst(c);
  unsigned __int128 numerator=(unsigned __int128)(c->max_packet-at_send)*BRUTAL_SECOND;
  unsigned __int128 wait=(numerator+rate-1)/rate;
  if (wait<BRUTAL_MILLISECOND) wait=BRUTAL_MILLISECOND;
  uint64_t due=brutal_saturate((unsigned __int128)c->last_sent+wait);
  return due>now ? due : now;
}
#endif
