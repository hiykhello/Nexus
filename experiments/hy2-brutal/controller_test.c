#include "controller.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
  brutal_controller c;
  assert(!brutal_init(&c, 0, 1200, 1));
  assert(brutal_init(&c, 1000000, 1200, 1));
  assert(brutal_rate(&c)==1000000 && brutal_burst(&c)==12000);
  assert(brutal_cwnd(&c, 0, 0)==10240);
  assert(brutal_cwnd(&c, BRUTAL_SECOND/10, 1)==200000);
  for (int i=0;i<49;++i) brutal_observe(&c, BRUTAL_SECOND, i<10);
  assert(brutal_rate(&c)==1000000);
  brutal_observe(&c, BRUTAL_SECOND, 0);
  assert(brutal_rate(&c)==1250000);
  assert(brutal_cwnd(&c, BRUTAL_SECOND/10, 1)==250000);
  assert(brutal_reconfigure(&c, 2000000, 0, BRUTAL_SECOND));
  assert(brutal_rate(&c)==2000000);
  assert(brutal_reconfigure(&c, 2000000, 1, BRUTAL_SECOND));
  assert(brutal_rate(&c)==2500000);
  brutal_observe(&c, 6*BRUTAL_SECOND, 0);
  assert(brutal_rate(&c)==2000000);
  assert(brutal_init(&c, 1000000, 1200, 0));
  for (int i=0;i<80;++i) brutal_observe(&c, 0, i<40);
  assert(brutal_rate(&c)==1000000);
  for (int i=0;i<10;++i) brutal_sent(&c, BRUTAL_SECOND, 1200);
  assert(brutal_budget_at(&c, BRUTAL_SECOND)==0);
  assert(brutal_next(&c, BRUTAL_SECOND)==BRUTAL_SECOND+1200000);
  assert(brutal_budget_at(&c, BRUTAL_SECOND+1199999)==1199);
  assert(brutal_next(&c, BRUTAL_SECOND+1199999)==BRUTAL_SECOND+1200000);
  assert(brutal_budget_at(&c, BRUTAL_SECOND+1200000)==1200);
  assert(!brutal_reconfigure(&c, 0, 1, BRUTAL_SECOND+600000));
  assert(brutal_reconfigure(&c, 500000, 0, BRUTAL_SECOND+600000));
  assert(c.budget==600 && c.last_sent==BRUTAL_SECOND+600000);
  assert(brutal_next(&c, BRUTAL_SECOND+600000)==BRUTAL_SECOND+1800000);
  assert(!brutal_reconfigure(&c, 1000000, 1, BRUTAL_SECOND));
  assert(brutal_reconfigure(&c, 1000000, 0, BRUTAL_SECOND+1800000));
  brutal_sent(&c, BRUTAL_SECOND+1800000, 1200);
  assert(brutal_budget_at(&c, BRUTAL_SECOND+20000000)==12000);
  assert(brutal_init(&c, UINT64_MAX, 1500, 1));
  for (int i=0;i<50;++i) brutal_observe(&c, 0, i<20);
  assert(brutal_rate(&c)==UINT64_MAX);
  assert(brutal_cwnd(&c, UINT64_MAX, 1)==UINT64_MAX);
  assert(brutal_next(&c, UINT64_MAX-1)==UINT64_MAX-1);
  assert(brutal_init(&c, 1, 1500, 1));
  brutal_sent(&c, UINT64_MAX-100, 15000);
  assert(brutal_next(&c, UINT64_MAX-100)==BRUTAL_NO_DEADLINE);
  puts("Brutal sampling, window, pacing, saturation passed");
}
