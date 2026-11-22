// Joint feature tests do not enable FakeIP requests, but must satisfy the
// test-only callbacks compiled into the combined proxy and DNS query graph.
extern "C" void nexus_test_fakeip_blocked() {}
extern "C" void nexus_test_fakeip_watcher_done() {}
extern "C" void nexus_test_fakeip_session_release(bool) {}
extern "C" void nexus_test_fakeip_dns_received() {}
