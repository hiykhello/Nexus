#ifdef NEXUS_TEST_FAKEIP
namespace {
    bool throw_on_receive = false;
    unsigned received = 0;
}

extern "C" void nexus_test_fakeip_dns_received() {
    ++received;
    if (throw_on_receive) throw 1;
}

extern "C" void nexus_test_set_fakeip_receive_hook(bool enabled) {
    throw_on_receive = enabled;
    received = 0;
}

extern "C" unsigned nexus_test_fakeip_receive_hook_count() { return received; }
#endif
