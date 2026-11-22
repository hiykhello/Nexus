import std;

#ifdef NEXUS_TEST_UDP_PENDING
namespace {
    thread_local bool pending_fault_enabled=false;
    thread_local bool pending_fault_injected=false;
}

auto enable_udp_pending_fault() noexcept -> void { pending_fault_enabled=true; }
auto udp_pending_fault_injected() noexcept -> bool { return pending_fault_injected; }
extern "C" void nexus_test_udp_pending() {
    if (!pending_fault_enabled) return;
    pending_fault_injected=true;
    throw std::bad_alloc();
}
#endif

#ifdef NEXUS_TEST_UDP_SEND_DELAY
namespace {
    std::array<unsigned,16> sends_in_flight{};
    std::size_t sends_started=0,send_peak_pending=0;
    bool send_overlap=false,send_distinct_overlap=false,send_queue_observed=false;
    bool inject_send_fault=false,inject_send_task_fault=false,send_fault_injected=false;
}
extern "C" void nexus_test_udp_send_begin(std::size_t index) noexcept {
    for (std::size_t i=0;i<sends_in_flight.size();++i)
        if (i!=index && sends_in_flight[i]) send_distinct_overlap=true;
    if (index>=sends_in_flight.size() || ++sends_in_flight[index]!=1) send_overlap=true;
    ++sends_started;
}
extern "C" void nexus_test_udp_send_end(std::size_t index) noexcept {
    if (index>=sends_in_flight.size() || sends_in_flight[index]!=1) send_overlap=true;
    else --sends_in_flight[index];
}
extern "C" void nexus_test_udp_send_queue(std::size_t count,std::size_t pending) noexcept {
    if (count>=2) send_queue_observed=true;
    send_peak_pending=std::max(send_peak_pending,pending);
}
extern "C" void nexus_test_udp_send_launch() {
    if (inject_send_fault && !send_fault_injected) { send_fault_injected=true; throw std::bad_alloc(); }
}
extern "C" void nexus_test_udp_send_before_write() {
    if (inject_send_task_fault && send_queue_observed && !send_fault_injected) {
        send_fault_injected=true; throw std::bad_alloc();
    }
}

auto configure_udp_send_faults(std::string_view mode) noexcept -> void {
    inject_send_fault=mode=="send-fault";
    inject_send_task_fault=mode=="send-task-fault";
}
auto udp_send_queue_observed() noexcept -> bool { return send_queue_observed && sends_started; }
auto check_udp_send_results(std::string_view mode,int result) noexcept -> int {
    if (send_overlap || std::ranges::any_of(sends_in_flight,[](unsigned count) { return count!=0; })) return 26;
    if (mode=="send-fault" || mode=="send-task-fault") { if (!send_fault_injected || result!=4) return 27; }
    else if (!send_queue_observed || sends_started<(mode=="send-stop" ? 1u : mode=="send-full" ? 40u : 8u)) return 28;
    if ((mode=="multi" || mode=="multi6") && !send_distinct_overlap) return 29;
    if (mode=="send-full" && send_peak_pending!=16) return 30;
    return result;
}
#endif
