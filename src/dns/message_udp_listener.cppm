export module dns.message_udp_listener;
import std;
import dns.message_program;
import dns.message_cache;
import dns.input_budget;
import dns.policy;
import nexus.thirdparty.corosio;
export namespace dns {
    class MessageUdpListener {
        struct Impl;std::unique_ptr<Impl> impl_;
    public:
        MessageUdpListener(nex::corosio::io_context& context,std::span<policy::DnsRule const> rules,std::span<MessageUpstream const> upstreams,std::size_t fallback,std::size_t limit,std::chrono::milliseconds timeout,MessageCache* cache=nullptr,bool disable_cache=false,InputBudget* input_budget=nullptr,InputBudget* query_budget=nullptr,MessageRuleSource source={});
        ~MessageUdpListener();
        MessageUdpListener(MessageUdpListener const&)=delete;
        auto operator=(MessageUdpListener const&) -> MessageUdpListener& = delete;
        // A staged listener may bind and allocate before its owner opens admission.
        auto start(nex::corosio::endpoint endpoint,bool const* admitted=nullptr) -> std::error_code;
        auto local_endpoint() const -> nex::corosio::endpoint;
        auto begin_drain() noexcept -> void;
        auto stop() noexcept -> void;
        auto drained() noexcept -> bool;
        auto failure() const noexcept -> std::exception_ptr;
        auto io_failure() const noexcept -> std::error_code;
        auto healthy() const noexcept -> bool;
        auto dropped() const noexcept -> std::uint64_t;
        auto send_failures() const noexcept -> std::uint64_t;
    };
}
