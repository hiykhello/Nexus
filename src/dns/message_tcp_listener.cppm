export module dns.message_tcp_listener;
import std;
import dns.message_program;
import dns.message_cache;
import dns.input_budget;
import dns.policy;
import corosio;
export namespace dns {
    class MessageTcpListener {
        struct Impl;std::unique_ptr<Impl> impl_;
    public:
        MessageTcpListener(corosio::io_context& context,std::span<policy::DnsRule const> rules,std::span<MessageUpstream const> upstreams,std::size_t fallback,std::size_t limit,std::chrono::milliseconds timeout,std::size_t max_requests,MessageCache* cache=nullptr,bool disable_cache=false,InputBudget* input_budget=nullptr,InputBudget* query_budget=nullptr,MessageRuleSource source={});
        ~MessageTcpListener();
        MessageTcpListener(MessageTcpListener const&)=delete;
        auto operator=(MessageTcpListener const&) -> MessageTcpListener& = delete;
        // A staged listener may bind and allocate before its owner opens admission.
        auto start(corosio::endpoint endpoint,bool const* admitted=nullptr) -> std::error_code;
        auto local_endpoint() const -> corosio::endpoint;
        auto begin_drain() noexcept -> void;
        auto stop() noexcept -> void;
        auto drained() noexcept -> bool;
        auto failure() const noexcept -> std::exception_ptr;
        auto io_failure() const noexcept -> std::error_code;
        auto healthy() const noexcept -> bool;
    };
}
