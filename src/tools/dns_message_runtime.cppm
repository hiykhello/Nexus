export module cli.dns_message_runtime;
import std;
import logging.cli;
import config;
import cli.dns_transports;
import dns.message_program;
import dns.reverse;
import cli.dns_fakeip_backend;
export namespace cli {
    class DnsMessageRuntime {
        struct Impl;std::unique_ptr<Impl> impl_;
    public:
        explicit DnsMessageRuntime(logging::Runtime const& logs);
        ~DnsMessageRuntime();
        DnsMessageRuntime(DnsMessageRuntime const&)=delete;
        auto operator=(DnsMessageRuntime const&) -> DnsMessageRuntime& = delete;
        auto prepare(config::Config const&,std::span<DnsProtection const>,dns::MessageRuleSource={},
            DnsMessageRuntime const* previous=nullptr,std::shared_ptr<dns::ReverseCache> reverse={}) -> std::expected<void,std::string>;
#ifdef NEXUS_ENABLE_FAKEIP
        auto fakeip() const -> std::shared_ptr<dns::FakeIpShared>;
#endif
        auto start(bool admit=true) -> std::expected<void,std::string>;
        auto admit() noexcept -> void;
        // Lifecycle operations are serialized by the host control thread.
        auto same_binding(DnsMessageRuntime const&) const noexcept -> bool;
        auto replace_program(DnsMessageRuntime& prepared_candidate) noexcept -> void;
        auto swap(DnsMessageRuntime&) noexcept -> void;
        auto has_listeners() const noexcept -> bool;
        auto healthy() const noexcept -> bool;
        auto begin_drain() noexcept -> void;
        auto drained() noexcept -> bool;
        auto checkpoint() noexcept -> void;
        auto reclaim_memory(bool hard) noexcept -> void;
        auto stop() noexcept -> void;
    };
}
