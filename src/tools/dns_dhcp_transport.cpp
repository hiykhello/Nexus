module cli.dns_transports;
import std;
import capy;
import corosio;
import config;
import dns.corosio_query;
import dns.dhcp_upstream;
import dns.input_budget;
import dns.message;
import platform.ip_address;

namespace cli {
    namespace {
        auto ip_to_endpoint(platform::IpAddress const& ip) -> corosio::endpoint {
            if (ip.size == 4) {
                corosio::ipv4_address::bytes_type b{};
                std::copy_n(ip.bytes.begin(), 4, b.begin());
                return {corosio::ipv4_address(b), 53};
            }
            return {corosio::ipv6_address(ip.bytes), 53};
        }

        struct DhcpServerCache {
            std::mutex mutex;
            std::condition_variable_any cv;
            std::vector<corosio::endpoint> endpoints;
            std::jthread worker;

            DhcpServerCache() {
                refresh();
                worker = std::jthread([this](std::stop_token tok) {
                    std::unique_lock lk(mutex);
                    while (!tok.stop_requested()) {
                        cv.wait_for(lk, tok, std::chrono::seconds(30), [] { return false; });
                        if (tok.stop_requested()) break;
                        lk.unlock();
                        refresh();
                        lk.lock();
                    }
                });
            }
            ~DhcpServerCache() {
                worker.request_stop();
                cv.notify_all();
                if (worker.joinable()) worker.join();
            }
            auto refresh() -> void {
                auto found = dns::discover_dhcp_dns_servers();
                std::vector<corosio::endpoint> next;
                next.reserve(found.size());
                for (auto const& e : found) next.push_back(ip_to_endpoint(e.address));
                std::lock_guard lk(mutex);
                endpoints = std::move(next);
            }
            auto snapshot() -> std::vector<corosio::endpoint> {
                std::lock_guard lk(mutex);
                return endpoints;
            }
        };
    }

    auto prepare_dhcp_dns_transport(config::DnsServer const&)
        -> std::expected<dns::detail::ProtectedQuery, std::string> {
        auto cache = std::make_shared<DhcpServerCache>();
        return dns::detail::ProtectedQuery{
            [cache](corosio::io_context& context, corosio::endpoint, dns::QueryMessage const& query, std::uint16_t id,
                std::chrono::steady_clock::time_point deadline, dns::InputBudget&, std::stop_token stop)
                -> capy::task<std::expected<dns::Response, dns::detail::UdpError>> {
                using Error = dns::detail::UdpError;
                if (stop.stop_requested()) co_return std::unexpected(Error::canceled);
                if (std::chrono::steady_clock::now() >= deadline) co_return std::unexpected(Error::timeout);
                auto discovered = cache->snapshot();
                if (discovered.empty()) co_return std::unexpected(Error::transport);

                auto last_err = Error::transport;
                for (auto const& ep : discovered) {
                    if (stop.stop_requested()) co_return std::unexpected(Error::canceled);
                    if (std::chrono::steady_clock::now() >= deadline) co_return std::unexpected(Error::timeout);
                    dns::detail::FallbackQuery transport(context, false, nullptr, nullptr);
                    std::stop_callback cancel(stop, [&]() noexcept { transport.cancel(); });
                    auto res = co_await transport.query_borrowed(ep, query, deadline, id);
                    if (res) co_return std::move(*res);
                    last_err = res.error();
                }
                co_return std::unexpected(last_err);
            }
        };
    }
}
