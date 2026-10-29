// Private implementation: import std and nexus.dns.message before including.
#pragma once
#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/timeout.hpp>
#include <boost/corosio/udp_socket.hpp>

#ifdef NEXUS_TEST_DNS_LIFETIME
extern "C" void nexus_test_dns_received();
#endif
#ifdef NEXUS_TEST_FAKEIP
extern "C" void nexus_test_fakeip_dns_received();
#endif

namespace nexus::dns::detail {
    enum class UdpError { state, invalid_query, transport, timeout, canceled, truncated, response_limit, protocol };
    // Single use, single executor. The owner must retain this object until query
    // returns, including after cancel(), and must use an unpredictable transaction ID.
    class UdpQuery {
        boost::corosio::udp_socket socket_;
        bool started_ = false, canceled_ = false;
    public:
        explicit UdpQuery(boost::corosio::io_context& context) : socket_(context) {}
        UdpQuery(UdpQuery const&) = delete;
        auto operator=(UdpQuery const&) -> UdpQuery& = delete;
        auto cancel() noexcept -> void { canceled_ = true; socket_.cancel(); }
        auto query(boost::corosio::endpoint upstream, std::uint16_t id, Question question,
                   std::chrono::steady_clock::time_point deadline, bool edns=false)
            -> boost::capy::task<std::expected<Response, UdpError>> {
            namespace capy = boost::capy;
            namespace io = boost::corosio;
            if (started_) co_return std::unexpected(UdpError::state);
            started_ = true;
            if (canceled_) co_return std::unexpected(UdpError::canceled);
            if (std::chrono::steady_clock::now() >= deadline) co_return std::unexpected(UdpError::timeout);
            auto request = edns ? make_edns_query(id,question,1232) : make_query(id, question);
            if (!request) co_return std::unexpected(UdpError::invalid_query);
            if (socket_.open(upstream.address().family())) co_return std::unexpected(UdpError::transport);
            auto finish = [this](UdpError error) -> std::expected<Response, UdpError> {
                socket_.close(); return std::unexpected(error);
            };
            auto [send_error, sent] = co_await io::timeout(
                socket_.send_to(capy::const_buffer(request->data(), request->size()), upstream), deadline);
            if (canceled_) co_return finish(UdpError::canceled);
            if (send_error || sent != request->size() || std::chrono::steady_clock::now() >= deadline)
                co_return finish(send_error == capy::cond::timeout || std::chrono::steady_clock::now() >= deadline ?
                                 UdpError::timeout : UdpError::transport);
            std::array<std::uint8_t, 4097> buffer{};
            for (unsigned received = 0; received < 32; ++received) {
                io::endpoint source;
                auto [error, size] = co_await io::timeout(
                    socket_.recv_from(capy::mutable_buffer(buffer.data(), buffer.size()), source), deadline);
                if (canceled_) co_return finish(UdpError::canceled);
                if (error || std::chrono::steady_clock::now() >= deadline)
                    co_return finish(error == capy::cond::timeout || std::chrono::steady_clock::now() >= deadline ?
                                     UdpError::timeout : UdpError::transport);
#ifdef NEXUS_TEST_DNS_LIFETIME
                nexus_test_dns_received();
#endif
#ifdef NEXUS_TEST_FAKEIP
                nexus_test_fakeip_dns_received();
#endif
                if (source != upstream || size > (edns ? 1232u : 4096u)) continue;
                auto parsed = parse_response(std::span(buffer).first(size), id, question);
                if (parsed) { socket_.close(); co_return std::move(*parsed); }
                if (parsed.error() == MessageError::truncated) co_return finish(UdpError::truncated);
            }
            co_return finish(UdpError::response_limit);
        }
    };
}
