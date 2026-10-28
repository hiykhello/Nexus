// Private implementation: import std and nexus.dns.message before including.
#pragma once
#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/timeout.hpp>
#include "corosio_udp.hpp"

namespace nexus::dns::detail {
    // Single use; owner retains this object until the coroutine finishes.
    class TcpQuery {
        boost::corosio::tcp_socket socket_;
        bool started_ = false, canceled_ = false;
        using Clock = std::chrono::steady_clock;
        auto transfer(std::span<std::uint8_t> bytes, bool write, Clock::time_point deadline)
            -> boost::capy::task<std::error_code> {
            namespace capy = boost::capy;
            namespace io = boost::corosio;
            while (!bytes.empty()) {
                if (Clock::now() >= deadline) co_return std::make_error_code(std::errc::timed_out);
                auto [error, n] = write ?
                    co_await io::timeout(socket_.write_some(capy::const_buffer(bytes.data(),bytes.size())),deadline) :
                    co_await io::timeout(socket_.read_some(capy::mutable_buffer(bytes.data(),bytes.size())),deadline);
                if (error) co_return error;
                if (!n) co_return std::make_error_code(std::errc::connection_reset);
                bytes = bytes.subspan(n);
            }
            co_return std::error_code{};
        }
    public:
        explicit TcpQuery(boost::corosio::io_context& context) : socket_(context) {}
        TcpQuery(TcpQuery const&) = delete;
        auto operator=(TcpQuery const&) -> TcpQuery& = delete;
        auto cancel() noexcept -> void { canceled_ = true; socket_.cancel(); }
        auto query(boost::corosio::endpoint upstream, std::uint16_t id, Question question, Clock::time_point deadline, bool edns=false)
            -> boost::capy::task<std::expected<Response, UdpError>> {
            namespace capy = boost::capy;
            namespace io = boost::corosio;
            if (started_) co_return std::unexpected(UdpError::state);
            started_ = true;
            if (canceled_) co_return std::unexpected(UdpError::canceled);
            if (Clock::now() >= deadline) co_return std::unexpected(UdpError::timeout);
            auto message = edns ? make_edns_query(id,question,1232) : make_query(id, question);
            if (!message) co_return std::unexpected(UdpError::invalid_query);
            Bytes frame{static_cast<std::uint8_t>(message->size() >> 8), static_cast<std::uint8_t>(message->size())};
            frame.insert(frame.end(),message->begin(),message->end());
            auto finish = [this](UdpError error) -> std::expected<Response,UdpError> {
                socket_.close(); return std::unexpected(error);
            };
            auto classify = [this,deadline](std::error_code error) {
                if (canceled_) return UdpError::canceled;
                return error == capy::cond::timeout || error == std::errc::timed_out || Clock::now() >= deadline ?
                    UdpError::timeout : UdpError::transport;
            };
            auto [connect_error] = co_await io::timeout(socket_.connect(upstream),deadline);
            if (connect_error || canceled_ || Clock::now() >= deadline) co_return finish(classify(connect_error));
            auto write_error = co_await transfer(frame,true,deadline);
            if (write_error || canceled_ || Clock::now() >= deadline) co_return finish(classify(write_error));
            std::array<std::uint8_t,2> length{};
            auto read_error = co_await transfer(length,false,deadline);
            if (read_error || canceled_ || Clock::now() >= deadline) co_return finish(classify(read_error));
            auto size = (std::size_t(length[0]) << 8) | length[1];
            if (size < 12 || size > 4096) co_return finish(UdpError::protocol);
            Bytes response(size);
            read_error = co_await transfer(response,false,deadline);
            if (read_error || canceled_ || Clock::now() >= deadline) co_return finish(classify(read_error));
            auto parsed = parse_response(response,id,question);
            if (!parsed) co_return finish(parsed.error()==MessageError::truncated ? UdpError::truncated : UdpError::protocol);
            socket_.close(); co_return std::move(*parsed);
        }
    };
    class FallbackQuery {
        UdpQuery udp_;
        TcpQuery tcp_;
        bool canceled_ = false, tcp_only_ = false;
    public:
        explicit FallbackQuery(boost::corosio::io_context& context, bool tcp_only = false)
            : udp_(context),tcp_(context),tcp_only_(tcp_only) {}
        auto cancel() noexcept -> void { canceled_ = true; udp_.cancel(); tcp_.cancel(); }
        auto query(boost::corosio::endpoint upstream, std::uint16_t id, Question question,
                   std::chrono::steady_clock::time_point deadline, bool edns=false)
            -> boost::capy::task<std::expected<Response,UdpError>> {
            if (tcp_only_) co_return co_await tcp_.query(upstream,id,std::move(question),deadline,edns);
            auto result = co_await udp_.query(upstream,id,question,deadline,edns);
            if (canceled_) co_return std::unexpected(UdpError::canceled);
            if (result || result.error()!=UdpError::truncated) co_return result;
            co_return co_await tcp_.query(upstream,id,std::move(question),deadline,edns);
        }
    };
}
