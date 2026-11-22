// Private experimental loopback listener. Import std and the FakeIP modules first.
#pragma once
#include <boost/capy/buffers.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/udp_socket.hpp>

namespace dns::detail {
    enum class FakeIpListenerError { state, transport, completion };
    // One executor, one receive or send at a time. The owner, shared registry and
    // all dependent objects must live until run() completes after stop().
    class FakeIpListener {
        boost::corosio::udp_socket socket_;
        FakeIpShared& registry_;
        std::uint32_t range_;
        std::uint64_t view_;
        bool opened_=false, running_=false, stopped_=false, finished_=false;
    public:
        FakeIpListener(boost::corosio::io_context& context,FakeIpShared& registry,
                       std::uint32_t range,std::uint64_t view)
            : socket_(context),registry_(registry),range_(range),view_(view) {}
        FakeIpListener(FakeIpListener const&)=delete;
        auto operator=(FakeIpListener const&) -> FakeIpListener& = delete;
        [[nodiscard]] auto open(std::uint16_t port) -> std::expected<void,FakeIpListenerError> {
            if (opened_ || stopped_) return std::unexpected(FakeIpListenerError::state);
            namespace io=boost::corosio;
            if (socket_.open()) return std::unexpected(FakeIpListenerError::transport);
            if (socket_.bind(io::endpoint(io::ipv4_address::loopback(),port))) {
                socket_.close(); return std::unexpected(FakeIpListenerError::transport);
            }
            opened_=true;
            return {};
        }
        [[nodiscard]] auto local_endpoint() const { return socket_.local_endpoint(); }
        auto stop() noexcept -> void { stopped_=true; socket_.close(); }
        [[nodiscard]] auto run() -> boost::capy::task<std::expected<void,FakeIpListenerError>> {
            namespace capy=boost::capy;
            if (!opened_ || running_ || finished_) co_return std::unexpected(FakeIpListenerError::state);
            running_=true;
            std::array<std::uint8_t,513> buffer{};
            while (!stopped_) {
                boost::corosio::endpoint source;
                auto [error,n]=co_await socket_.recv_from(capy::mutable_buffer(buffer.data(),buffer.size()),source);
                if (stopped_) break;
                if (error) { finished_=true; co_return std::unexpected(FakeIpListenerError::transport); }
                if (n>512) continue;
                auto response=registry_.respond(range_,std::span(buffer).first(n),view_);
                if (!response) {
                    if (!validate_fakeip_query(std::span(buffer).first(n))) continue;
                    // Echo only a fully validated supported question.
                    buffer[2]=static_cast<std::uint8_t>(0x80 | (buffer[2]&1));
                    buffer[3]=0x82; // recursion available, SERVFAIL
                    if (buffer[11]==1) {
                        auto payload=std::min<std::uint16_t>((std::uint16_t{buffer[n-8]}<<8)|buffer[n-7],1232);
                        buffer[n-8]=static_cast<std::uint8_t>(payload>>8);
                        buffer[n-7]=static_cast<std::uint8_t>(payload);
                    }
                    auto [send_error,sent]=co_await socket_.send_to(capy::const_buffer(buffer.data(),n),source);
                    if (stopped_) break;
                    if (send_error || sent!=n) { finished_=true; co_return std::unexpected(FakeIpListenerError::transport); }
                    continue;
                }
                auto wire=(*response)->wire();
                auto [send_error,sent]=co_await socket_.send_to(capy::const_buffer(wire.data(),wire.size()),source);
                // Any submitted operation, including cancellation, may have sent.
                auto completed=(*response)->finish(true);
                if (!completed) { finished_=true; co_return std::unexpected(FakeIpListenerError::completion); }
                if (stopped_) break;
                if (send_error || sent!=wire.size()) { finished_=true; co_return std::unexpected(FakeIpListenerError::transport); }
            }
            finished_=true;
            co_return std::expected<void,FakeIpListenerError>{};
        }
    };
}
