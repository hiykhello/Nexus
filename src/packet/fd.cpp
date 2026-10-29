module;
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
module nexus.packet.fd;
import std;

namespace nexus::packet {
    FdPump::FdPump(int fd, MemoryLink& link, std::size_t mtu)
        : fd_(fd), link_(&link), mtu_(mtu), buffer_(mtu+1) {}
    FdPump::~FdPump() = default;
    FdPump::FdPump(FdPump&&) noexcept = default;
    auto FdPump::operator=(FdPump&&) noexcept -> FdPump& = default;
    auto FdPump::create(int fd, MemoryLink& link, std::size_t mtu) -> std::expected<FdPump, FdFailure> {
        if (fd < 0) return std::unexpected(FdFailure{FdError::invalid_fd});
        if (!mtu || mtu > 65535) return std::unexpected(FdFailure{FdError::invalid_limit});
        int flags=::fcntl(fd,F_GETFL);
        if (flags < 0) return std::unexpected(FdFailure{std::error_code{errno,std::generic_category()}});
        if (!(flags & O_NONBLOCK)) return std::unexpected(FdFailure{FdError::blocking_fd});
        return FdPump(fd,link,mtu);
    }
    auto FdPump::step() -> FdStep {
        FdStep result;
        if (!output_) {
            auto packet=link_->receive(Side::first);
            if (!packet) result.output_error=FdFailure{packet.error()};
            else if (*packet) output_=std::move(**packet);
        }
        if (output_) {
            if (output_->size()>mtu_) { result.output_error=FdFailure{FdError::packet_too_large}; output_.reset(); }
            else {
                auto n=::write(fd_,output_->data(),output_->size());
                if (n < 0) {
                    if (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR) result.output_backpressured=true;
                    else result.output_error=FdFailure{std::error_code{errno,std::generic_category()}};
                } else if (static_cast<std::size_t>(n)!=output_->size()) {
                    result.output_error=FdFailure{FdError::partial_write}; output_.reset();
                } else { result.output_delivered=true; output_.reset(); }
            }
        }
        if (!input_size_) {
            auto n=::read(fd_,buffer_.data(),buffer_.size());
            if (n < 0) {
                if (errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR)
                    result.input_error=FdFailure{std::error_code{errno,std::generic_category()}};
            } else if (!n) result.input_error=FdFailure{FdError::end_of_file};
            else if (static_cast<std::size_t>(n)>mtu_) result.input_error=FdFailure{FdError::packet_too_large};
            else { result.input=true; input_size_=static_cast<std::size_t>(n); }
        }
        if (input_size_) {
            try {
                auto sent=link_->send(Side::first,std::span(buffer_).first(input_size_));
                if (sent) { result.input_delivered=true; input_size_=0; }
                else if (sent.error()==DeviceError::queue_full) result.input_backpressured=true;
                else { result.input_error=FdFailure{sent.error()}; input_size_=0; }
            } catch (std::bad_alloc const&) { result.input_backpressured=true; }
        }
        return result;
    }
}
