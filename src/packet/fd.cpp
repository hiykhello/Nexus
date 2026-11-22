module;
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
module packet.fd;
import std;

namespace packet {
    static_assert(requires { static_cast<decltype(&fd_detail::abi::read)>(&::read); });
    static_assert(requires { static_cast<decltype(&fd_detail::abi::write)>(&::write); });
    static_assert(requires { static_cast<decltype(&fd_detail::abi::fcntl)>(&::fcntl); });
    static_assert(requires { static_cast<decltype(&fd_detail::abi::__errno_location)>(&::__errno_location); });
    static_assert(F_GETFL==fd_detail::abi::get_flags && O_NONBLOCK==fd_detail::abi::nonblocking);
    static_assert(EAGAIN==std::to_underlying(std::errc::resource_unavailable_try_again) && EWOULDBLOCK==std::to_underlying(std::errc::operation_would_block) && EINTR==std::to_underlying(std::errc::interrupted));
    namespace {
        struct MemoryDevice {
            using Packet=QueuedPacket;
            using Failure=DeviceError;
            MemoryLink& link;
            FdPump::OutputValidator validator;
            void* context;
            auto receive_packet() -> std::expected<std::optional<Packet>,Failure> { return link.receive_packet(Side::first); }
            auto send(std::span<std::uint8_t const> packet) -> std::expected<void,Failure> { return link.send(Side::first,packet); }
            static auto packet_bytes(Packet const& packet) noexcept -> std::span<std::uint8_t const> { return packet.bytes; }
            static auto retryable(Failure failure) noexcept -> bool { return failure==DeviceError::queue_full; }
            auto valid_output(Packet const& packet) const noexcept -> bool {
                return (!packet.generation || packet.generation->valid) && (!validator || validator(context,packet));
            }
        };
    }
    FdPump::FdPump(int fd,MemoryLink& link,std::size_t mtu) : fd_(fd),link_(&link),mtu_(mtu),buffer_(mtu+1) {}
    FdPump::~FdPump()=default;
    FdPump::FdPump(FdPump&&) noexcept=default;
    auto FdPump::operator=(FdPump&&) noexcept -> FdPump& = default;
    auto FdPump::create(int fd,MemoryLink& link,std::size_t mtu) -> std::expected<FdPump,FdFailure> {
        auto checked=fd_detail::validate(fd,mtu,65535);
        if (!checked) return std::unexpected(fd_detail::convert<FdFailure>(checked.error()));
        return FdPump(fd,link,mtu);
    }
    auto FdPump::step(OutputValidator validator,void* context) -> FdStep {
        MemoryDevice device{*link_,validator,context};
        return fd_detail::step(fd_,device,mtu_,buffer_,input_size_,output_);
    }
}
