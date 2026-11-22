module;
#if !defined(__linux__) || (!defined(__x86_64__) && !defined(__aarch64__)) || !defined(__LP64__)
#error "The static descriptor boundary is verified for Linux x86-64 / aarch64 LP64 only"
#endif
#include <cstddef>

// The existing system headers in fd.cpp verify these exact glibc declarations
// and constants. Static pumps call the same C symbols without I/O forwarding.
namespace packet::fd_detail::raw_abi {
    extern "C" std::ptrdiff_t read(int,void*,std::size_t);
    extern "C" std::ptrdiff_t write(int,void const*,std::size_t);
    extern "C" int fcntl(int,int,...);
    extern "C" int* __errno_location() noexcept;
}

export module packet.fd;
export import packet;
import std;

export namespace packet {
    enum class FdError { invalid_fd, blocking_fd, invalid_limit, end_of_file, packet_too_large, partial_write };
    template<class DeviceFailure> using FdFailureFor=std::variant<FdError,DeviceFailure,std::error_code>;
    template<class DeviceFailure> struct FdStepFor {
        bool input = false, input_delivered = false, input_backpressured = false;
        bool output_delivered = false, output_backpressured = false, output_discarded = false;
        std::optional<FdFailureFor<DeviceFailure>> input_error, output_error;
    };
    using FdFailure=FdFailureFor<DeviceError>;
    using FdStep=FdStepFor<DeviceError>;
    namespace fd_detail {
        namespace abi {
            using raw_abi::read;
            using raw_abi::write;
            using raw_abi::fcntl;
            using raw_abi::__errno_location;
            inline constexpr int get_flags=3,nonblocking=2048;
        }
        using SetupFailure=std::variant<FdError,std::error_code>;
        inline auto system_error() noexcept -> std::error_code { return {*abi::__errno_location(),std::generic_category()}; }
        inline auto temporary(std::error_code error) noexcept -> bool {
            return error==std::errc::resource_unavailable_try_again || error==std::errc::operation_would_block || error==std::errc::interrupted;
        }
        inline auto validate(int fd,std::size_t mtu,std::size_t capacity) noexcept -> std::expected<void,SetupFailure> {
            if (fd<0) return std::unexpected(SetupFailure{FdError::invalid_fd});
            if (!mtu || mtu>65535 || mtu>capacity) return std::unexpected(SetupFailure{FdError::invalid_limit});
            int flags=abi::fcntl(fd,abi::get_flags);
            if (flags<0) return std::unexpected(SetupFailure{system_error()});
            if (!(flags&abi::nonblocking)) return std::unexpected(SetupFailure{FdError::blocking_fd});
            return {};
        }
        template<class Failure> inline auto convert(SetupFailure error) -> Failure {
            return std::visit([](auto value) -> Failure { return Failure{value}; },error);
        }
        // One algorithm for MemoryLink and compile-time packet devices.
        template<class Device> auto step(int fd,Device& device,std::size_t mtu,std::span<std::uint8_t> buffer,std::size_t& input_size,
            std::optional<typename Device::Packet>& output) -> FdStepFor<typename Device::Failure> {
            using Failure=FdFailureFor<typename Device::Failure>;
            FdStepFor<typename Device::Failure> result;
            if (!output) {
                auto packet=device.receive_packet();
                if (!packet) result.output_error=Failure{packet.error()};
                else if (*packet) output=std::move(**packet);
            }
            if (output && !device.valid_output(*output)) { output.reset(); result.output_discarded=true; }
            if (output) {
                auto bytes=device.packet_bytes(*output);
                if (bytes.size()>mtu) { result.output_error=Failure{FdError::packet_too_large}; output.reset(); }
                else {
                    auto count=abi::write(fd,bytes.data(),bytes.size());
                    if (count<0) {
                        auto error=system_error();
                        if (temporary(error)) result.output_backpressured=true;
                        else result.output_error=Failure{error};
                    } else if (static_cast<std::size_t>(count)!=bytes.size()) { result.output_error=Failure{FdError::partial_write}; output.reset(); }
                    else {
                        if constexpr (requires {device.output_delivered(bytes);}) device.output_delivered(bytes);
                        result.output_delivered=true;
                        output.reset();
                    }
                }
            }
            if (!input_size) {
                auto count=abi::read(fd,buffer.data(),buffer.size());
                if (count<0) {
                    auto error=system_error(); if (!temporary(error)) result.input_error=Failure{error};
                } else if (!count) result.input_error=Failure{FdError::end_of_file};
                else if (static_cast<std::size_t>(count)>mtu) result.input_error=Failure{FdError::packet_too_large};
                else { result.input=true; input_size=static_cast<std::size_t>(count); }
            }
            if (input_size) {
                try {
                    auto sent=device.send(std::span<std::uint8_t const>(buffer).first(input_size));
                    if (sent) { result.input_delivered=true; input_size=0; }
                    else if (device.retryable(sent.error())) result.input_backpressured=true;
                    else { result.input_error=Failure{sent.error()}; input_size=0; }
                } catch (std::bad_alloc const&) { result.input_backpressured=true; }
            }
            return result;
        }
    }
    // Original API and MemoryLink behavior use the same sole algorithm.
    class FdPump {
        int fd_;
        MemoryLink* link_;
        std::size_t mtu_;
        Bytes buffer_;
        std::size_t input_size_ = 0;
        std::optional<QueuedPacket> output_;
        FdPump(int fd, MemoryLink& link, std::size_t mtu);
    public:
        ~FdPump();
        FdPump(FdPump&&) noexcept;
        auto operator=(FdPump&&) noexcept -> FdPump&;
        FdPump(FdPump const&) = delete;
        auto operator=(FdPump const&) -> FdPump& = delete;
        [[nodiscard]] static auto create(int fd,MemoryLink& link,std::size_t mtu) -> std::expected<FdPump,FdFailure>;
        using OutputValidator=bool (*)(void*,QueuedPacket const&) noexcept;
        [[nodiscard]] auto step(OutputValidator validator=nullptr,void* context=nullptr) -> FdStep;
    };
    // Device statically supplies Packet/Failure, send/receive_packet,
    // packet_bytes, retryable and valid_output. No extra queue or heap.
    template<class Device,std::size_t Capacity> class StaticFdPump {
        static_assert(Capacity>0 && Capacity<=65535);
    public:
        class Setup {
            friend class StaticFdPump;
            int fd_; std::size_t mtu_;
            Setup(int fd,std::size_t mtu) noexcept : fd_(fd),mtu_(mtu) {}
        public:
            Setup(Setup const&)=delete;
            auto operator=(Setup const&) -> Setup& = delete;
            Setup(Setup&&)=default;
        };
        using Failure=FdFailureFor<typename Device::Failure>;
        using Step=FdStepFor<typename Device::Failure>;
    private:
        int fd_;
        Device* device_;
        std::size_t mtu_;
        std::array<std::uint8_t,Capacity+1> buffer_{};
        std::size_t input_size_=0;
        std::optional<typename Device::Packet> output_;
    public:
        StaticFdPump(Setup setup,Device& device) noexcept : fd_(setup.fd_),device_(&device),mtu_(setup.mtu_) {}
        StaticFdPump(StaticFdPump const&)=delete;
        auto operator=(StaticFdPump const&) -> StaticFdPump& = delete;
        StaticFdPump(StaticFdPump&&)=delete;
        auto operator=(StaticFdPump&&) -> StaticFdPump& = delete;
        [[nodiscard]] static auto prepare(int fd,std::size_t mtu) noexcept -> std::expected<Setup,Failure> {
            auto checked=fd_detail::validate(fd,mtu,Capacity);
            if (!checked) return std::unexpected(fd_detail::convert<Failure>(checked.error()));
            return Setup(fd,mtu);
        }
        [[nodiscard]] static auto create(int fd,Device& device,std::size_t mtu) -> std::expected<StaticFdPump,Failure> {
            auto setup=prepare(fd,mtu); if (!setup) return std::unexpected(setup.error());
            return std::expected<StaticFdPump,Failure>(std::in_place,std::move(*setup),device);
        }
        [[nodiscard]] auto step() -> Step { return fd_detail::step(fd_,*device_,mtu_,std::span(buffer_).first(mtu_+1),input_size_,output_); }
        [[nodiscard]] auto pending() const noexcept -> bool { return input_size_ || output_; }
        auto clear() noexcept -> void { std::ranges::fill(buffer_,0); input_size_=0; output_.reset(); }
    };
}
