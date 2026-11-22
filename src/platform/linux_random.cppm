#if !defined(__linux__) || (!defined(__x86_64__) && !defined(__aarch64__)) || !defined(__LP64__)
#error "The Linux entropy boundary is verified for Linux x86-64 / aarch64 LP64 only"
#endif

export module platform.linux_random;
import std;

// This boundary is checked against the system declarations and flag in the
// existing TUN entropy fault fixture. It targets the workspace's glibc ABI.
namespace platform::linux_abi {
    extern "C" std::ptrdiff_t getrandom(void*,std::size_t,unsigned int);
    extern "C" int* __errno_location() noexcept;
}
#ifdef NEXUS_TEST_LINUX_RANDOM
extern "C" bool nexus_test_linux_random(void*,std::size_t,unsigned int,std::ptrdiff_t*) noexcept;
#endif

export namespace platform {
    namespace linux_random_abi {
        using GetrandomSignature=std::ptrdiff_t (*)(void*,std::size_t,unsigned int);
        using ErrnoLocationSignature=int* (*)() noexcept;
        inline constexpr unsigned int nonblocking_flag=1;
    }
    // Never waits for kernel RNG initialization; EINTR and short reads retry.
    // Any other failure is returned to the caller, including a zero read.
    [[nodiscard]] auto secure_random(std::span<std::byte> bytes) noexcept -> std::expected<void,std::error_code> {
        std::size_t offset=0;
        while (offset<bytes.size()) {
            std::ptrdiff_t count;
#ifdef NEXUS_TEST_LINUX_RANDOM
            if (!nexus_test_linux_random(bytes.data()+offset,bytes.size()-offset,linux_random_abi::nonblocking_flag,&count))
#endif
                count=linux_abi::getrandom(bytes.data()+offset,bytes.size()-offset,linux_random_abi::nonblocking_flag);
            if (count<0) {
                auto error=*linux_abi::__errno_location();
                if (error==std::to_underlying(std::errc::interrupted)) continue;
                return std::unexpected(std::error_code(error,std::generic_category()));
            }
            if (!count) return std::unexpected(std::make_error_code(std::errc::io_error));
            offset+=static_cast<std::size_t>(count);
        }
        return {};
    }
}
