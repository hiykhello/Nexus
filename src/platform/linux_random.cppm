module;
#if defined(__linux__)
#if (!defined(__x86_64__) && !defined(__aarch64__)) || !defined(__LP64__)
#error "The Linux entropy boundary is verified for Linux x86-64 / aarch64 LP64 only"
#endif
#include <cstddef>

namespace platform::linux_abi {
    extern "C" std::ptrdiff_t getrandom(void*,std::size_t,unsigned int);
    extern "C" int* __errno_location() noexcept;
}
#ifdef NEXUS_TEST_LINUX_RANDOM
extern "C" bool nexus_test_linux_random(void*,std::size_t,unsigned int,std::ptrdiff_t*) noexcept;
#endif
#elif defined(__APPLE__)
#include <cstdlib>
#elif defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#if defined(_MSC_VER)
#pragma comment(lib, "bcrypt.lib")
#endif
#else
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#endif

export module platform.linux_random;
import std;

export namespace platform {
#if defined(__linux__)
    namespace linux_random_abi {
        using GetrandomSignature=std::ptrdiff_t (*)(void*,std::size_t,unsigned int);
        using ErrnoLocationSignature=int* (*)() noexcept;
        inline constexpr unsigned int nonblocking_flag=1;
    }
#endif
    // Never blocks on POSIX when backed by kernel CSPRNG / nonblocking entropy.
    // Any OS failure or zero read is returned to the caller.
    [[nodiscard]] auto secure_random(std::span<std::byte> bytes) noexcept -> std::expected<void,std::error_code> {
        if (bytes.empty()) return {};
#if defined(__linux__)
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
#elif defined(__APPLE__)
        ::arc4random_buf(bytes.data(),bytes.size());
        return {};
#elif defined(_WIN32)
        std::size_t offset=0;
        while (offset<bytes.size()) {
            auto chunk=std::min<std::size_t>(bytes.size()-offset,0x40000000u);
            auto status=::BCryptGenRandom(nullptr,reinterpret_cast<PUCHAR>(bytes.data()+offset),
                static_cast<ULONG>(chunk),BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            if (!BCRYPT_SUCCESS(status))
                return std::unexpected(std::error_code(static_cast<int>(status),std::system_category()));
            offset+=chunk;
        }
        return {};
#else
        int fd=::open("/dev/urandom",O_RDONLY|O_CLOEXEC);
        if (fd<0) return std::unexpected(std::error_code(errno,std::generic_category()));
        std::size_t offset=0;
        while (offset<bytes.size()) {
            auto count=::read(fd,bytes.data()+offset,bytes.size()-offset);
            if (count<0) {
                if (errno==EINTR) continue;
                auto err=errno;
                ::close(fd);
                return std::unexpected(std::error_code(err,std::generic_category()));
            }
            if (!count) {
                ::close(fd);
                return std::unexpected(std::make_error_code(std::errc::io_error));
            }
            offset+=static_cast<std::size_t>(count);
        }
        ::close(fd);
        return {};
#endif
    }
}
