#pragma once
#include <cerrno>
#include <system_error>
#include <sys/socket.h>

namespace shadowsocks::detail {
    // Configure before closing an unauthenticated TCP connection. The caller
    // must still close the socket and handle failure to configure the option.
    inline auto prepare_probe_reset(int fd) noexcept -> std::error_code {
        linger option{1,0};
        if (::setsockopt(fd,SOL_SOCKET,SO_LINGER,&option,sizeof(option))==0) return {};
        return {errno,std::generic_category()};
    }
}
