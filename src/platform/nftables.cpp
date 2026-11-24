module;
#include <cerrno>
#include <cstring>
#include <linux/netlink.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

module platform.nftables;
import std;
import platform.linux_random;

namespace platform::nftables {
    namespace {
        auto error() noexcept -> std::error_code {return {errno,std::generic_category()};}
    }

    auto Table::close_socket() noexcept -> void {
        if (socket_>=0) { (void)::close(socket_); socket_=-1; }
    }

    auto Table::exchange(Transaction const& request,Clock::time_point deadline) -> std::error_code {
        sockaddr_nl kernel{.nl_family=AF_NETLINK};
        auto sent=::sendto(socket_,request.bytes.data(),request.bytes.size(),0,
            reinterpret_cast<sockaddr const*>(&kernel),sizeof kernel);
        if (sent<0) return error();
        if (static_cast<std::size_t>(sent)!=request.bytes.size()) return std::make_error_code(std::errc::io_error);
        std::bitset<512> acknowledgements;
        auto first=sequence_;
        sequence_=request.end;
        auto remaining=sequence_-first-2;
        while (Clock::now()<deadline) {
            auto delay=std::chrono::ceil<std::chrono::milliseconds>(deadline-Clock::now()).count();
            pollfd descriptor{socket_,POLLIN,0};
            auto ready=::poll(&descriptor,1,static_cast<int>(std::max<std::int64_t>(0,delay)));
            if (ready<0) {
                if (errno==EINTR) continue;
                return error();
            }
            if (!ready) break;
            alignas(nlmsghdr) std::array<std::uint8_t,32768> buffer;
            sockaddr_nl sender{};
            socklen_t width=sizeof sender;
            auto received=::recvfrom(socket_,buffer.data(),buffer.size(),MSG_TRUNC,
                reinterpret_cast<sockaddr*>(&sender),&width);
            if (received<0) {
                if (errno==EAGAIN || errno==EINTR) continue;
                return error();
            }
            if (sender.nl_pid!=0 || sender.nl_family!=AF_NETLINK || received>static_cast<ssize_t>(buffer.size()))
                return std::make_error_code(std::errc::protocol_error);
            for (auto offset=std::size_t{}; offset<static_cast<std::size_t>(received);) {
                nlmsghdr header{};
                if (std::size_t(received)-offset<sizeof header)
                    return std::make_error_code(std::errc::protocol_error);
                std::memcpy(&header,buffer.data()+offset,sizeof header);
                if (header.nlmsg_len<sizeof header || header.nlmsg_len>std::size_t(received)-offset)
                    return std::make_error_code(std::errc::protocol_error);
                if (header.nlmsg_seq>=first && header.nlmsg_seq<sequence_ && header.nlmsg_type==NLMSG_ERROR) {
                    if (header.nlmsg_len<NLMSG_LENGTH(sizeof(nlmsgerr)))
                        return std::make_error_code(std::errc::protocol_error);
                    nlmsgerr ack{};
                    std::memcpy(&ack,buffer.data()+offset+NLMSG_HDRLEN,sizeof ack);
                    if (ack.error) return {-ack.error,std::generic_category()};
                    auto index=header.nlmsg_seq-first;
                    if (index && index<sequence_-first-1 && !acknowledgements.test(index)) {
                        acknowledgements.set(index);
                        --remaining;
                    }
                }
                offset+=NLMSG_ALIGN(header.nlmsg_len);
            }
            if (!remaining) return {};
        }
        return std::make_error_code(std::errc::timed_out);
    }

    Table::~Table() { close_socket(); }
    auto Table::start(Redirect const& redirect,Clock::time_point deadline) -> std::error_code {
        if (socket_>=0) return std::make_error_code(std::errc::operation_in_progress);
        std::array<std::uint64_t,2> token{};
        if (auto random=secure_random(std::as_writable_bytes(std::span(token)));!random) return random.error();
        name_=std::format("nexus_auto_redirect_{:016x}{:016x}",token[0],token[1]);
        auto messages=encode(name_,&redirect,sequence_);
        if (!messages) return messages.error();
        socket_=::socket(AF_NETLINK,SOCK_RAW|SOCK_NONBLOCK|SOCK_CLOEXEC,NETLINK_NETFILTER);
        if (socket_<0) return error();
        sockaddr_nl local{.nl_family=AF_NETLINK};
        if (::bind(socket_,reinterpret_cast<sockaddr*>(&local),sizeof local)<0) {
            auto ec=error(); close_socket(); return ec;
        }
        auto result=exchange(*messages,deadline);
        if (result) { close_socket(); owned_=false; return result; }
        owned_=true;
        return {};
    }

    auto Table::stop(Clock::time_point deadline) -> std::error_code {
        if (!owned_) { close_socket(); return {}; }
        auto messages=encode(name_,nullptr,sequence_);
        auto result=messages ? exchange(*messages,deadline) : messages.error();
        close_socket();
        owned_=false;
        if (!result || result==std::errc::no_such_file_or_directory) return {};
        return result;
    }
}
