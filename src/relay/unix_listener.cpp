module;
#include <cerrno>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/when_all.hpp>
#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/corosio/posix_stream_descriptor.hpp>
#include <boost/corosio/local_stream_socket.hpp>
#include <boost/corosio/timeout.hpp>
#include <boost/corosio/wait_type.hpp>

module relay;
import std;
import net.stream_relay;
import platform.unix_socket;
import proxy.v4;
import capy;
import corosio;

namespace relay {
    namespace {
        namespace unix_stream=platform::unix_stream;

        auto open_local(io::local_stream_socket& destination,io::io_context& context,
            std::string_view path,Clock::time_point deadline) -> capy::task<bool> {
            auto endpoint=unix_stream::address(path);
            unix_stream::Fd socket(::socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0));
            if (!endpoint || !socket) co_return false;
            if (::connect(socket.get(),reinterpret_cast<sockaddr*>(&endpoint->value),endpoint->size)<0) {
                if (errno!=EINPROGRESS) co_return false;
                io::posix_stream_descriptor pending(context);
                if (pending.assign(socket.get())) co_return false;
                (void)socket.release();
                auto [ec]=co_await io::timeout(pending.wait(io::wait_type::write),deadline);
                if (ec) co_return false;
                int status=0;
                socklen_t size=sizeof(status);
                if (::getsockopt(pending.native_handle(),SOL_SOCKET,SO_ERROR,&status,&size)<0 || status) co_return false;
                auto [released,fd]=pending.release();
                if (released) co_return false;
                socket.reset(fd);
            }
            if (destination.assign(socket.get())) co_return false;
            (void)socket.release();
            co_return true;
        }

        template<class Source,class Destination>
        struct LocalTransfer {
            Source& source;
            Destination& destination;
            Session& session;
            bool upstream;
            static constexpr bool socket_input=true,socket_output=true,locked_output=false;
            auto start() const -> bool {return !session.closed;}
            auto input_fd() const noexcept -> int {
                if constexpr (requires { { source.native_handle() } -> std::convertible_to<int>; })
                    return static_cast<int>(source.native_handle());
                else return -1;
            }
            auto output_fd() const noexcept -> int {
                if constexpr (requires { { destination.native_handle() } -> std::convertible_to<int>; })
                    return static_cast<int>(destination.native_handle());
                else return -1;
            }
            auto read(std::span<std::uint8_t> bytes) {return source.read_some(capy::mutable_buffer(bytes.data(),bytes.size()));}
            auto write(std::span<std::uint8_t const> bytes) {return destination.write_some(capy::const_buffer(bytes.data(),bytes.size()));}
            auto eof(std::error_code const& error,std::size_t size) const -> bool {return error==capy::cond::eof || (!error && !size);}
            auto invalid_read(std::error_code const& error,std::size_t size,std::size_t space) const -> bool {return error || size>space;}
            auto invalid_write(std::error_code const& error,std::size_t size,std::size_t space) const -> bool {
                return error || !size || size>space;
            }
            auto close_now() const -> bool {return !destination.shutdown(io::shutdown_send);}
            auto after_read() const -> void {session.touched=Clock::now();}
            auto after_write() const -> void {session.touched=Clock::now();}
            auto delivered(std::size_t size) const -> void {session.traffic_delivery()(upstream,size);}
            auto read_failed() const noexcept -> void {session.close();}
            auto write_failed() const noexcept -> void {session.close();}
        };

        template<class Source,class Target>
        auto local_direction(Source& source,Target& target,Session& session,bool upstream) -> capy::task<capy::results<>> {
            try {
                if (!co_await net::stream_relay::transfer(LocalTransfer{source,target,session,upstream})) session.close();
            } catch (...) {
                session.close();
                throw;
            }
            co_return capy::results<>{};
        }

        template<class Source,class Target>
        auto local_relay(Source& source,Target& target,Session& session) -> capy::task<> {
            std::stop_callback cancel(session.stop.get_token(),[&]() noexcept {source.cancel();target.cancel();});
            session.relaying=true;
            (void)co_await capy::when_all(local_direction(source,target,session,true),local_direction(target,source,session,false));
        }

        struct FinishLocal {
            Session& session;
            ~FinishLocal() { session.close();session.done=true; }
        };

        auto serve_local(std::unique_ptr<Session> session,io::local_stream_socket source,io::io_context& context,
            rules::RouteProgram const& policy,socks5::Request const* tcp,std::string_view target) -> capy::task<> {
            FinishLocal finish{*session};
            session->begin_traffic(TrafficProtocol::fixed_tcp,tcp ? tcp->port : 0);
            if (target.empty()) {
                if (co_await dial_destination(*session,context,policy,*tcp,session->handshake_deadline)) co_return;
                co_await local_relay(source,session->target,*session);
            } else {
                io::local_stream_socket local(context);
                if (!co_await open_local(local,context,target,session->handshake_deadline)) co_return;
                co_await local_relay(source,local,*session);
            }
        }
    }

    auto serve_fixed_unix(Session& session,io::io_context& context,std::string_view path) -> capy::task<> {
        FinishLocal finish{session};
        io::local_stream_socket target(context);
        if (!co_await open_local(target,context,path,session.handshake_deadline)) co_return;
        session.begin_traffic(TrafficProtocol::fixed_tcp,0);
        co_await local_relay(session.client,target,session);
    }

    auto Server::accept_unix() -> capy::task<> {
        while (accepting) {
            auto [wait_error]=co_await listener_readiness->wait(io::wait_type::read);
            if (!accepting) co_return;
            if (wait_error) {
                record_failure({FailureKind::accept,wait_error});
                co_return;
            }
            unix_stream::Fd fd(::accept4(listener_readiness->native_handle(),nullptr,nullptr,SOCK_NONBLOCK|SOCK_CLOEXEC));
            if (!fd) {
                if (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR || errno==ECONNABORTED) continue;
                record_failure({FailureKind::accept,unix_stream::error()});
                co_return;
            }
            if (shedding_memory()) continue;
            auto lease=quota.try_acquire();
            if (!lease) continue;
            io::local_stream_socket peer(context);
            if (auto error=peer.assign(fd.get())) {
                record_failure({FailureKind::accept,error});
                co_return;
            }
            (void)fd.release();
            auto session=std::make_unique<Session>(context);
            attach_session(*session,std::move(*lease));
            auto const& matcher=session->route_snapshot ? session->route_snapshot->matcher : policy;
            auto stop=session->stop.get_token();
            auto on_error=session_error(*session);
            auto task=serve_local(std::move(session),std::move(peer),context,matcher,
                                  fixed_tcp_target ? &*fixed_tcp_target : nullptr,fixed_unix_target);
            capy::run_async(context.get_executor(),stop,[] {},std::move(on_error))(std::move(task));
        }
    }
    auto Server::set_fixed_unix_target(std::string_view path) -> bool {
        if (running || !platform::unix_stream::address(path)) return false;
        fixed_unix_target=path;
        return true;
    }

    auto Server::start_unix(std::string_view path,unsigned workers) -> std::expected<void,std::error_code> {
        using namespace platform::unix_stream;
        if (running || workers!=1 || (fixed_unix_target.empty() && !fixed_tcp_target) || path==fixed_unix_target)
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        auto owner=std::make_unique<ListenerPath>();
        Fd socket(::socket(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0));
        if (!socket) return std::unexpected(error());
        if (auto ec=owner->bind(socket.get(),path)) return std::unexpected(ec);
        if (::listen(socket.get(),SOMAXCONN)<0) return std::unexpected(error());
        if (owner->directory) (void)::flock(owner->directory.get(),LOCK_UN);
        if (auto prepared=prepare_routing(1);!prepared) return std::unexpected(prepared.error());
        if (auto activated=activate_context();!activated) return std::unexpected(activated.error());
        listener_readiness.emplace(context);
        if (auto ec=listener_readiness->assign(socket.get())) {
            if (shared_context) { stop(); return std::unexpected(ec); }
            stop_outbound_contexts();
            context.restart();
            (void)context.run();
            finish_outbound_contexts();
            return std::unexpected(ec);
        }
        (void)socket.release();
        unix_listener_cleanup=[owner=std::move(owner)]() noexcept {owner->close();};
        inbound_type=Inbound::fixed_tcp;
        running=accepting=accept_task_active=true;
        try {
            capy::run_async(context.get_executor(), [this]() noexcept { accept_task_active=false; },
                [this](std::exception_ptr) noexcept {
                try {record_failure({FailureKind::accept_task,{}});} catch (...) {}
                running=accepting=accept_task_active=false;
                close_listener();
            })(accept_unix());
        } catch (...) {
            accept_task_active=false;
            stop();
            throw;
        }
        return {};
    }
}
