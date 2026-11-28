module;
#include <cerrno>
#include <sys/socket.h>
#if defined(__linux__)
#include <fcntl.h>
#include <unistd.h>
#endif
#include <proxy/proxy_macros.h>
#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/ex/async_event.hpp>
#include <boost/capy/when_all.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/endpoint.hpp>

module relay;
import proxy.v4;
import std;
import socks5;
import rules;
import http.connect;
import sniff.tcp;
import sniff.route_tcp;


namespace relay {
    namespace {
        auto write(io::tcp_socket& socket, std::span<std::uint8_t const> data, Session& session,std::optional<bool> payload_direction) -> capy::task<bool> {
            if (payload_direction && session.meters_principal_bytes())
                co_return co_await write_principal_payload(session,*payload_direction,data);
#ifdef MSG_NOSIGNAL
            constexpr int kSendFlags = MSG_DONTWAIT | MSG_NOSIGNAL;
#else
            constexpr int kSendFlags = MSG_DONTWAIT;
#endif
            std::size_t delivered = 0;
            while (!data.empty() && !session.closed) {
                int const fd = socket.native_handle();
                if (fd >= 0) {
                    ssize_t const w = ::send(fd, data.data(), data.size(), kSendFlags);
                    if (w > 0) {
                        auto const n = static_cast<std::size_t>(w);
                        delivered += n;
                        data = data.subspan(n);
                        continue;
                    }
                    if (w < 0 && errno == EINTR) continue;
                    if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                        if (payload_direction && delivered) session.count_traffic(*payload_direction, delivered);
                        co_return false;
                    }
                }
                if (delivered) {
                    if (payload_direction) session.count_traffic(*payload_direction, delivered);
                    session.touched = Clock::now();
                    delivered = 0;
                }
                if (session.closed) co_return false;
                auto [error, n] = co_await socket.write_some(capy::const_buffer(data.data(), data.size()));
                if (payload_direction && n) session.count_traffic(*payload_direction,n);
                if (error || n == 0 || session.closed) co_return false;
                session.touched = Clock::now();
                data = data.subspan(n);
            }
            if (delivered) {
                if (payload_direction) session.count_traffic(*payload_direction, delivered);
                session.touched = Clock::now();
            }
            co_return data.empty() && !session.closed;
        }
        auto read_nb_or_async(io::tcp_socket& socket, void* dst, std::size_t cap, Session& session)
            -> capy::task<std::pair<std::error_code, std::size_t>> {
            if (session.closed) co_return {std::make_error_code(std::errc::operation_canceled), std::size_t{0}};
            int const fd = socket.native_handle();
            if (fd >= 0) {
                for (;;) {
                    ssize_t const r = ::recv(fd, dst, cap, MSG_DONTWAIT);
                    if (r > 0) {
                        session.touched = Clock::now();
                        co_return {std::error_code{}, static_cast<std::size_t>(r)};
                    }
                    if (r == 0) co_return {std::error_code{}, std::size_t{0}};
                    if (errno == EINTR) continue;
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    co_return {std::error_code{errno, std::generic_category()}, std::size_t{0}};
                }
            }
            if (session.closed) co_return {std::make_error_code(std::errc::operation_canceled), std::size_t{0}};
            auto [error, n] = co_await socket.read_some(capy::mutable_buffer(dst, cap));
            if (!error && n) session.touched = Clock::now();
            co_return {error, n};
        }
        // Bounded high-throughput plain-TCP body copy using pooled 128 KiB buffers
        // (and bounded zero-copy Linux splice on epoll for large Content-Length bodies).
        auto forward_fixed_plain(Session& session, io::tcp_socket& input, io::tcp_socket& output,
            bool upstream, std::uint64_t remaining, bool stop_on_drain = false) -> capy::task<bool> {
            auto stop = [&]() noexcept { return session.closed || (stop_on_drain && session.http_draining); };
            constexpr std::size_t kYieldBurstBytes = 512 * 1024;
#if defined(__linux__) && !BOOST_COROSIO_HAVE_LIBURING
            if (remaining >= 64 * 1024 && session.splice_pipes && session.splice_pipe_pool) {
                if (auto lease = session.splice_pipes->try_acquire()) {
                    auto pipe = session.splice_pipe_pool->acquire();
                    if (pipe.valid()) {
                        std::size_t in_pipe = 0, burst = 0, since_yield = 0;
                        auto const max_cached = std::min(session.splice_pipes->limit(), session.splice_max_idle_pipes);
                        struct Guard {
                            SplicePipePool* pool; SplicePipePool::Pipe pipe; std::size_t const& in_pipe; std::size_t max_cached;
                            ~Guard() { pool->release(pipe, in_pipe == 0, max_cached, Clock::now()); }
                        } guard{session.splice_pipe_pool, pipe, in_pipe, max_cached};
                        constexpr auto flags = SPLICE_F_MOVE | SPLICE_F_NONBLOCK;
                        auto const chunk = std::min<std::size_t>(pipe.capacity, SplicePipePool::kTargetPipeSize);
                        auto flush = [&]() noexcept {
                            if (burst) { session.count_traffic(upstream, burst); session.touched = Clock::now(); burst = 0; }
                        };
                        while (remaining > 0 && !stop()) {
                            int const in_fd = input.native_handle();
                            if (in_fd < 0) { flush(); co_return false; }
                            auto const want = static_cast<std::size_t>(std::min<std::uint64_t>(chunk, remaining));
                            auto r = ::splice(in_fd, nullptr, pipe.fd[1], nullptr, want, flags);
                            if (r < 0) {
                                int const e = errno;
                                if (e == EINTR) continue;
                                if (e == EAGAIN) {
                                    flush();
                                    since_yield = 0;
                                    auto [we] = co_await input.wait(io::wait_type::read);
                                    if (we || stop()) co_return false;
                                    continue;
                                }
                                flush();
                                if (e == EINVAL || e == ENOSYS || e == EOPNOTSUPP || e == EPERM || e == EACCES) break;
                                co_return false;
                            }
                            if (r == 0) { flush(); co_return false; }
                            in_pipe = static_cast<std::size_t>(r);
                            remaining -= in_pipe;
                            while (in_pipe > 0 && !stop()) {
                                int const out_fd = output.native_handle();
                                if (out_fd < 0) { flush(); co_return false; }
                                auto w = ::splice(pipe.fd[0], nullptr, out_fd, nullptr, in_pipe, flags);
                                if (w > 0) {
                                    auto const n = static_cast<std::size_t>(w);
                                    in_pipe -= n; burst += n; since_yield += n; continue;
                                }
                                if (w == 0) { flush(); co_return false; }
                                int const e = errno;
                                if (e == EINTR) continue;
                                if (e == EAGAIN) {
                                    flush();
                                    since_yield = 0;
                                    auto [we] = co_await output.wait(io::wait_type::write);
                                    if (we || stop()) co_return false;
                                    continue;
                                }
                                flush(); co_return false;
                            }
                            if (since_yield >= kYieldBurstBytes && remaining > 0 && !stop()) {
                                flush();
                                since_yield = 0;
                                co_await YieldToExecutor{};
                            }
                        }
                        flush();
                        if (remaining == 0 && in_pipe == 0) co_return true;
                        if (in_pipe > 0 || stop()) co_return false;
                    }
                }
            }
#endif
            DirectBufferPool::Lease pooled = (remaining >= 32 * 1024 && session.direct_buffers)
                ? session.direct_buffers->try_acquire() : DirectBufferPool::Lease{};
            std::array<std::uint8_t, http::max_connect_header_bytes> small;
            auto* ptr = pooled ? pooled.data() : small.data();
            auto const cap = pooled ? DirectBufferPool::kBufferSize : small.size();
            std::size_t since_yield = 0;
            while (remaining > 0 && !stop()) {
                auto const want = static_cast<std::size_t>(std::min<std::uint64_t>(cap, remaining));
                auto [ec, n] = co_await read_nb_or_async(input, ptr, want, session);
                if (ec || n == 0 || stop()) co_return false;
                if (!co_await write(output, std::span(ptr, n), session, upstream)) co_return false;
                remaining -= n;
                since_yield += n;
                if (since_yield >= kYieldBurstBytes && remaining > 0 && !stop()) {
                    since_yield = 0;
                    co_await YieldToExecutor{};
                }
            }
            co_return remaining == 0 && !stop();
        }
        auto write_text(io::tcp_socket& socket, std::string_view text, Session& session,std::optional<bool> payload_direction={}) -> capy::task<bool> {
            co_return co_await write(socket, {reinterpret_cast<std::uint8_t const*>(text.data()),text.size()},session,payload_direction);
        }
        constexpr auto http_error_reply(std::uint16_t code, bool head) noexcept -> std::string_view {
            switch (code) {
            case 403: return head ? "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                                  : "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 10\r\n\r\nForbidden\n";
            case 417: return head ? "HTTP/1.1 417 Expectation Failed\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                                  : "HTTP/1.1 417 Expectation Failed\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 19\r\n\r\nExpectation Failed\n";
            case 431: return head ? "HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                                  : "HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 32\r\n\r\nRequest Header Fields Too Large\n";
            case 501: return head ? "HTTP/1.1 501 Not Implemented\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                                  : "HTTP/1.1 501 Not Implemented\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 16\r\n\r\nNot Implemented\n";
            case 502: return head ? "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                                  : "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 12\r\n\r\nBad Gateway\n";
            default:  return head ? "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                                  : "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 12\r\n\r\nBad Request\n";
            }
        }
        auto write_target(Session& session, std::string_view text) -> capy::task<bool> {
            if (!session.tunnel) co_return co_await write_text(session.target,text,session,true);
            if (session.meters_principal_bytes())
                co_return co_await write_principal_payload(session,true,
                    {reinterpret_cast<std::uint8_t const*>(text.data()),text.size()});
            if (!co_await session.tunnel->send({reinterpret_cast<std::uint8_t const*>(text.data()),text.size()}))
                co_return false;
            session.count_traffic(true,text.size());
            co_return true;
        }
        auto finish(Session& session) -> void { session.close(); }

        auto drain(Session& session) -> capy::task<> {
            std::array<char, http::max_connect_header_bytes> buffer{};
            while (!session.closed) {
                auto [error, n] = co_await session.client.read_some(capy::mutable_buffer(buffer.data(), buffer.size()));
                if (error || n == 0) break;
            }
            session.close();
        }

        auto finish_response(Session& session, capy::async_event* ready = nullptr) -> void {
            session.http_draining = true;
            session.http_drain_started = Clock::now();
            session.target.close();
            if (session.tunnel) session.tunnel->cancel();
            (void)session.client.shutdown(io::shutdown_send);
            if (ready) ready->set();
        }

        auto upload_body(Session& session, std::string initial, http::RequestDecoder& decoder)
            -> capy::task<bool> {
            if (!decoder.complete() && !decoder.request().chunked &&
                !session.tunnel && !session.meters_principal_bytes()) {
                std::uint64_t remaining = decoder.request().body_length;
                if (!initial.empty()) {
                    auto const take = static_cast<std::size_t>(std::min<std::uint64_t>(remaining, initial.size()));
                    if (!co_await write_target(session, std::string_view(initial).substr(0, take))) co_return false;
                    remaining -= take;
                }
                if (remaining == 0) co_return true;
                co_return co_await forward_fixed_plain(session, session.client, session.target, true, remaining, true);
            }
            std::array<char, http::max_connect_header_bytes> buffer;
            std::string_view data = initial;
            std::string output;
            bool complete = decoder.complete();
            while (!complete && !session.closed) {
                auto step=decoder.feed(data,output);
                if (step.event==http::RequestEvent::malformed || step.event==http::RequestEvent::truncated) break;
                if (!co_await write_target(session,step.wire)) break;
                if (step.event==http::RequestEvent::complete) { complete=true; break; }
                if (step.consumed<data.size()) {
                    if (!step.consumed) break;
                    data.remove_prefix(step.consumed);
                    continue;
                }
                auto capacity=decoder.next_read_size();
                auto [error, n] = co_await read_nb_or_async(session.client, buffer.data(), capacity, session);
                if (error || n == 0 || session.http_draining) break;
                data = std::string_view(buffer.data(), n);
            }
            co_return complete;
        }

        auto upload(Session& session, std::string initial, http::RequestDecoder& decoder,
                    capy::async_event& response_done) -> capy::task<> {
            auto complete = co_await upload_body(session, std::move(initial), decoder);
            if (!complete && !session.closed && !session.http_draining) {
                if (session.tunnel) session.tunnel->cancel();
                else (void)session.target.shutdown(io::shutdown_send);
            }
            if (!session.closed && !session.http_draining)
                (void)co_await response_done.wait();
            if (!session.closed && session.http_draining) co_await drain(session);
        }

        auto response(Session& session, bool head, capy::async_event& response_done) -> capy::task<> {
            struct DoneGuard { capy::async_event& ev; ~DoneGuard() { ev.set(); } } done_guard{response_done};
            std::array<std::uint8_t, http::max_connect_header_bytes> buffer;
            std::size_t size=0, offset=0;
            bool final_header=false;
            http::ResponseDecoder decoder(head,static_cast<bool>(session.tunnel));
            for (;;) {
                auto data=std::string_view(reinterpret_cast<char const*>(buffer.data()+offset),size-offset);
                auto step=decoder.feed(data);
                offset+=step.consumed;
                if (step.event==http::ResponseEvent::malformed || step.event==http::ResponseEvent::truncated) {
                    if (!final_header) {
                        if (co_await write_text(session.client,http_error_reply(502,head),session)) finish_response(session,&response_done);
                        else finish(session);
                    } else finish_response(session,&response_done);
                    co_return;
                }
                if (step.event==http::ResponseEvent::header && !step.informational) final_header=true;
                if (!step.wire.empty() && !co_await write_text(session.client,step.wire,session,false)) { finish(session); co_return; }
                if (step.event==http::ResponseEvent::complete) { finish_response(session,&response_done); co_return; }
                if (step.event==http::ResponseEvent::header && !step.informational && !head &&
                    step.status_code!=204 && step.status_code!=304 && step.content_length && *step.content_length>0 &&
                    !session.tunnel && !session.meters_principal_bytes()) {
                    std::uint64_t remaining=*step.content_length;
                    if (offset<size) {
                        auto const take=static_cast<std::size_t>(std::min<std::uint64_t>(remaining,size-offset));
                        if (!co_await write(session.client,std::span(buffer.data()+offset,take),session,false)) { finish(session); co_return; }
                        remaining-=take;
                    }
                    if (remaining>0 && !co_await forward_fixed_plain(session,session.target,session.client,false,remaining)) {
                        finish(session);
                        co_return;
                    }
                    finish_response(session,&response_done);
                    co_return;
                }
                if (offset<size) {
                    if (!step.consumed) { finish(session); co_return; }
                    continue;
                }
                if (step.event==http::ResponseEvent::header) continue;
                std::error_code error;
                std::size_t n=0;
                if (session.tunnel) {
                    auto result=co_await session.tunnel->read(buffer);
                    if (result) n=*result;
                    else error=std::make_error_code(std::errc::io_error);
                } else {
                    std::tie(error, n) = co_await read_nb_or_async(session.target, buffer.data(), buffer.size(), session);
                }
                if (error && session.tunnel) {
                    if (!final_header) {
                        if (co_await write_text(session.client,http_error_reply(502,head),session)) finish_response(session,&response_done);
                        else finish(session);
                    } else finish_response(session,&response_done);
                    co_return;
                }
                if (error || n==0) {
                    auto end=decoder.finish();
                    if (!end.wire.empty() && !co_await write_text(session.client,end.wire,session,false)) { finish(session); co_return; }
                    if (end.event!=http::ResponseEvent::complete && !final_header) {
                        if (co_await write_text(session.client,http_error_reply(502,head),session)) finish_response(session,&response_done);
                        else finish(session);
                    } else finish_response(session,&response_done);
                    co_return;
                }
                session.touched=Clock::now(); size=n; offset=0;
            }
        }

        // The forward decoder retains and rewrites the original header. Sniff
        // only that complete prefix; replaying it would send a second request.
        auto ordered_forward_dial(Session& session,io::io_context& context,socks5::Request const& request,
            std::string_view header,std::span<std::uint8_t const> first,bool& first_sent) -> capy::task<std::uint8_t> {
            OrderedTcpRequest owner;
            if(!owner.prepare(session,request))co_return 1;
            std::array<std::uint8_t,http::max_connect_header_bytes> wire{},scratch{};
            sniff::TcpSniffer sniffer(wire,scratch);
            auto prefix=std::span(reinterpret_cast<std::uint8_t const*>(header.data()),header.size());
            auto fed=sniffer.feed(prefix);
            if(fed.consumed!=prefix.size())co_return 1;
            rules::ProgramCursor cursor;
            auto const& policy=*session.ordered_tcp;
            auto sniff_deadline=std::min(session.handshake_deadline,Clock::now()+policy.sniff_timeout);
            auto branch=[&]() -> capy::task<capy::results<OrderedTcpResult>> {
                auto result=co_await execute_ordered_tcp(session,context,policy.program,cursor,owner.input,sniffer,
                    owner.candidates,owner.endpoints,policy.fallback,sniff_deadline,session.handshake_deadline,policy.unknown_policy,nullptr,nullptr,first);
                co_return capy::results<OrderedTcpResult>{std::make_error_code(std::errc::operation_canceled),std::move(result)};
            };
            auto [signal,result,watch]=co_await capy::when_all(branch(),watch_client_error(session));
            (void)signal;(void)watch;
            first_sent=result.first_sent;
            co_return !session.closed && result.stop==sniff::RouteTcpStop::terminal ? result.code : 1;
        }

        auto joined_upload(Session& session, std::string initial, http::RequestDecoder& decoder,
                           capy::async_event& response_done) -> capy::task<capy::results<>> {
            try { co_await upload(session, std::move(initial), decoder, response_done); }
            catch (...) { session.close(); throw; }
            co_return capy::results<>{};
        }
        auto joined_response(Session& session, bool head, capy::async_event& response_done)
            -> capy::task<capy::results<>> {
            try { co_await response(session,head,response_done); }
            catch (...) { session.close(); throw; }
            co_return capy::results<>{};
        }
    }

    auto Server::probe_http(Session& session,OutboundProbe& probe) -> capy::task<bool> {
        if (probe.use_tls) co_return co_await probe_https(session,probe);
        if (co_await dial_destination(session,context,probe.route,probe.target,probe.deadline)) co_return false;
        session.handshake_deadline=probe.deadline;
        if (!co_await write_target(session,probe.request)) co_return false;
        http::ResponseDecoder decoder(true,false);
        std::array<std::uint8_t,1024> buffer{};
        auto status_ok=[&](std::uint16_t code) noexcept -> bool {
            if (probe.expected_status.empty()) return code>=200 && code<300;
            return std::ranges::any_of(probe.expected_status,[code](auto const& range) {
                return code>=range.low && code<=range.high;
            });
        };
        while (!session.closed && Clock::now()<probe.deadline) {
            std::size_t size=0;
            if (session.tunnel) {
                auto data=co_await session.tunnel->read(buffer);
                if (!data) co_return false;
                size=*data;
            } else {
                auto [error,n]=co_await session.target.read_some(capy::mutable_buffer(buffer.data(),buffer.size()));
                if (error) co_return false;
                size=n;
            }
            if (!size || Clock::now()>=probe.deadline) co_return false;
            auto data=std::string_view(reinterpret_cast<char const*>(buffer.data()),size);
            while (!data.empty()) {
                auto step=decoder.feed(data);
                if (step.event==http::ResponseEvent::header && !step.informational) {
                    probe.status_code.store(step.status_code,std::memory_order_relaxed);
                    co_return status_ok(step.status_code);
                }
                if (!step.consumed || step.event==http::ResponseEvent::malformed) co_return false;
                data.remove_prefix(step.consumed);
            }
        }
        co_return false;
    }

    auto forward_http(Session& session, io::io_context& context,
                      rules::RouteProgram const& policy, std::string_view input) -> capy::task<> {
        http::RequestDecoder decoder;
        std::string output;
        auto first=decoder.feed(input,output);
        auto const& request=decoder.request();
        if (first.event != http::RequestEvent::header) {
            auto const err = request.status == http::ConnectStatus::too_large ? std::uint16_t{431} :
                request.status == http::ConnectStatus::expectation_failed ? std::uint16_t{417} :
                request.status == http::ConnectStatus::unsupported ? std::uint16_t{501} : std::uint16_t{400};
            if (co_await write_text(session.client, http_error_reply(err, input.starts_with("HEAD ")), session)) {
                finish_response(session);
                co_await drain(session);
            } else finish(session);
            session.done = true;
            co_return;
        }
        socks5::Request destination;
        destination.status = socks5::Status::accepted;
        destination.port = request.destination.port;
        if (request.destination.kind == http::HostKind::domain) {
            destination.address_type = 3;
            destination.address_length = static_cast<std::uint8_t>(request.destination.host.size());
            std::copy(request.destination.host.begin(), request.destination.host.end(), destination.address.begin());
        } else {
            destination.address_type = request.destination.kind == http::HostKind::ipv4 ? 1 : 4;
            destination.address_length = request.destination.kind == http::HostKind::ipv4 ? 4 : 16;
            std::copy(request.destination.address.begin(), request.destination.address.end(), destination.address.begin());
        }
        session.begin_traffic(TrafficProtocol::http_forward,destination.port);
        bool first_sent=false;
        auto first_wire=std::span(reinterpret_cast<std::uint8_t const*>(request.wire.data()),request.wire.size());
        auto code = session.ordered_tcp ? co_await ordered_forward_dial(session,context,destination,input.substr(0,first.consumed),first_wire,first_sent) :
            co_await dial(session,context,policy,destination,Clock::time_point::max(),first_wire,&first_sent);
        if (code != 0) {
            if (co_await write_text(session.client, http_error_reply(code == 2 ? 403 : 502, request.head), session)) {
                finish_response(session);
                co_await drain(session);
            } else finish(session);
            session.done = true;
            co_return;
        }
        session.relaying = true;
        if (!first_sent && !co_await write_target(session, request.wire)) { finish(session); session.done = true; co_return; }
        auto tail = input.substr(first.consumed);
        if (!request.chunked) tail = tail.substr(0, static_cast<std::size_t>(std::min<std::uint64_t>(request.body_length, tail.size())));
        capy::async_event response_done;
        try {
            (void)co_await capy::when_all(
                joined_upload(session,std::string(tail),decoder,response_done),
                joined_response(session,request.head,response_done));
        } catch (...) {
            session.close();
            session.done = true;
            throw;
        }
        session.close();
        session.done = true;
    }
}
