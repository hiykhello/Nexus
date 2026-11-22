module;
#include <proxy/proxy_macros.h>
#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/ex/async_event.hpp>
#include <boost/capy/when_all.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/endpoint.hpp>

module proxy;
import proxy.v4;
import std;
import socks5;
import rules;
import http.connect;
import sniff.tcp;
import sniff.route_tcp;


namespace proxy {
    namespace {
        auto write(io::tcp_socket& socket, std::span<std::uint8_t const> data, Session& session,std::optional<bool> payload_direction) -> capy::task<bool> {
            if (payload_direction && session.meters_principal_bytes())
                co_return co_await write_principal_payload(session,*payload_direction,data);
            while (!data.empty()) {
                auto [error, n] = co_await socket.write_some(capy::const_buffer(data.data(), data.size()));
                if (payload_direction && n) session.count_traffic(*payload_direction,n);
                if (error || n == 0) co_return false;
                session.touched = Clock::now();
                data = data.subspan(n);
            }
            co_return true;
        }
        auto write_text(io::tcp_socket& socket, std::string_view text, Session& session,std::optional<bool> payload_direction={}) -> capy::task<bool> {
            co_return co_await write(socket, {reinterpret_cast<std::uint8_t const*>(text.data()),text.size()},session,payload_direction);
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
            std::array<char, http::max_connect_header_bytes> buffer{};
            std::string_view data = initial;
            bool complete = decoder.complete();
            while (!complete && !session.closed) {
                std::string output;
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
                auto [error, n] = co_await session.client.read_some(capy::mutable_buffer(buffer.data(), capacity));
                if (error || n == 0 || session.http_draining) break;
                session.touched = Clock::now();
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
            std::array<std::uint8_t, http::max_connect_header_bytes> buffer{};
            std::size_t size=0, offset=0;
            bool final_header=false;
            http::ResponseDecoder decoder(head,static_cast<bool>(session.tunnel));
            for (;;) {
                auto data=std::string_view(reinterpret_cast<char const*>(buffer.data()+offset),size-offset);
                auto step=decoder.feed(data);
                offset+=step.consumed;
                if (step.event==http::ResponseEvent::malformed || step.event==http::ResponseEvent::truncated) {
                    if (!final_header) {
                        if (co_await write_text(session.client,"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",session)) finish_response(session,&response_done);
                        else finish(session);
                    } else finish_response(session,&response_done);
                    co_return;
                }
                if (step.event==http::ResponseEvent::header && !step.informational) final_header=true;
                if (!step.wire.empty() && !co_await write_text(session.client,step.wire,session,false)) { finish(session); co_return; }
                if (step.event==http::ResponseEvent::complete) { finish_response(session,&response_done); co_return; }
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
                    auto result=co_await session.target.read_some(capy::mutable_buffer(buffer.data(),buffer.size()));
                    error=std::get<0>(result); n=std::get<1>(result);
                }
                if (error && session.tunnel) {
                    if (!final_header) {
                        if (co_await write_text(session.client,"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",session)) finish_response(session,&response_done);
                        else finish(session);
                    } else finish_response(session,&response_done);
                    co_return;
                }
                if (error || n==0) {
                    auto end=decoder.finish();
                    if (!end.wire.empty() && !co_await write_text(session.client,end.wire,session,false)) { finish(session); co_return; }
                    if (end.event!=http::ResponseEvent::complete && !final_header) {
                        if (co_await write_text(session.client,"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",session)) finish_response(session,&response_done);
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
                      rules::RouteMatcher const& policy, std::string_view input) -> capy::task<> {
        http::RequestDecoder decoder;
        std::string output;
        auto first=decoder.feed(input,output);
        auto const& request=decoder.request();
        if (first.event != http::RequestEvent::header) {
            auto response = request.status == http::ConnectStatus::expectation_failed ?
                "HTTP/1.1 417 Expectation Failed\r\nConnection: close\r\nContent-Length: 0\r\n\r\n" :
                request.status == http::ConnectStatus::unsupported ?
                "HTTP/1.1 501 Not Implemented\r\nConnection: close\r\nContent-Length: 0\r\n\r\n" :
                "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
            if (co_await write_text(session.client, response, session)) {
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
            auto response = code == 2 ? "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n" :
                                        "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
            if (co_await write_text(session.client, response, session)) {
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
