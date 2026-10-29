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
#include <boost/corosio/resolver.hpp>

module nexus.proxy;
import proxy.v4;
import std;
import nexus.socks5;
import nexus.rules;
import nexus.http.connect;


namespace nexus::proxy {
    namespace {
        auto write(io::tcp_socket& socket, std::span<std::uint8_t const> data, Session& session) -> capy::task<bool> {
            while (!data.empty()) {
                auto [error, n] = co_await socket.write_some(capy::const_buffer(data.data(), data.size()));
                if (error || n == 0) co_return false;
                session.touched = Clock::now();
                data = data.subspan(n);
            }
            co_return true;
        }
        auto write_text(io::tcp_socket& socket, std::string_view text, Session& session) -> capy::task<bool> {
            co_return co_await write(socket, {reinterpret_cast<std::uint8_t const*>(text.data()), text.size()}, session);
        }
        auto write_target(Session& session, std::string_view text) -> capy::task<bool> {
            if (session.tunnel)
                co_return co_await session.tunnel->send({reinterpret_cast<std::uint8_t const*>(text.data()),text.size()});
            co_return co_await write_text(session.target,text,session);
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

        auto upload_body(Session& session, std::string initial, std::uint64_t remaining, bool chunked)
            -> capy::task<bool> {
            http::ChunkDecoder decoder;
            std::array<char, http::max_connect_header_bytes> buffer{};
            std::string_view data = initial;
            bool complete = !chunked && remaining == 0;
            while (!complete && !session.closed) {
                if (chunked) {
                    std::string output;
                    auto status = decoder.consume(data, output);
                    if (status == http::ChunkStatus::malformed) break;
                    if (!co_await write_target(session, output)) break;
                    if (status == http::ChunkStatus::complete) { complete = true; break; }
                } else {
                    auto count = static_cast<std::size_t>(std::min<std::uint64_t>(remaining, data.size()));
                    if (!co_await write_target(session, data.substr(0, count))) break;
                    remaining -= count;
                    if (remaining == 0) { complete = true; break; }
                }
                auto capacity = chunked ? buffer.size() : static_cast<std::size_t>(std::min<std::uint64_t>(remaining, buffer.size()));
                auto [error, n] = co_await session.client.read_some(capy::mutable_buffer(buffer.data(), capacity));
                if (error || n == 0 || session.http_draining) break;
                session.touched = Clock::now();
                data = std::string_view(buffer.data(), n);
            }
            co_return complete;
        }

        auto upload(Session& session, std::string initial, std::uint64_t remaining, bool chunked,
                    capy::async_event& response_done) -> capy::task<> {
            auto complete = co_await upload_body(session, std::move(initial), remaining, chunked);
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
                if (!step.wire.empty() && !co_await write_text(session.client,step.wire,session)) { finish(session); co_return; }
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
                    if (!end.wire.empty() && !co_await write_text(session.client,end.wire,session)) { finish(session); co_return; }
                    if (end.event!=http::ResponseEvent::complete && !final_header) {
                        if (co_await write_text(session.client,"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",session)) finish_response(session,&response_done);
                        else finish(session);
                    } else finish_response(session,&response_done);
                    co_return;
                }
                session.touched=Clock::now(); size=n; offset=0;
            }
        }

        auto joined_upload(Session& session, std::string initial, std::uint64_t remaining, bool chunked,
                           capy::async_event& response_done) -> capy::task<capy::results<>> {
            try { co_await upload(session, std::move(initial), remaining, chunked, response_done); }
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

    auto forward_http(std::shared_ptr<Session> const& session, io::io_context& context,
                      rules::RouteMatcher const& policy, std::string_view input) -> capy::task<> {
        auto request = http::parse_forward_request(input);
        if (request.status != http::ConnectStatus::accepted) {
            auto response = request.status == http::ConnectStatus::expectation_failed ?
                "HTTP/1.1 417 Expectation Failed\r\nConnection: close\r\nContent-Length: 0\r\n\r\n" :
                request.status == http::ConnectStatus::unsupported ?
                "HTTP/1.1 501 Not Implemented\r\nConnection: close\r\nContent-Length: 0\r\n\r\n" :
                "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
            if (co_await write_text(session->client, response, *session)) {
                finish_response(*session);
                co_await drain(*session);
            } else finish(*session);
            session->done = true;
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
        auto code = co_await dial(session, context, policy, destination);
        if (code != 0) {
            auto response = code == 2 ? "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n" :
                                        "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
            if (co_await write_text(session->client, response, *session)) {
                finish_response(*session);
                co_await drain(*session);
            } else finish(*session);
            session->done = true;
            co_return;
        }
        session->relaying = true;
        if (!co_await write_target(*session, request.wire)) { finish(*session); session->done = true; co_return; }
        auto tail = input.substr(request.consumed);
        if (!request.chunked) tail = tail.substr(0, static_cast<std::size_t>(std::min<std::uint64_t>(request.body_length, tail.size())));
        capy::async_event response_done;
        try {
            (void)co_await capy::when_all(
                joined_upload(*session,std::string(tail),request.body_length,request.chunked,response_done),
                joined_response(*session,request.head,response_done));
        } catch (...) {
            session->close();
            session->done = true;
            throw;
        }
        session->close();
        session->done = true;
    }
}
