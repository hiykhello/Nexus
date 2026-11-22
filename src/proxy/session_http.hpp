// HTTP/1.1 admission and tunnel setup inside the session implementation.
#pragma once
#include "../encoding/base64_decode.hpp"

        auto http_response(Session& session, std::string_view text) -> capy::task<bool> {
            auto bytes = std::span(reinterpret_cast<std::uint8_t const*>(text.data()), text.size());
            co_return co_await write_all(session.client, bytes, session);
        }

        auto validate_basic(std::string_view value,Credentials const& credentials) noexcept -> bool {
            auto equal_ci=[](char a,char b) {return a==b || (a>='A' && a<='Z' && a-'A'+'a'==b);};
            if (value.size()<6 || !std::ranges::equal(value.substr(0,5),std::string_view("basic"),equal_ci) ||
                value[5]!=' ') return false;
            value=http::trim_header_ows(value.substr(6));
            constexpr std::size_t maximum=255+1+255;
            if (value.empty() || value.size()%4 || value.size()>((maximum+2)/3)*4) return false;
            auto padding=value.ends_with("==") ? 2u : value.ends_with('=') ? 1u : 0u;
            auto length=value.size()/4*3-padding;
            if (length>maximum) return false;
            struct Secret {
                std::array<std::uint8_t,maximum> data;
                ~Secret() {::explicit_bzero(data.data(),data.size());}
            } decoded;
            auto bytes=std::span(decoded.data).first(length);
            if (!decode_base64_exact(std::span(value.data(),value.size()),bytes)) return false;
            auto separator=std::ranges::find(bytes,':');
            if (separator==bytes.end()) return false;
            auto username=bytes.first(static_cast<std::size_t>(separator-bytes.begin()));
            auto password=bytes.subspan(username.size()+1);
            unsigned difference=static_cast<unsigned>((username.size()^credentials.username_size) |
                (password.size()^credentials.password_size));
            for (std::size_t i=0;i<credentials.username.size();++i) {
                difference|=(i<username.size() ? username[i] : 0)^credentials.username[i];
                difference|=(i<password.size() ? password[i] : 0)^credentials.password[i];
            }
            return difference==0;
        }

        // Strip the verified field before either the CONNECT or forwarding parser
        // can retain or relay request bytes.
        auto consume_http_auth(std::span<std::uint8_t> buffer,std::size_t& size,
                               Credentials const& credentials) noexcept -> bool {
            auto input=std::string_view(reinterpret_cast<char const*>(buffer.data()),size);
            http::HeaderFieldCursor fields(http::inspect_header(input).field_lines);
            auto equal_ci=[](char a,char b) {return a==b || (a>='A' && a<='Z' && a-'A'+'a'==b);};
            std::optional<std::size_t> offset;
            for (;;) {
                auto field=fields.next();
                if (field.status==http::HeaderFieldStatus::end) break;
                if (field.status==http::HeaderFieldStatus::malformed) return false;
                if (!std::ranges::equal(field.field.name,std::string_view("proxy-authorization"),equal_ci)) continue;
                if (offset || !validate_basic(field.field.value,credentials)) return false;
                offset=static_cast<std::size_t>(field.field.name.data()-input.data());
            }
            if (!offset) return false;
            auto end=input.find("\r\n",*offset)+2;
            ::memmove(buffer.data()+*offset,buffer.data()+end,size-end);
            auto removed=end-*offset;
            size-=removed;
            ::explicit_bzero(buffer.data()+size,removed);
            return true;
        }

        auto http_handshake(Session& session, io::io_context& context,
                            rules::RouteMatcher const& policy, std::uint8_t first,
                            std::optional<Credentials> const& credentials) -> capy::task<> {
            auto fail = [&] { session.close(); session.done = true; };
            std::array<std::uint8_t, http::max_connect_header_bytes> buffer{};
            buffer[0] = first;
            std::size_t size = 1;
            http::HeaderBoundary boundary;
            auto status=http::HeaderBoundaryStatus::incomplete;
            for (;;) {
                auto text = std::string_view(reinterpret_cast<char const*>(buffer.data()), size);
                status=boundary.inspect(text);
                if (status!=http::HeaderBoundaryStatus::incomplete) break;
                auto [error, n] = co_await session.client.read_some(capy::mutable_buffer(buffer.data() + size, buffer.size() - size));
                if (error || n == 0) { fail(); co_return; }
                session.touched = Clock::now();
                size += n;
            }
            if (credentials && status==http::HeaderBoundaryStatus::complete) {
                if (!consume_http_auth(buffer,size,*credentials)) {
                    ::explicit_bzero(buffer.data(),size);
                    (void)co_await http_response(session,"HTTP/1.1 407 Proxy Authentication Required\r\n"
                        "Proxy-Authenticate: Basic realm=\"Nexus\"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
                    fail(); co_return;
                }
                auto user=std::string_view(reinterpret_cast<char const*>(credentials->username.data()),credentials->username_size);
                if (!session.admit_principal(user)) {
                    (void)co_await http_response(session,"HTTP/1.1 429 Too Many Requests\r\n"
                        "Connection: close\r\nContent-Length: 0\r\n\r\n");
                    fail(); co_return;
                }
            }
            auto parsed=http::parse_connect(std::string_view(reinterpret_cast<char const*>(buffer.data()),size));
            if (parsed.status == http::ConnectStatus::unsupported) {
                auto text = std::string_view(reinterpret_cast<char const*>(buffer.data()), size);
                if (!text.starts_with("CONNECT ")) {
                    co_await forward_http(session, context, policy, text);
                    co_return;
                }
            }
            if (parsed.status != http::ConnectStatus::accepted) {
                auto response = parsed.status == http::ConnectStatus::too_large ?
                    "HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n" :
                    parsed.status == http::ConnectStatus::unsupported ?
                    "HTTP/1.1 501 Not Implemented\r\nConnection: close\r\nContent-Length: 0\r\n\r\n" :
                    "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
                (void)co_await http_response(session, response);
                fail(); co_return;
            }
            socks5::Request request;
            request.status = socks5::Status::accepted;
            request.port = parsed.port;
            if (parsed.kind == http::HostKind::domain) {
                request.address_type = 3;
                request.address_length = static_cast<std::uint8_t>(parsed.host.size());
                std::copy(parsed.host.begin(), parsed.host.end(), request.address.begin());
            } else {
                request.address_type = parsed.kind == http::HostKind::ipv4 ? 1 : 4;
                request.address_length = parsed.kind == http::HostKind::ipv4 ? 4 : 16;
                std::copy(parsed.address.begin(), parsed.address.end(), request.address.begin());
            }
            session.begin_traffic(TrafficProtocol::http_connect,request.port);
            if(session.ordered_tcp) {
                auto tail=std::span(buffer).subspan(parsed.consumed,size-parsed.consumed);
                co_await ordered_connect(session,context,request,tail,ConnectReply::http);co_return;
            }
            auto tail=std::span(buffer).subspan(parsed.consumed, size - parsed.consumed);
            bool first_sent=false;
            auto code = co_await dial(session, context, policy, request,Clock::time_point::max(),tail,&first_sent);
            if (code != 0) {
                auto response = code == 2 ? "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n" :
                                            "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
                (void)co_await http_response(session, response);
                fail(); co_return;
            }
            if (!co_await http_response(session, "HTTP/1.1 200 Connection Established\r\n\r\n")) {
                fail(); co_return;
            }
            if (!first_sent && session.meters_principal_bytes()) {
                if (!co_await write_principal_payload(session,true,tail)) {fail();co_return;}
            } else if (!first_sent) {
                auto sent=session.tunnel ? co_await session.tunnel->send(tail) : co_await write_all(session.target,tail,session,true);
                if (!sent) {fail();co_return;}
                if (session.tunnel && !tail.empty()) session.count_traffic(true,tail.size());
            }
            session.relaying = true;
            co_await relay_pair(session);
        }
