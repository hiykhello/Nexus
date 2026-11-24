export module dns.doh_exchange;
import std;
import dns.corosio_query;
import dns.input_budget;
import dns.response_match;
import http.connect;
import http.corosio_https;
import http.header;
import http2.client_channel;
import tls.byte_stream;
import tls.encrypted_extensions;
import capy;
import corosio;

export namespace dns::doh_detail {
    using Clock=std::chrono::steady_clock;
    using Error=dns::detail::UdpError;
    using Io=corosio::io_context;
    using Endpoint=corosio::endpoint;
    namespace capy = ::capy;
    constexpr std::string_view media_type="application/dns-message";
    constexpr std::size_t max_message=65535;

    [[nodiscard]] auto valid_path(std::string_view value) noexcept -> bool {
        if (!value.starts_with('/') || value.starts_with("//") || value.size()>2048) return false;
        constexpr std::string_view punctuation="-._~!$&'()*+,;=:@/?";
        auto hex=[](char c) {return (c>='0' && c<='9') || (c>='a' && c<='f') || (c>='A' && c<='F');};
        for (std::size_t i=0;i<value.size();++i) {
            auto c=value[i];
            if (c=='%') {
                if (value.size()-i<3 || !hex(value[i+1]) || !hex(value[i+2])) return false;
                i+=2;
            } else if (!(c>='0' && c<='9') && !(c>='a' && c<='z') && !(c>='A' && c<='Z') && !punctuation.contains(c))
                return false;
        }
        return true;
    }


    namespace detail {
        auto ascii_equal(std::string_view actual,std::string_view expected) noexcept -> bool {
            return std::ranges::equal(actual,expected,[](char a,char b) {
                return (a>='A' && a<='Z' ? a-'A'+'a' : a)==b;
            });
        }
        struct Body {
            InputBudget& budget;
            Bytes bytes;
            std::optional<InputBudget::Lease> lease;
            std::optional<std::size_t> length;
            std::optional<std::uint32_t> age;
            Error error=Error::protocol;
            bool content_type=false,encoding=false;

            explicit Body(InputBudget& owner):budget(owner) {}

            auto field(std::string_view name,std::string_view value) noexcept -> bool {
                value=http::trim_header_ows(value);
                if (ascii_equal(name,"content-type"))
                    return !std::exchange(content_type,true) && ascii_equal(value,media_type);
                if (ascii_equal(name,"content-encoding"))
                    return !std::exchange(encoding,true) && ascii_equal(value,"identity");
                if (ascii_equal(name,"content-length")) {
                    std::size_t size=0;
                    auto [end,ec]=std::from_chars(value.data(),value.data()+value.size(),size);
                    if (length || ec!=std::errc{} || end!=value.data()+value.size() || size<12 || size>max_message)
                        return false;
                    length=size;
                }
                if (ascii_equal(name,"age")) {
                    std::uint32_t seconds=0;
                    auto [end,ec]=std::from_chars(value.data(),value.data()+value.size(),seconds);
                    if (age || end!=value.data()+value.size() ||
                        (ec!=std::errc{} && ec!=std::errc::result_out_of_range)) return false;
                    age=ec==std::errc::result_out_of_range ? std::numeric_limits<std::uint32_t>::max() : seconds;
                }
                return true;
            }
            auto begin(unsigned status) -> bool {
                if (status<200 || status>=300 || !content_type) return false;
                auto limit=length.value_or(max_message);
                lease=budget.acquire(limit);
                if (!lease) {error=Error::budget_exhausted;return false;}
                bytes.reserve(limit);
                return true;
            }
            auto append(std::span<std::uint8_t const> chunk) -> bool {
                if (!lease || chunk.size()>length.value_or(max_message)-bytes.size()) return false;
                bytes.insert(bytes.end(),chunk.begin(),chunk.end());
                return true;
            }
            auto complete() const noexcept -> bool {
                return lease && bytes.size()>=12 && (!length || *length==bytes.size());
            }

            auto operator()(http::ResponseStep const& response) -> bool {
                if (response.informational) return true;
                if (response.event!=http::ResponseEvent::header)
                    return append({reinterpret_cast<std::uint8_t const*>(response.wire.data()),response.wire.size()});
                auto header=http::inspect_header(response.wire);
                if (header.status!=http::HeaderStatus::complete) return false;
                http::HeaderFieldCursor cursor(header.field_lines);
                for (;;) {
                    auto step=cursor.next();
                    if (step.status==http::HeaderFieldStatus::end) return begin(response.status_code);
                    if (step.status==http::HeaderFieldStatus::malformed || !field(step.field.name,step.field.value))
                        return false;
                }
            }
        };

        auto finish(Body body,QueryMessage const& query,std::uint16_t id) -> std::expected<Response,Error> {
            auto response=parse_owned_response(std::move(body.bytes),0,query.question);
            if (!response)
                return std::unexpected(response.error()==MessageError::truncated ? Error::truncated : Error::protocol);
            if (!age_response(*response,body.age.value_or(0),id)) return std::unexpected(Error::protocol);
            return std::move(*response);
        }

        auto h2_fields(std::string_view authority,std::string_view path,std::string_view length)
            -> std::array<http2::FieldView,8> {
            return {{{":method","POST"},{":scheme","https"},{":authority",authority},{":path",path},
                {"content-type",media_type},{"accept",media_type},{"content-length",length},{"accept-encoding","identity"}}};
        }

        template<class Channel>
        auto receive_h2(Channel& channel,http2::StreamTicket ticket,Clock::time_point deadline,Body& body,std::stop_token stop)
            -> capy::task<bool> {
            bool accepted=false;
            while (!stop.stop_requested() && Clock::now()<deadline) {
                auto response=channel.response(ticket);
                if (!response || response->failure) break;
                if (!accepted && response->status) {
                    if (!std::ranges::all_of(response->headers,[&](auto const& field) {
                        return body.field(field.name,field.value);
                    }) || !body.begin(response->status)) break;
                    accepted=true;
                }
                auto bytes=channel.peek(ticket);
                if (!bytes) break;
                if (!bytes->empty()) {
                    if (!body.append(*bytes) || !channel.consume(ticket,bytes->size())) break;
                    continue;
                }
                if (response->closed) co_return accepted && response->remote_end && body.complete();
                if (!co_await channel.wait_change(deadline)) break;
            }
            co_return false;
        }

        template<class Channel>
        auto collect_h2(Channel& channel,std::string_view authority,std::string_view path,std::span<std::uint8_t const> request,
            Clock::time_point deadline,Body& body,bool& success) -> capy::task<capy::results<>> {
            struct Guard {
                Channel& channel;
                ~Guard() {channel.cancel();}
            } guard{channel};
            auto length=std::to_string(request.size());
            auto ticket=channel.submit(h2_fields(authority,path,length),{request});
            if (!ticket) co_return capy::results<>{};
            if (co_await receive_h2(channel,*ticket,deadline,body,{}))
                success=channel.release(*ticket).value_or(false);
            co_return capy::results<>{};
        }

    }

    // Connection setup belongs to the caller. The request, response budget,
    // HTTP framing and DNS validation are shared by both physical and layered TLS.
    [[nodiscard]] auto make_query_wire(QueryMessage const& query) -> std::expected<Bytes,Error> {
        auto encoded=encode_query(query);
        if (!encoded || encoded->size()>max_message) return std::unexpected(Error::invalid_query);
        (*encoded)[0]=(*encoded)[1]=0;
        return std::move(*encoded);
    }

    template<class Connector>
    auto exchange(Connector& connector,std::string_view authority,std::string_view path,std::uint16_t port,
        QueryMessage const& query,std::uint16_t id,std::span<std::uint8_t const> encoded,Clock::time_point deadline,InputBudget& budget,std::stop_token stop)
        -> capy::task<std::expected<Response,Error>> {
        auto fail=[&](Error error) {
            return stop.stop_requested() ? Error::canceled : Clock::now()>=deadline ? Error::timeout : error;
        };
        if (stop.stop_requested() || Clock::now()>=deadline) co_return std::unexpected(fail(Error::transport));
        auto* negotiated=connector.negotiated();
        std::string host(authority);
        if (port!=443) host+=':'+std::to_string(port);
        detail::Body body(budget);
        bool success=false;
        constexpr std::array<std::uint8_t,2> h2{'h','2'};
        if (negotiated && negotiated->alpn && std::ranges::equal(*negotiated->alpn,h2)) {
            auto client=http2::Client<1>::create();
            if (!client) co_return std::unexpected(Error::budget_exhausted);
            tls::detail::ByteStream<typename Connector::Socket> lower(*connector.application());
            http2::ClientChannel<decltype(lower),1> channel(lower,std::move(*client),deadline);
            (void)co_await capy::when_all(
                channel.run(),detail::collect_h2(channel,host,path,encoded,deadline,body,success));
        } else {
            auto request=std::format("POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: {}\r\n"
                "Accept: {}\r\nAccept-Encoding: identity\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                path,host,media_type,media_type,encoded.size());
            request.append(reinterpret_cast<char const*>(encoded.data()),encoded.size());
            auto exchange=co_await http::detail::https_exchange(connector,request,false,body,deadline,true,
                http::ChunkOutput::payload);
            success=exchange.has_value() && body.complete();
        }
        if (!success || stop.stop_requested() || Clock::now()>=deadline)
            co_return std::unexpected(fail(body.error));
        co_return detail::finish(std::move(body),query,id);
    }
}
