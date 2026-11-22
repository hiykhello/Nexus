#pragma once

namespace proxy::vless_xhttp {
    using Socket=nex::corosio::tcp_socket;
    using Deadline=net::StreamDeadline;
    using IoError=tls::detail::ByteStreamError;

    inline auto bytes(std::string_view text) noexcept -> std::span<std::uint8_t const> {
        return {reinterpret_cast<std::uint8_t const*>(text.data()),text.size()};
    }
    inline auto entropy() -> std::optional<std::uint64_t> {
        std::array<std::uint8_t,8> data;
        if (!crypto::random_bytes(data)) return {};
        return std::bit_cast<std::uint64_t>(data);
    }

    class Lower {
        net::SocketByteStream<Socket> raw_;
        std::optional<tls::detail::ByteStream<Socket>> secure_;
    public:
        inline explicit Lower(Socket& socket) noexcept :raw_(socket) {}
        inline auto attach(tls::detail::ApplicationConnection<Socket>& connection) -> void {secure_.emplace(connection);}
        inline auto cancel() noexcept -> void {if (secure_) secure_->cancel(); else raw_.cancel();}
        inline auto read(std::span<std::uint8_t> output,Deadline deadline={})
            -> nex::capy::task<std::expected<std::size_t,IoError>> {
            if (secure_) co_return co_await secure_->read(output,deadline);
            auto result=co_await raw_.read(output,deadline);
            if (!result) co_return std::unexpected(result.error()==std::errc::timed_out ? IoError::timeout : IoError::io);
            co_return *result;
        }
        inline auto send(std::span<std::uint8_t const> input,Deadline deadline={}) {
            return secure_ ? secure_->send(input,deadline) : raw_.send(input,deadline);
        }
        inline auto close_output(Deadline deadline={}) {
            return secure_ ? secure_->close_output(deadline) : raw_.close_output(deadline);
        }
    };

    struct RequestHead {
        std::string method,target,authority;
        std::vector<xhttp::Field> fields;
        std::size_t content_length=0;
        std::size_t consumed=0;
        bool close=false;
    };

    inline auto parse_request(http::HeaderView header) -> std::optional<RequestHead> {
        auto method_end=header.first.find(' ');
        auto version=header.first.rfind(' ');
        if (method_end==header.first.npos || method_end==version || header.first.substr(version+1)!="HTTP/1.1") return {};
        RequestHead request{std::string(header.first.substr(0,method_end)),
            std::string(header.first.substr(method_end+1,version-method_end-1)),{}, {},0,header.consumed};
        if (request.target.empty() || request.target.front()!='/' ||
            std::ranges::any_of(request.target,[](unsigned char c) {return c<=32 || c>=127 || c=='#';})) return {};
        bool length=false;
        http::HeaderFieldCursor cursor(header.field_lines);
        for (;;) {
            auto item=cursor.next();
            if (item.status==http::HeaderFieldStatus::end) break;
            if (item.status==http::HeaderFieldStatus::malformed) return {};
            auto [name,value]=item.field;
            std::string key(name);
            for (auto& c:key) if (c>='A' && c<='Z') c+='a'-'A';
            if (key=="transfer-encoding" || key=="expect" || key=="upgrade") return {};
            if (key=="host") {
                if (!request.authority.empty() || value.empty()) return {};
                request.authority=value;
            } else if (key=="content-length") {
                if (length || value.empty()) return {};
                auto [end,error]=std::from_chars(value.data(),value.data()+value.size(),request.content_length);
                if (error!=std::errc{} || end!=value.data()+value.size()) return {};
                length=true;
            } else if (key=="connection") {
                std::string connection(value);
                for (auto& c:connection) if (c>='A' && c<='Z') c+='a'-'A';
                for (auto token:connection | std::views::split(','))
                    if (http::trim_header_ows(std::string_view(token.begin(),token.end()))=="close") request.close=true;
            }
            request.fields.emplace_back(std::move(key),value);
        }
        if (request.authority.empty()) return {};
        return request;
    }

    inline auto request_head(xhttp::Request const& request,std::string_view authority,
                             std::optional<std::size_t> length,bool close) -> std::string {
        std::string wire(request.method);
        wire+=' ';wire+=request.target;wire+=" HTTP/1.1\r\nHost: ";wire+=authority;
        if (close) wire+="\r\nConnection: close";
        for (auto const& [name,value]:request.fields) {
            wire+="\r\n";wire+=name;wire+=": ";wire+=value;
        }
        if (length) {wire+="\r\nContent-Length: ";wire+=std::to_string(*length);}
        wire+="\r\n\r\n";
        return wire;
    }

    class Response {
        http::ResponseDecoder decoder_{false,false,http::ChunkOutput::payload};
        std::array<std::uint8_t,8192> input_;
        std::size_t begin_=0,end_=0,delivered_=0;
        std::string payload_;
        bool headers_=false,complete_=false;
    public:
        inline auto reusable() const noexcept -> bool {return complete_ && begin_==end_ && decoder_.reusable();}
        inline auto read(Lower& lower,std::span<std::uint8_t> output,Deadline deadline)
            -> nex::capy::task<std::expected<std::size_t,IoError>> {
            if (output.empty()) co_return 0;
            for (;;) {
                if (delivered_<payload_.size()) {
                    auto size=std::min(output.size(),payload_.size()-delivered_);
                    std::copy_n(payload_.begin()+delivered_,size,output.begin());
                    delivered_+=size;
                    co_return size;
                }
                if (complete_) co_return 0;
                if (begin_==end_) {
                    auto read=co_await lower.read(input_,deadline);
                    if (!read) co_return std::unexpected(read.error());
                    if (!*read) {
                        complete_=headers_ && decoder_.finish().event==http::ResponseEvent::complete;
                        if (!complete_) co_return std::unexpected(IoError::protocol);
                        co_return 0;
                    }
                    begin_=0;end_=*read;
                }
                auto step=decoder_.feed(std::string_view(reinterpret_cast<char const*>(input_.data()+begin_),end_-begin_));
                begin_+=step.consumed;
                switch (step.event) {
                case http::ResponseEvent::header:
                    if (step.informational) break;
                    if (step.status_code!=200 || !step.identity_encoding) co_return std::unexpected(IoError::protocol);
                    headers_=true;
                    if (step.content_length==0) complete_=true;
                    break;
                case http::ResponseEvent::data:
                case http::ResponseEvent::complete:
                    complete_=step.event==http::ResponseEvent::complete;
                    payload_=std::move(step.wire);
                    delivered_=0;
                    break;
                case http::ResponseEvent::need_more:
                    if (step.consumed) break;
                    [[fallthrough]];
                default:
                    co_return std::unexpected(IoError::protocol);
                }
            }
        }
    };
}
