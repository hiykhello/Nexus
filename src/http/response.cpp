module http.connect;
import std;

namespace http {
    auto ResponseDecoder::feed(std::string_view input) -> ResponseStep {
        constexpr std::size_t max_step = 16384;
        input=input.substr(0,max_step);
        if (state_==State::complete) return {ResponseEvent::complete};
        if (state_==State::failed) return {ResponseEvent::malformed};
        if (state_==State::header) {
            std::size_t consumed=0;
            while (consumed<input.size()) {
                header_.push_back(input[consumed++]);
                if (header_.ends_with("\r\n\r\n")) {
                    auto parsed=parse_forward_response(header_,head_);
                    if (parsed.status!=ConnectStatus::accepted || (parsed.informational && informational_==8)) {
                        state_=State::failed; return {ResponseEvent::malformed,consumed};
                    }
                    auto interim=parsed.informational;
                    if (interim) ++informational_;
                    else {
                        auto mode=parsed.chunked ? BodyMode::chunked :
                            parsed.body_length ? BodyMode::fixed : BodyMode::close_delimited;
                        persistent_=parsed.persistent;
                        body_=BodyDecoder(mode,parsed.body_length.value_or(0),chunk_output_);
                        state_=body_.complete() ? State::complete : State::body;
                    }
                    header_.clear();
                    if (state_==State::body && body_.mode()==BodyMode::close_delimited && frame_close_) {
                        // The request parser accepts only HTTP/1.1 clients. Upgrade an
                        // HTTP/1.0 origin status line when applying chunked framing.
                        parsed.wire.replace(0,8,"HTTP/1.1");
                        parsed.wire.insert(parsed.wire.size()-2,"Transfer-Encoding: chunked\r\n");
                    }
                    return {ResponseEvent::header,consumed,std::move(parsed.wire),interim,
                        parsed.status_code,parsed.body_length,parsed.identity_encoding};
                }
                if (header_.size()>=max_connect_header_bytes) { state_=State::failed; return {ResponseEvent::malformed,consumed}; }
            }
            return {ResponseEvent::need_more,consumed};
        }
        auto mode=body_.mode();
        std::string output;
        auto body=body_.feed(input,output);
        if (body.event==BodyEvent::malformed || body.event==BodyEvent::truncated) {
            state_=State::failed;
            return {body.event==BodyEvent::malformed ? ResponseEvent::malformed : ResponseEvent::truncated,body.consumed};
        }
        auto event=body.event==BodyEvent::complete ? ResponseEvent::complete :
            body.event==BodyEvent::data ? ResponseEvent::data : ResponseEvent::need_more;
        if (event==ResponseEvent::complete) state_=State::complete;
        if (mode==BodyMode::chunked) return {event,body.consumed,std::move(output)};
        if (mode!=BodyMode::close_delimited || !frame_close_ || event!=ResponseEvent::data) {
            output.assign(body.wire);
            return {event,body.consumed,std::move(output)};
        }
        std::array<char,32> size{};
        auto [end,error]=std::to_chars(size.data(),size.data()+size.size(),body.wire.size(),16);
        if (error!=std::errc{}) { state_=State::failed; return {ResponseEvent::malformed}; }
        output.assign(size.data(),end);
        output+="\r\n"; output.append(body.wire); output+="\r\n";
        return {ResponseEvent::data,body.consumed,std::move(output)};
    }
    auto ResponseDecoder::finish() -> ResponseStep {
        if (state_==State::complete) return {ResponseEvent::complete};
        if (state_==State::failed) return {ResponseEvent::malformed};
        if (state_==State::body && body_.finish().event==BodyEvent::complete) {
            state_=State::complete;
            return {ResponseEvent::complete,0,body_.mode()==BodyMode::close_delimited && frame_close_ ? "0\r\n\r\n" : ""};
        }
        state_=State::failed; return {ResponseEvent::truncated};
    }
}
