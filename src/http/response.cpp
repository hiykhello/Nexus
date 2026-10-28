module nexus.http.connect;
import std;

namespace nexus::http {
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
                    else if (parsed.chunked) state_=State::chunked;
                    else if (!parsed.body_length) state_=State::close;
                    else if (*parsed.body_length==0) state_=State::complete;
                    else { state_=State::fixed; remaining_=*parsed.body_length; }
                    header_.clear();
                    if (state_==State::close && frame_close_) {
                        // The request parser accepts only HTTP/1.1 clients. Upgrade an
                        // HTTP/1.0 origin status line when applying chunked framing.
                        parsed.wire.replace(0,8,"HTTP/1.1");
                        parsed.wire.insert(parsed.wire.size()-2,"Transfer-Encoding: chunked\r\n");
                    }
                    return {ResponseEvent::header,consumed,std::move(parsed.wire),interim};
                }
                if (header_.size()>=max_connect_header_bytes) { state_=State::failed; return {ResponseEvent::malformed,consumed}; }
            }
            return {ResponseEvent::need_more,consumed};
        }
        if (state_==State::chunked) {
            std::string output; auto chunk=chunk_.consume_some(input,output);
            if (chunk.status==ChunkStatus::malformed) { state_=State::failed; return {ResponseEvent::malformed,chunk.consumed}; }
            if (chunk.status==ChunkStatus::complete) { state_=State::complete; return {ResponseEvent::complete,chunk.consumed,std::move(output)}; }
            return {output.empty() ? ResponseEvent::need_more : ResponseEvent::data,chunk.consumed,std::move(output)};
        }
        if (state_==State::fixed) {
            auto n=static_cast<std::size_t>(std::min<std::uint64_t>(remaining_,input.size()));
            remaining_-=n;
            if (!remaining_) state_=State::complete;
            return {state_==State::complete ? ResponseEvent::complete : n ? ResponseEvent::data : ResponseEvent::need_more,n,std::string(input.substr(0,n))};
        }
        if (input.empty()) return {ResponseEvent::need_more};
        if (!frame_close_) return {ResponseEvent::data,input.size(),std::string(input)};
        std::array<char,32> size{};
        auto [end,error]=std::to_chars(size.data(),size.data()+size.size(),input.size(),16);
        if (error!=std::errc{}) { state_=State::failed; return {ResponseEvent::malformed}; }
        std::string wire(size.data(),end);
        wire+="\r\n"; wire.append(input); wire+="\r\n";
        return {ResponseEvent::data,input.size(),std::move(wire)};
    }
    auto ResponseDecoder::finish() -> ResponseStep {
        if (state_==State::complete) return {ResponseEvent::complete};
        if (state_==State::close) { state_=State::complete; return {ResponseEvent::complete,0,frame_close_ ? "0\r\n\r\n" : ""}; }
        if (state_==State::failed) return {ResponseEvent::malformed};
        state_=State::failed; return {ResponseEvent::truncated};
    }
}
