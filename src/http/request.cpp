module http.connect;
import std;

namespace http {
    auto RequestDecoder::feed(std::string_view input,std::string& chunk_output) -> RequestStep {
        chunk_output.clear();
        if (state_==State::complete) return {RequestEvent::complete};
        if (state_==State::failed) return {RequestEvent::malformed};
        if (state_==State::header) {
            if (boundary_.inspect(input)==HeaderBoundaryStatus::incomplete) return {RequestEvent::need_more};
            auto request=parse_forward_request(input);
            if (request.status==ConnectStatus::incomplete) return {RequestEvent::need_more};
            request_=std::move(request);
            if (request_.status!=ConnectStatus::accepted) {
                state_=State::failed;
                return {RequestEvent::malformed};
            }
            body_=BodyDecoder(request_.chunked ? BodyMode::chunked : BodyMode::fixed,request_.body_length);
            state_=body_.complete() ? State::complete : State::body;
            return {RequestEvent::header,request_.consumed,request_.wire};
        }
        auto result=body_.feed(input,chunk_output);
        switch (result.event) {
        case BodyEvent::need_more: return {RequestEvent::need_more,result.consumed,result.wire};
        case BodyEvent::data: return {RequestEvent::data,result.consumed,result.wire};
        case BodyEvent::complete:
            state_=State::complete;
            return {RequestEvent::complete,result.consumed,result.wire};
        case BodyEvent::malformed:
            state_=State::failed;
            return {RequestEvent::malformed,result.consumed};
        case BodyEvent::truncated:
            state_=State::failed;
            return {RequestEvent::truncated,result.consumed};
        }
        state_=State::failed;
        return {RequestEvent::malformed};
    }

    auto RequestDecoder::finish() -> RequestStep {
        if (state_==State::complete) return {RequestEvent::complete};
        if (state_==State::failed) return {RequestEvent::malformed};
        if (state_==State::body && body_.finish().event==BodyEvent::complete) {
            state_=State::complete;
            return {RequestEvent::complete};
        }
        state_=State::failed;
        return {RequestEvent::truncated};
    }
}
