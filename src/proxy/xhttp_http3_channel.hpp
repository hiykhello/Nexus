#pragma once

namespace proxy::vless_xhttp {
    template<class Bundle,class Driver>
    class Http3Channel {
        Bundle& bundle_;
        Driver& driver_;

    public:
        Http3Channel(Bundle& bundle,Driver& driver) noexcept :bundle_(bundle),driver_(driver) {}
        auto wait(Deadline deadline={}) -> nex::capy::task<bool> {
            if (bundle_.hooks.dead) co_return false;
            auto& event=driver_.changed();
            event.clear();
            auto [error]=deadline ? co_await nex::corosio::timeout(event.wait(),*deadline) : co_await event.wait();
            co_return !error && !bundle_.hooks.dead;
        }
        auto state(std::int64_t id) noexcept {return bundle_.hooks.find(id);}
        auto respond(std::int64_t id,std::span<h3::nghttp3_nv const> fields,bool body) -> bool {
            auto* stream=state(id);
            if (!stream || stream->failed || stream->closed ||
                bundle_.app.h3().response(id,fields,body)) return false;
            stream->fin_requested=!body;
            driver_.notify();
            return true;
        }
        auto body(std::int64_t id,std::span<std::uint8_t const> bytes,bool fin) -> bool {
            auto* stream=state(id);
            if (!stream || stream->failed || stream->closed || stream->fin_requested || !stream->output.empty()) return false;
            stream->output.assign(bytes.begin(),bytes.end());
            stream->fin_requested=fin;
            if (bundle_.app.h3().resume(id)) {
                release(id);
                return false;
            }
            driver_.notify();
            return true;
        }
        auto read(std::int64_t id,std::span<std::uint8_t> output,Deadline until) -> nex::capy::task<std::expected<std::size_t,IoError>> {
            if (output.empty()) co_return 0;
            for (;;) {
                auto* stream=state(id);
                if (!stream || stream->failed || stream->retired || bundle_.hooks.dead) co_return std::unexpected(IoError::io);
                auto data=stream->input.peek();
                if (!data.empty()) {
                    auto size=std::min(output.size(),data.size());
                    if (stream->closed) bundle_.app.discard_body(size);
                    else if (!bundle_.app.consume_body(id,size)) co_return std::unexpected(IoError::io);
                    std::ranges::copy(data.first(size),output.begin());
                    stream->input.consume(size);
                    driver_.notify();
                    co_return size;
                }
                if (stream->remote_end) co_return 0;
                if (!co_await wait(until))
                    co_return std::unexpected(until && Clock::now()>=*until ? IoError::timeout : IoError::io);
            }
        }
        auto wait_sent(std::int64_t id,bool fin,Deadline until) -> nex::capy::task<bool> {
            for (;;) {
                auto* stream=state(id);
                if (!stream || stream->failed || stream->retired || bundle_.hooks.dead) co_return false;
                if (fin ? stream->fin_written : stream->output.empty()) co_return true;
                if (!co_await wait(until)) co_return false;
            }
        }
        auto release(std::int64_t id) noexcept -> void {
            auto* stream=state(id);
            if (!stream || stream->retired) return;
            bundle_.app.discard_body(stream->input.size());
            stream->input.discard();
            if (stream->closed) bundle_.hooks.streams.erase(id);
            else {
                stream->retired=true;
                if (!stream->remote_end || !stream->fin_written) {
                    bundle_.hooks.fail(*stream);
                    if (!bundle_.app.stopping() && bundle_.app.flush_pending()) bundle_.app.request_stop();
                }
            }
            driver_.notify();
        }
    };
}
