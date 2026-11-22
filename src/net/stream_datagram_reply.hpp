// Included inside the stream datagram runtime namespace.
#pragma once
    template<class State>
    auto count_download(State& state,std::size_t payload_size) -> void {
        // Some transports return success for a deliberate drop and report
        // delivery at their own write-completion boundary.
        if constexpr (!requires {state.incoming.accounts_download;})
            state.session.count_traffic(false,payload_size);
    }
    template<class State>
    auto send_reply(State& state,ProxyAddress const& address,std::span<std::uint8_t const> payload,
        Clock::time_point deadline=Clock::now()+std::chrono::seconds(300)) -> capy::task<bool> {
        using namespace std::chrono_literals;
        // A transport with asynchronous datagram completion reserves and
        // settles its own replies, including deliberate transport drops.
        if constexpr (requires {state.incoming.accounts_download;}) {
            if (!co_await state.incoming.send_packet(address,payload)) co_return false;
            state.session.touched=Clock::now();
            co_return true;
        }
        auto credit=reserve_datagram_bytes(state.session,false,payload.size());
        if (!credit) {
            auto [error]=co_await io::delay(1ms);
            co_return !error && !state.session.closed;
        }
        if constexpr (requires {state.incoming.send_packet(address,payload);}) {
            credit->submit();
            if (!co_await state.incoming.send_packet(address,payload)) co_return false;
        } else {
            auto wire=encode_datagram(state.framing,address,payload);
            if (!wire) co_return false;
            credit->submit();
            if (!co_await state.incoming.send(*wire,deadline)) co_return false;
        }
        credit->complete(payload.size());
        count_download(state,payload.size());
        state.session.touched=Clock::now();
        co_return true;
    }
