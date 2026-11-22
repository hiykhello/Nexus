// Included inside the stream datagram runtime namespace.
#pragma once
    // The upload task may append to pending, while this serialized process
    // task inspects it. It never removes entries during this wait. The fixed
    // lookahead bound preserves the queue's existing byte/count budgets.
    template<class State>
    auto inspect_quic(State& state,typename State::Packet& packet,Clock::time_point deadline)
        -> capy::task<sniff::QuicProbeResult> {
        using namespace std::chrono_literals;
        if(state.session.closed || state.canceled || Clock::now()>=packet.deadline) {
            packet.quic=sniff::QuicProbeResult{};co_return *packet.quic;
        }
        if(packet.quic)co_return *packet.quic;
        auto& classification=packet.quic.emplace();
        deadline=std::min(deadline,packet.deadline);
        auto probe=sniff::make_quic_probe();if(!probe)co_return classification;
        auto result=probe->feed(packet.payload);
        if(result.status==sniff::QuicProbeStatus::matched) {
            if(Clock::now()<deadline)classification=std::move(result);
            co_return classification;
        }
        if(result.status!=sniff::QuicProbeStatus::waiting)co_return classification;
        std::array<std::size_t,8> members{};std::size_t count=0,index=0;
        while(!state.session.closed && !state.canceled && Clock::now()<deadline && index<8) {
            if(std::ranges::any_of(std::span(members).first(count),[&](auto member) {
                return Clock::now()>=state.pending[member].deadline;
            }))break;
            if(index>=state.pending.size()) {
                auto [error]=co_await io::delay(1ms);if(error)state.session.close();continue;
            }
            auto& next=state.pending[index];
            if(Clock::now()<next.deadline && next.destination==packet.destination) {
                auto observed=probe->feed(next.payload);
                if(observed.status==sniff::QuicProbeStatus::waiting || observed.status==sniff::QuicProbeStatus::matched ||
                    observed.status==sniff::QuicProbeStatus::unknown)members[count++]=index;
                if(observed.status==sniff::QuicProbeStatus::matched) {classification=std::move(observed);break;}
                if(observed.status==sniff::QuicProbeStatus::unknown)break;
            }
            ++index;
        }
        if(state.session.closed || state.canceled || Clock::now()>=deadline ||
            std::ranges::any_of(std::span(members).first(count),[&](auto member) {
                return Clock::now()>=state.pending[member].deadline;
            }))classification={};
        for(std::size_t i=0;i<count;++i) {
            state.pending[members[i]].quic=classification;
        }
        co_return classification;
    }
