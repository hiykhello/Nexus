export module wireguard.session;
import std;
import crypto;
import wireguard;
import wireguard.crypto;

export namespace wireguard {
    // Owns one authenticated generation. The endpoint owns current/previous
    // generations, timers and routing; decrypted bytes still include padding.
    // Only successful open permits endpoint roaming or key confirmation.
    class Session {
        SecretKey send_,receive_;
        SendCounter counter_;
        ReplayWindow replay_;
        std::uint32_t local_,remote_;
        Clock::time_point born_;
        bool initiator_,confirmed_,closed_=false;
        auto active(Clock::time_point now) noexcept -> bool {
            if (closed_) return false;
            if (now<born_ || now-born_>=reject_after_time) { close(); return false; }
            return true;
        }
    public:
        Session(SecretKey send,SecretKey receive,std::uint32_t local,std::uint32_t remote,bool initiator,Clock::time_point now) noexcept
            : send_(std::move(send)),receive_(std::move(receive)),local_(local),remote_(remote),born_(now),initiator_(initiator),confirmed_(initiator) {}
        ~Session() { close(); }
        Session(Session const&)=delete;
        auto operator=(Session const&) -> Session& = delete;
        Session(Session&& other) noexcept : send_(std::move(other.send_)),receive_(std::move(other.receive_)),counter_(other.counter_),
            replay_(other.replay_),local_(other.local_),remote_(other.remote_),born_(other.born_),initiator_(other.initiator_),
            confirmed_(other.confirmed_),closed_(other.closed_) { other.close(); }
        auto operator=(Session&& other) noexcept -> Session& {
            if (this!=&other) {
                close(); send_=std::move(other.send_); receive_=std::move(other.receive_); counter_=other.counter_; replay_=other.replay_;
                local_=other.local_; remote_=other.remote_; born_=other.born_; initiator_=other.initiator_;
                confirmed_=other.confirmed_; closed_=other.closed_; other.close();
            }
            return *this;
        }
        auto close(this Session& self) noexcept -> void { self.send_.clear(); self.receive_.clear(); self.closed_=true; }
        // The input is one complete inner packet, or empty for keepalive.
        // Padding is capped by the configured inner MTU, as in wireguard-go.
        auto seal(std::span<std::uint8_t const> plaintext,Clock::time_point now,std::size_t inner_mtu=max_datagram_size-transport_overhead)
            -> std::expected<std::vector<std::uint8_t>,Error> {
            if (!active(now)) return std::unexpected(Error::expired);
            if (!confirmed_) return std::unexpected(Error::not_confirmed);
            if (!inner_mtu || inner_mtu>max_datagram_size-transport_overhead || plaintext.size()>inner_mtu) return std::unexpected(Error::invalid_length);
            auto counter=counter_.take(); if (!counter) return std::unexpected(counter.error());
            auto padded=std::min((plaintext.size()+15)&~std::size_t{15},inner_mtu);
            std::vector<std::uint8_t> input(padded);
            detail::Erase erase{input}; std::ranges::copy(plaintext,input.begin());
            auto ciphertext=crypto::seal(crypto::Aead::chacha20_poly1305,send_.view(),transport_nonce(*counter),input,{});
            if (!ciphertext) return std::unexpected(Error::backend);
            auto header=transport_header(remote_,*counter);
            std::vector<std::uint8_t> result;
            result.reserve(header.size()+ciphertext->size()); result.insert(result.end(),header.begin(),header.end());
            result.insert(result.end(),ciphertext->begin(),ciphertext->end()); return result;
        }
        auto open(std::span<std::uint8_t const> wire,Clock::time_point now) -> std::expected<std::vector<std::uint8_t>,Error> {
            if (!active(now)) return std::unexpected(Error::expired);
            auto transport=parse_transport(wire); if (!transport) return std::unexpected(transport.error());
            if (transport->receiver!=local_) return std::unexpected(Error::invalid_state);
            auto acceptable=replay_.check(transport->counter); if (!acceptable) return std::unexpected(acceptable.error());
            auto plaintext=crypto::open(crypto::Aead::chacha20_poly1305,receive_.view(),transport_nonce(transport->counter),transport->ciphertext,{});
            if (!plaintext) return std::unexpected(detail::open_error(plaintext.error()));
            auto committed=replay_.commit_authenticated(transport->counter);
            if (!committed) { crypto::cleanse(*plaintext); return std::unexpected(committed.error()); }
            confirmed_=true; return std::move(*plaintext);
        }
        auto confirmed(this Session const& self) noexcept -> bool { return self.confirmed_ && !self.closed_; }
        auto next_counter(this Session const& self) noexcept -> std::uint64_t { return self.counter_.next(); }
        auto last_received(this Session const& self) noexcept -> std::uint64_t { return self.replay_.last(); }
        auto rekey_due(this Session const& self,Clock::time_point now) noexcept -> bool {
            return !self.closed_ && now>=self.born_ && (self.counter_.next()>=rekey_after_messages ||
                (self.initiator_ && now-self.born_>=rekey_after_time));
        }
        auto receive_rekey_due(this Session const& self,Clock::time_point now) noexcept -> bool {
            return !self.closed_ && self.initiator_ && now>=self.born_ && now-self.born_>=std::chrono::seconds(105);
        }
    };
}
