export module wireguard.session;
import std;
import crypto;
import crypto.aead_context;
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
        static auto overlaps(std::span<std::uint8_t> a,std::span<std::uint8_t const> b) noexcept -> bool {
            if (a.empty() || b.empty()) return false;
            auto first=reinterpret_cast<std::uintptr_t>(a.data()),second=reinterpret_cast<std::uintptr_t>(b.data());
            return first<=second ? second-first<a.size() : first-second<b.size();
        }
        auto seal_checked(std::span<std::uint8_t> output,std::span<std::uint8_t const> plaintext,std::size_t padded) noexcept
            -> std::expected<std::size_t,Error> {
            auto total=transport_header_size+padded+16;
            if (output.size()<total || overlaps(output.first(total),plaintext)) return std::unexpected(Error::invalid_length);
            crypto::AeadContext aead;
            if (!aead.reset(crypto::Aead::chacha20_poly1305,send_.view())) return std::unexpected(Error::backend);
            auto counter=counter_.take(); if (!counter) return std::unexpected(counter.error());
            auto header=transport_header(remote_,*counter);
            std::ranges::copy(header,output.begin());
            auto dst=output.subspan(transport_header_size,padded+16);
            if (!plaintext.empty()) std::ranges::copy(plaintext,dst.begin());
            if (padded>plaintext.size()) std::fill_n(dst.begin()+plaintext.size(),padded-plaintext.size(),std::uint8_t{0});
            auto sealed=aead.seal_to(dst,transport_nonce(*counter),dst.first(padded));
            if (!sealed) { crypto::cleanse(output.first(total)); return std::unexpected(Error::backend); }
            return total;
        }
        auto open_checked(TransportView const& transport,std::span<std::uint8_t> output) noexcept
            -> std::expected<std::size_t,Error> {
            auto plain_size=transport.ciphertext.size()-16;
            if (output.size()<plain_size) return std::unexpected(Error::invalid_length);
            crypto::AeadContext aead;
            if (!aead.reset(crypto::Aead::chacha20_poly1305,receive_.view())) return std::unexpected(Error::backend);
            auto opened=aead.open_to(output.first(plain_size),transport_nonce(transport.counter),transport.ciphertext);
            if (!opened) return std::unexpected(detail::open_error(opened.error()));
            auto committed=replay_.commit_authenticated(transport.counter);
            if (!committed) { crypto::cleanse(output.first(*opened)); return std::unexpected(committed.error()); }
            confirmed_=true; return *opened;
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
        auto seal_to(std::span<std::uint8_t> output,std::span<std::uint8_t const> plaintext,Clock::time_point now,
            std::size_t inner_mtu=max_datagram_size-transport_overhead) noexcept -> std::expected<std::size_t,Error> {
            if (!active(now)) return std::unexpected(Error::expired);
            if (!confirmed_) return std::unexpected(Error::not_confirmed);
            if (!inner_mtu || inner_mtu>max_datagram_size-transport_overhead || plaintext.size()>inner_mtu) return std::unexpected(Error::invalid_length);
            auto padded=std::min((plaintext.size()+15)&~std::size_t{15},inner_mtu);
            return seal_checked(output,plaintext,padded);
        }
        auto seal(std::span<std::uint8_t const> plaintext,Clock::time_point now,std::size_t inner_mtu=max_datagram_size-transport_overhead)
            -> std::expected<std::vector<std::uint8_t>,Error> {
            if (!active(now)) return std::unexpected(Error::expired);
            if (!confirmed_) return std::unexpected(Error::not_confirmed);
            if (!inner_mtu || inner_mtu>max_datagram_size-transport_overhead || plaintext.size()>inner_mtu) return std::unexpected(Error::invalid_length);
            auto padded=std::min((plaintext.size()+15)&~std::size_t{15},inner_mtu);
            std::vector<std::uint8_t> result(transport_header_size+padded+16);
            auto written=seal_checked(result,plaintext,padded);
            if (!written) return std::unexpected(written.error());
            return result;
        }
        auto open_to(std::span<std::uint8_t> output,std::span<std::uint8_t const> wire,Clock::time_point now) noexcept
            -> std::expected<std::size_t,Error> {
            if (!active(now)) return std::unexpected(Error::expired);
            auto transport=parse_transport(wire); if (!transport) return std::unexpected(transport.error());
            if (transport->receiver!=local_) return std::unexpected(Error::invalid_state);
            auto acceptable=replay_.check(transport->counter); if (!acceptable) return std::unexpected(acceptable.error());
            return open_checked(*transport,output);
        }
        auto open(std::span<std::uint8_t const> wire,Clock::time_point now) -> std::expected<std::vector<std::uint8_t>,Error> {
            if (!active(now)) return std::unexpected(Error::expired);
            auto transport=parse_transport(wire); if (!transport) return std::unexpected(transport.error());
            if (transport->receiver!=local_) return std::unexpected(Error::invalid_state);
            auto acceptable=replay_.check(transport->counter); if (!acceptable) return std::unexpected(acceptable.error());
            std::vector<std::uint8_t> plaintext(transport->ciphertext.size()-16);
            auto opened=open_checked(*transport,plaintext);
            if (!opened) return std::unexpected(opened.error());
            return plaintext;
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
