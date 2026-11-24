export module hysteria2.salamander;
import std;
import crypto;
import net.datagram_driver;
import quic.datagram_port;
import corosio;

export namespace hysteria2 {
    // The caller owns the wire salt and supplies fresh randomness for each
    // outgoing datagram. Applying the same transform decodes a received one.
    inline auto salamander_transform(std::span<std::uint8_t> payload,
        std::span<std::uint8_t const> password,std::span<std::uint8_t const,8> salt) noexcept -> void {
        std::array<std::uint8_t,32> mask{};
        crypto::blake2b_256_parts(mask,password,salt);
        for (std::size_t i=0;i<payload.size();++i) payload[i]^=mask[i%mask.size()];
        crypto::cleanse(mask);
    }

    // The port retains ownership and send tokens. This adapter only transforms
    // the driver's packet buffer, before QUIC sees it or after QUIC seals it.
    template<class Port> class SalamanderPort {
        Port& port_;
        std::optional<std::span<std::uint8_t const>> password_;
        std::vector<std::pair<std::uint16_t,std::uint16_t>> hop_ranges_;
        std::chrono::milliseconds hop_interval_{0};
        std::uint16_t primary_port_=0, active_port_=0;
        net::DatagramClock::time_point next_hop_{};
        bool hopping_=false;

        auto total_hop_ports() const noexcept -> std::uint64_t {
            std::uint64_t total=0;
            for (auto [lo,hi] : hop_ranges_) total+=static_cast<std::uint64_t>(hi-lo)+1;
            return total;
        }
        auto port_at(std::uint64_t idx) const noexcept -> std::uint16_t {
            for (auto [lo,hi] : hop_ranges_) {
                auto span=static_cast<std::uint64_t>(hi-lo)+1;
                if (idx<span) return static_cast<std::uint16_t>(lo+idx);
                idx-=span;
            }
            return primary_port_;
        }
        auto pick_hop_port() noexcept -> std::uint16_t {
            auto total=total_hop_ports();
            if (!total) return primary_port_;
            std::array<std::uint8_t,4> rnd{};
            std::uint32_t v=0;
            if (crypto::random_bytes(rnd)) v=(std::uint32_t{rnd[0]}<<24)|(std::uint32_t{rnd[1]}<<16)|(std::uint32_t{rnd[2]}<<8)|rnd[3];
            auto chosen=port_at(v%total);
            if (total>1 && chosen==active_port_) chosen=port_at((v+1)%total);
            return chosen;
        }
        auto in_hop_set(std::uint16_t p) const noexcept -> bool {
            if (p==active_port_ || p==primary_port_) return true;
            for (auto [lo,hi] : hop_ranges_) if (p>=lo && p<=hi) return true;
            return false;
        }
    public:
        using Failure=typename Port::Failure;
        SalamanderPort(Port& port,std::optional<std::span<std::uint8_t const>> password) noexcept
            :port_(port),password_(password) {}
        auto configure_hopping(std::uint16_t primary,std::span<std::pair<std::uint16_t,std::uint16_t> const> ranges,
            std::chrono::milliseconds interval,net::DatagramClock::time_point now) -> void {
            if (ranges.empty() || interval.count()<=0) return;
            hop_ranges_.assign(ranges.begin(),ranges.end());
            hop_interval_=interval;
            primary_port_=primary;
            active_port_=pick_hop_port();
            next_hop_=now+hop_interval_;
            hopping_=true;
        }
        [[nodiscard]] auto active_hop_port() const noexcept -> std::uint16_t { return hopping_ ? active_port_ : primary_port_; }
        auto request_stop() noexcept -> void {port_.request_stop();}
        auto stop() noexcept -> void {port_.stop();}
        auto drain() noexcept -> void {port_.drain();}
        auto next_expiry() const noexcept -> net::DatagramDeadline {
            auto inner=port_.next_expiry();
            if (!hopping_) return inner;
            if (!inner || next_hop_<*inner) return next_hop_;
            return inner;
        }
        auto expire(net::DatagramClock::time_point now) -> std::expected<void,Failure> {
            if (hopping_ && now>=next_hop_) {
                active_port_=pick_hop_port();
                next_hop_=now+hop_interval_;
            }
            return port_.expire(now);
        }
        auto transmitted(std::uint64_t token,net::DatagramClock::time_point now) -> std::expected<void,Failure> {
            return port_.transmitted(token,now);
        }
        auto mtu_rejected(std::uint64_t token,net::DatagramClock::time_point now) -> std::expected<void,Failure>
            requires requires {port_.mtu_rejected(token,now);} {return port_.mtu_rejected(token,now);}
        auto receive(corosio::endpoint const& peer,std::span<std::uint8_t> bytes,net::DatagramClock::time_point now)
            -> std::expected<void,Failure> {
            auto logical=(hopping_ && in_hop_set(peer.port())) ? corosio::endpoint(peer.address(),primary_port_) : peer;
            if (!password_) return port_.receive(logical,bytes,now);
            if (bytes.size()<8) return {};
            auto salt=std::span<std::uint8_t const,8>(bytes.data(),8);
            auto payload=bytes.subspan(8);
            salamander_transform(payload,*password_,salt);
            return port_.receive(logical,payload,now);
        }
        auto output(std::span<std::uint8_t> bytes,net::DatagramClock::time_point now)
            -> std::expected<std::optional<net::DatagramOutput>,Failure> {
            auto apply_hop=[this,now](std::expected<std::optional<net::DatagramOutput>,Failure>&& res) {
                if (hopping_ && res && *res) {
                    if (now>=next_hop_) { active_port_=pick_hop_port(); next_hop_=now+hop_interval_; }
                    (**res).peer=corosio::endpoint((**res).peer.address(),active_port_);
                }
                return std::move(res);
            };
            if (!password_) return apply_hop(port_.output(bytes,now));
            if (bytes.size()<8) return std::unexpected(Failure{quic::DatagramPortError::invalid_output});
            auto packet=port_.output(bytes.subspan(8),now);
            if (!packet || !*packet) return packet;
            if (!crypto::random_bytes(bytes.first(8))) return std::unexpected(Failure{quic::DatagramPortError::random});
            auto salt=std::span<std::uint8_t const,8>(bytes.data(),8);
            salamander_transform(bytes.subspan(8,(**packet).size),*password_,salt);
            (**packet).size+=8;
            return apply_hop(std::move(packet));
        }
    };
}
