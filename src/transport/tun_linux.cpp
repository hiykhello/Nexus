module transport.tun_linux;
import std;
import platform.linux_random;

namespace transport {
    LinuxTunDirect::LinuxTunDirect(packet::LinuxTun&& tun,tcp::ConnectionTable&& table,tcp::ConnectionTable6&& table6,rules::Matcher policy,TunLimits limits)
        : tun_(std::move(tun)),link_(limits.external),table_(std::move(table)),table6_(std::move(table6)),
          engine_(link_,table_,table6_,std::move(policy),limits.tcp_flows,limits.tcp_direct,limits.mapping,limits.filtering,limits.udp,limits.mtu,limits.internal,limits.socket_mark) {}
    LinuxTunDirect::~LinuxTunDirect() = default;
    auto LinuxTunDirect::create(packet::LinuxTun&& tun,rules::Matcher policy,TunLimits limits)
        -> std::expected<std::unique_ptr<LinuxTunDirect>,TunDriverFailure> {
        if (tun.native_handle()<0) return std::unexpected(TunDriverFailure{TunDriverError::invalid_device});
        auto usable=[&](packet::DeviceLimits const& value) {
            return value.packet_bytes>=limits.mtu && value.queue_bytes>=limits.mtu && value.queue_packets>0;
        };
        if (limits.mtu<65 || limits.mtu>65535 || !limits.tcp_direct || !limits.udp.flows ||
            !limits.udp.peers_per_flow || !limits.udp.idle_ms || !usable(limits.external) || !usable(limits.internal))
            return std::unexpected(TunDriverFailure{TunDriverError::invalid_limits});
        auto table=tcp::ConnectionTable::create(limits.tcp_flows,limits.tcp_buffer,limits.challenge_ack);
        if (!table) return std::unexpected(TunDriverFailure{table.error()});
        auto table6=tcp::ConnectionTable6::create(limits.tcp_flows,limits.tcp_buffer,limits.challenge_ack);
        if (!table6) return std::unexpected(TunDriverFailure{table6.error()});
        auto self=std::unique_ptr<LinuxTunDirect>(new LinuxTunDirect(std::move(tun),std::move(*table),std::move(*table6),std::move(policy),limits));
        auto pump=packet::FdPump::create(self->tun_.native_handle(),self->link_,limits.mtu);
        if (!pump) return std::unexpected(TunDriverFailure{pump.error()});
        self->pump_.emplace(std::move(*pump));
        return self;
    }
    auto LinuxTunDirect::step(std::uint64_t now) -> std::expected<TunStep,TunDriverFailure> {
        if (stopped_) return std::unexpected(TunDriverFailure{TunDriverError::stopped});
        if (initialized_ && now<now_) return std::unexpected(TunDriverFailure{TunDriverError::time_reversed});
        std::uint32_t iss{};
        auto bytes=std::as_writable_bytes(std::span(&iss,1));
        if (auto random=platform::secure_random(bytes); !random)
            return std::unexpected(TunDriverFailure{TunRandomFailure{random.error()}});
        return step(now,iss);
    }
    auto LinuxTunDirect::step(std::uint64_t now,std::uint32_t iss) -> std::expected<TunStep,TunDriverFailure> {
        if (stopped_) return std::unexpected(TunDriverFailure{TunDriverError::stopped});
        if (initialized_ && now<now_) return std::unexpected(TunDriverFailure{TunDriverError::time_reversed});
        initialized_=true; now_=now;
        auto validate=[](void* context,packet::QueuedPacket const& output) noexcept {
            auto& driver=*static_cast<LinuxTunDirect*>(context);
            return driver.engine_.valid_output(output);
        };
        auto device=pump_->step(validate,this);
        auto transport=engine_.step(now,iss);
        if (!transport) return std::unexpected(TunDriverFailure{transport.error()});
        return TunStep{std::move(device),std::move(*transport)};
    }
    auto LinuxTunDirect::stop(std::uint64_t now) -> std::expected<void,TunDriverFailure> {
        if (stopped_) return {};
        if (initialized_ && now<now_) return std::unexpected(TunDriverFailure{TunDriverError::time_reversed});
        if (auto result=engine_.stop(now); !result) return std::unexpected(TunDriverFailure{result.error()});
        pump_.reset();
        link_.close(packet::Side::first); link_.close(packet::Side::second);
        tun_.close(); stopped_=true; return {};
    }
}
