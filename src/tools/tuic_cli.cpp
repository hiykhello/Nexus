module cli.tuic_enabled;
import std;
import config;
import relay;
import relay.tuic_host;
import tuic.wire;
import tuic.application;
import tuic.transport_options;
import tls.server_credential;
import tls.profiles;
import rulefile;
import crypto;
import corosio;

namespace cli::tuic_enabled {
    Runtime::~Runtime() { stop(); }
    auto Runtime::resize(std::size_t count) -> void { profiles_.resize(count); }

    auto Runtime::configure(std::size_t index, config::InboundConfig const& entry) -> std::expected<void, std::string> {
        if (!entry.tuic) return {};
        if (index >= profiles_.size() || profiles_[index]) return std::unexpected("invalid TUIC slot");
        auto const& cfg = *entry.tuic;
        auto cred = tls::load_server_credential(cfg.certificate_file, cfg.private_key_file);
        if (!cred) return std::unexpected(cred.error());
        auto profile = std::make_unique<Profile>(std::move(*cred));
        profile->listen_address = cfg.listen_address;
        profile->options.handshake_timeout = std::chrono::milliseconds(cfg.handshake_timeout_ms);
        profile->options.idle_timeout = std::chrono::milliseconds(cfg.idle_timeout_ms);
        profile->options.native_bytes = cfg.native_bytes;
        profile->options.cc = cfg.congestion_control == "bbr" ? tuic::CongestionControl::bbr :
                              cfg.congestion_control == "reno" ? tuic::CongestionControl::reno :
                              tuic::CongestionControl::cubic;
        profile->options.zero_rtt_handshake = cfg.zero_rtt_handshake;
        for (auto const& u : cfg.users) {
            auto raw_uuid = rulefile::read_password_file(u.uuid_file);
            if (!raw_uuid) return std::unexpected("TUIC UUID: " + raw_uuid.error());
            auto uuid = tuic::parse_uuid(*raw_uuid);
            crypto::cleanse(std::span(reinterpret_cast<std::uint8_t*>(raw_uuid->data()), raw_uuid->size()));
            if (!uuid) return std::unexpected("invalid TUIC UUID format");
            auto pass = rulefile::read_password_file(u.password_file);
            if (!pass) return std::unexpected("TUIC password: " + pass.error());
            profile->users.push_back({*uuid, std::move(*pass), u.name});
        }
        profiles_[index] = std::move(profile);
        return {};
    }

    auto Runtime::start(std::size_t index, relay::Server& server, std::uint16_t port, bool ipv6, unsigned workers)
        -> std::expected<std::uint16_t, std::string> {
        if (index >= profiles_.size() || !profiles_[index]) return std::unexpected("TUIC inbound not configured");
        auto& p = *profiles_[index];
        p.host = std::make_unique<relay::TuicHost>(server, p.credential, p.users, p.options);
        corosio::endpoint ep;
        if (ipv6) {
            ep = {corosio::ipv6_address(p.listen_address), port};
        } else {
            corosio::ipv4_address::bytes_type b{};
            std::copy_n(p.listen_address.begin(), 4, b.begin());
            ep = {corosio::ipv4_address(b), port};
        }
        auto bound = p.host->start(ep, workers);
        if (!bound) { failure_ = bound.error(); p.host.reset(); return std::unexpected(bound.error()); }
        return *bound;
    }

    auto Runtime::queue_outbound_probe(std::size_t index,std::shared_ptr<relay::OutboundProbe> probe) -> bool {
        return index<profiles_.size() && profiles_[index] && profiles_[index]->host &&
            profiles_[index]->host->queue_outbound_probe(std::move(probe));
    }

    auto Runtime::healthy() const noexcept -> bool {
        return std::ranges::all_of(profiles_, [](auto const& p) { return !p || !p->host || p->host->healthy(); });
    }
    auto Runtime::failure() const -> std::optional<std::string> { return failure_; }
    auto Runtime::stop() noexcept -> void {
        for (auto& p : profiles_) if (p && p->host) p->host->stop();
    }
}
