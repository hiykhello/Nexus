module cli.hy2_enabled;
import std;
import config;
import relay;
import relay.hysteria2_host;
import hysteria2.credential;
import hysteria2.transport_options;
import tls.profiles;
import rulefile;
import crypto;
import quic.retry_admission;
import corosio;
namespace cli::hy2_enabled {
    Runtime::~Runtime(){stop();}
    auto Runtime::resize(std::size_t count)->void {profiles_.resize(count);}
    auto Runtime::configure_outbound(config::Config const&)->std::expected<void,std::string> {return {};}
    auto Runtime::configure(std::size_t index,config::InboundConfig const& entry)->std::expected<void,std::string> {
        if(!entry.hysteria2)return {};
        if(index>=profiles_.size() || profiles_[index])return std::unexpected("invalid Hysteria2 listener index");
        auto const& cfg=*entry.hysteria2;
        auto credential=tls::load_server_credential(cfg.connection.certificate_file,cfg.connection.private_key_file);
        if(!credential)return std::unexpected(credential.error());
        auto profile=std::make_unique<Profile>(std::move(*credential));
        profile->listen_address=cfg.listen_address;
        for(auto const& user:cfg.connection.users){
            auto password=rulefile::read_password_file(user.password_file);if(!password)return std::unexpected(password.error());
            auto bytes=std::span(reinterpret_cast<std::uint8_t const*>(password->data()),password->size());
            auto parsed=hysteria2::Password::create(bytes);crypto::cleanse(std::span(reinterpret_cast<std::uint8_t*>(password->data()),password->size()));
            if(!parsed)return std::unexpected("invalid Hysteria2 password");
            for(auto const& existing:profile->passwords)if(crypto::constant_time_equal(existing.bytes(),parsed->bytes()))return std::unexpected("duplicate Hysteria2 password");
            profile->passwords.push_back(std::move(*parsed));profile->names.push_back(user.name);
        }
        profile->options={std::chrono::milliseconds(cfg.transport.handshake_timeout_ms),std::chrono::milliseconds(cfg.transport.idle_timeout_ms),cfg.transport.native_bytes,cfg.transport.udp};
        profile->options.max_udp_payload_size=cfg.transport.max_udp_payload_size;
        profile->options.receive_windows=cfg.transport.receive_windows;
        profile->options.disable_path_mtu_discovery=cfg.transport.disable_path_mtu_discovery;
        profile->options.congestion={cfg.transport.send_bps,cfg.transport.receive_bps,cfg.transport.ignore_client_bandwidth,cfg.transport.disable_compensation};
        if(cfg.transport.salamander_password_file){
            auto value=rulefile::read_password_file(*cfg.transport.salamander_password_file);
            if(!value)return std::unexpected(value.error());
            struct Wipe {std::string& value;~Wipe(){crypto::cleanse(std::span(reinterpret_cast<std::uint8_t*>(value.data()),value.size()));}} wipe{*value};
            auto key=hysteria2::SalamanderKey::create(std::span(reinterpret_cast<std::uint8_t const*>(value->data()),value->size()));
            if(!key)return std::unexpected(key.error());
            profile->salamander.emplace(std::move(*key));
            profile->options.salamander_password=profile->salamander->bytes();
        }
        if(!profile->options.valid())return std::unexpected("invalid Hysteria2 transport options");
        profile->masquerade=cfg.masquerade;
        profiles_[index]=std::move(profile);return {};
    }
    auto Runtime::start(std::size_t index,relay::Server& server,std::uint16_t port,bool ipv6,unsigned workers)->std::expected<std::uint16_t,std::string> {
        if(index>=profiles_.size() || !profiles_[index])return std::unexpected("Hysteria2 profile missing");
        auto& profile=*profiles_[index];profile.host=std::make_unique<relay::Hysteria2Host>(server,profile.credential,profile.passwords,profile.names,profile.options,profile.masquerade);
        corosio::endpoint endpoint;
        if (ipv6) endpoint={corosio::ipv6_address(profile.listen_address),port};
        else {
            corosio::ipv4_address::bytes_type bytes{};
            std::ranges::copy(std::span(profile.listen_address).first<4>(),bytes.begin());
            endpoint={corosio::ipv4_address(bytes),port};
        }
        auto result=profile.host->start(endpoint,workers);if(!result){
            auto text=std::visit([](auto const& error)->std::string {using E=std::decay_t<decltype(error)>;
                if constexpr(std::same_as<E,std::error_code>)return error.message();
                else if constexpr(std::same_as<E,std::exception_ptr>){try{std::rethrow_exception(error);}catch(std::exception const& e){return e.what();}catch(...){return "unknown exception";}}
                else return std::format("Retry error {} native {}",static_cast<int>(error.stage),error.native);
            },result.error());profile.host.reset();return std::unexpected(text);
        }return *result;
    }
    auto Runtime::queue_outbound_probe(std::size_t index,std::shared_ptr<relay::OutboundProbe> probe) -> bool {
        return index<profiles_.size() && profiles_[index] && profiles_[index]->host &&
            profiles_[index]->host->queue_outbound_probe(std::move(probe));
    }

    auto Runtime::healthy()const noexcept->bool {return std::ranges::all_of(profiles_,[](auto const& p){return !p || !p->host || p->host->healthy();});}
    auto Runtime::failure()const ->std::optional<std::string> {
        if(failure_)return failure_;
        for(auto const& p:profiles_)if(p && p->host)if(auto failure=p->host->failure()){
            std::string text=std::format("Hysteria2 worker error kind={} native={}",static_cast<int>(failure->kind),failure->native);
            if(failure->system)text+=": "+failure->system.message();
            if(failure->driver)text+=std::format(" driver={} system={}",static_cast<int>(failure->driver->code),failure->driver->system.message());
            if(failure->port)text+=std::format(" port={}",static_cast<int>(*failure->port));
            if(failure->retry)text+=std::format(" retry-stage={} retry-native={}",static_cast<int>(failure->retry->stage),failure->retry->native);
            if(failure->exception)try{std::rethrow_exception(failure->exception);}catch(std::exception const& e){text+=": ";text+=e.what();}catch(...){text+=": unknown exception";}
            return text;
        }return {};
    }
    auto Runtime::stop()noexcept->void {for(auto& p:profiles_)if(p && p->host)p->host->stop();
        try{if(!failure_ && !healthy())failure_=failure();}catch(...){}
    }
}
