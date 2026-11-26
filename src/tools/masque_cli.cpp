module cli.masque_enabled;
import std;
import relay;
import crypto;
import masque.bearer;
import masque.ip_server;
import cli.masque_ip_server;
import rulefile;
import tls.ech_server;
import tls.server_credential;
import tls.profiles;
import cli.cert_reloader;
import logging.cli;
import dns.local_config;
import corosio;
namespace cli::masque_enabled {
    auto Runtime::configure(std::size_t index,config::InboundConfig const& entry,
        std::shared_ptr<void> const& acme_credential,cli::CertReloaderHub* cert_reloaders,logging::Runtime const* logs) -> std::expected<void,std::string> {
        if(!entry.masque)return {};
        if(index>=profiles_.size() || profiles_[index])return std::unexpected("invalid MASQUE profile slot");
        auto const& value=*entry.masque;
        std::optional<tls::ServerCredential> credential;
        std::shared_ptr<tls::AtomicServerCredential> atomic_credential;
        std::shared_ptr<tls::EchServerKeys const> ech_keys;
        if(!value.certificate_provider.empty()) {
            if(value.certificate_provider!="acme" || !acme_credential)
                return std::unexpected("MASQUE TLS certificate-provider '"+value.certificate_provider+"' is unavailable");
            atomic_credential=std::static_pointer_cast<tls::AtomicServerCredential>(acme_credential);
        } else if(value.cert_hot_reload) {
            if(!cert_reloaders)return std::unexpected("MASQUE TLS cert-hot-reload runtime unavailable");
            auto watched=cert_reloaders->watch(value.certificate_file,value.private_key_file,logs);
            if(!watched)return std::unexpected("MASQUE TLS cert-hot-reload: "+watched.error());
            atomic_credential=std::static_pointer_cast<tls::AtomicServerCredential>(*watched);
        } else {
            auto loaded=tls::load_server_credential(value.certificate_file,value.private_key_file);
            if(!loaded)return std::unexpected(loaded.error());
            credential.emplace(std::move(*loaded));
        }
        if(!value.ech_key_file.empty()) {
            auto ech=tls::load_ech_server_keys_file(value.ech_key_file);
            if(!ech)return std::unexpected("MASQUE TLS ech-key-file: "+ech.error());
            ech_keys=std::move(*ech);
        }
        auto password=rulefile::read_password_file(value.bearer_file);if(!password)return std::unexpected(password.error());
        struct Wipe {std::string& value;~Wipe(){crypto::cleanse({reinterpret_cast<std::uint8_t*>(value.data()),value.size()});}} wipe{*password};
        auto secret=masque::BearerCredential::create({reinterpret_cast<std::uint8_t const*>(password->data()),password->size()});
        if(!secret)return std::unexpected("invalid MASQUE bearer credential");
        std::vector<masque::DestinationRule> rules;rules.reserve(value.destinations.size());
        for(auto const& source:value.destinations) {
            masque::DestinationRule rule;rule.network.family=source.family;rule.network.address=source.network;rule.prefix=source.prefix;
            rule.first_port=source.first_port;rule.last_port=source.last_port;rules.push_back(rule);
        }
        masque::HostConfig config(value.authority,std::move(*secret),std::move(rules));
        config.dns_timeout=std::chrono::milliseconds(value.dns_timeout_ms);config.native_bytes=value.native_bytes;
        if(!config.valid(value.ip.has_value()))return std::unexpected("invalid MASQUE policy");
        auto profile=std::make_unique<Profile>(std::move(credential),std::move(atomic_credential),std::move(ech_keys),std::move(config));
        if(value.ip) {
            auto port=make_ip_server_port(*value.ip,value);
            if(!port)return std::unexpected(port.error());
            profile->ip=std::move(*port);
        }
        profile->address=value.listen_address;profile->ipv6=entry.listen_ipv6;profiles_[index]=std::move(profile);return {};
    }
    auto Runtime::loop(Profile& profile,Worker& worker) noexcept -> void {
        try {
            while(!profile.stopped.load(std::memory_order_acquire)) {
                worker.listener.poll_ip();
                if (!worker.listener.process_traffic_closes()) {
                    profile.failed.store(true,std::memory_order_release);
                    break;
                }
                worker.context.run_for(profile.ip ? std::chrono::milliseconds(5) : std::chrono::milliseconds(20));
                if(worker.listener.failed()) {profile.failed.store(true,std::memory_order_release);break;}
            }
            if(profile.ip && !worker.listener.failed()) {
                worker.listener.withdraw_ip();
                auto deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(250);
                while(std::chrono::steady_clock::now()<deadline) {
                    worker.listener.poll_ip();
                    worker.context.run_for(std::chrono::milliseconds(5));
                }
            }
            worker.listener.stop();
            while(!worker.listener.drained()) {worker.context.restart();worker.context.run_for(std::chrono::milliseconds(20));}
            if(!worker.listener.clean() || worker.listener.failed())profile.failed.store(true,std::memory_order_release);
        }catch(...) {
            profile.failed.store(true,std::memory_order_release);worker.listener.stop();
            try {while(!worker.listener.drained()){worker.context.restart();worker.context.run_for(std::chrono::milliseconds(20));}}
            catch(...) {std::terminate();}
        }
    }
    auto Runtime::start(std::size_t index,relay::Server& accounting,std::uint16_t port,unsigned count) -> std::expected<std::uint16_t,std::string> {
        if(count!=1)return std::unexpected("MASQUE requires exactly one worker until connection ID steering is implemented");
        if(index>=profiles_.size() || !profiles_[index] || !profiles_[index]->workers.empty())return std::unexpected("invalid MASQUE worker start");
        auto& profile=*profiles_[index];std::uint16_t bound=port;profile.stopped=false;profile.failed=false;
        try {
            for(unsigned i=0;i<count;++i) {
                auto worker=std::make_unique<Worker>(uring_,profile.config,profile.credential ? &*profile.credential : nullptr,profile.atomic_credential,profile.ip ? &profile.ip : nullptr,accounting,profile.ech_keys);
                corosio::endpoint local;
                if(profile.ipv6)local={corosio::ipv6_address(profile.address),bound};
                else {corosio::ipv4_address::bytes_type bytes{};std::ranges::copy(std::span(profile.address).first<4>(),bytes.begin());local={corosio::ipv4_address(bytes),bound};}
                auto prepared=worker->listener.prepare(local,count>1);
                if(!prepared) {auto error=prepared.error().message();worker->listener.stop();worker->context.restart();while(!worker->listener.drained())worker->context.run_for(std::chrono::milliseconds(20));stop_profile(profile);return std::unexpected(error);}
                bound=prepared->port();profile.workers.push_back(std::move(worker));
            }
            for(auto& worker:profile.workers)worker->listener.start();
            for(auto& worker:profile.workers)profile.threads.emplace_back([&profile,ptr=worker.get()] {loop(profile,*ptr);});
        }catch(std::exception const& e) {auto error=std::string(e.what());stop_profile(profile);return std::unexpected(error);}
        catch(...) {stop_profile(profile);return std::unexpected("MASQUE worker startup failed");}
        return bound;
    }
    auto Runtime::stop_profile(Profile& profile) noexcept -> void {
        profile.stopped.store(true,std::memory_order_release);
        for(auto& thread:profile.threads)if(thread.joinable())thread.join();
        for(std::size_t i=profile.threads.size();i<profile.workers.size();++i)loop(profile,*profile.workers[i]);
        profile.threads.clear();profile.workers.clear();
    }
}
