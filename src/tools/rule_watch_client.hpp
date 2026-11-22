#pragma once

    volatile std::sig_atomic_t interrupted=0;
    extern "C" void stop_rule_watch(int) {interrupted=1;}

    struct Signals {
        using Handler=void(*)(int);
        Handler interrupt=std::signal(SIGINT,stop_rule_watch);
        Handler terminate=std::signal(SIGTERM,stop_rule_watch);
        ~Signals() {
            if(interrupt!=SIG_ERR)std::signal(SIGINT,interrupt);
            if(terminate!=SIG_ERR)std::signal(SIGTERM,terminate);
        }
        auto installed() const noexcept -> bool {return interrupt!=SIG_ERR && terminate!=SIG_ERR;}
    };

    using FileIdentity=std::tuple<dev_t,ino_t,off_t,time_t,long,time_t,long>;
    using WatchDependencies=std::vector<FileIdentity>;

    struct WatchState {
        std::string config;
        std::optional<Alternative> alternative;
        std::optional<PublishedValidator> validator;
        std::optional<WatchDependencies> dependencies;
        std::unique_ptr<http::NamedHttpClient> client;
    };

    auto watch_dependencies(config::Config const& config,std::string_view name)
        -> std::optional<WatchDependencies> {
        using config::NamedHttpClient;
        auto selected=std::ranges::find(config.http_clients,name,&NamedHttpClient::name);
        // Proxied clients also own outbound credentials and state. Rebuild
        // those clients each refresh until their dependencies can be tracked.
        if (selected==config.http_clients.end() || selected->outbound_index || !config.dns ||
            cli::uses_proxy_dns(config.dns)) return {};

        WatchDependencies result;
        auto record=[&](char const* path,bool follow=true) {
            struct stat file{};
            auto status=follow ? ::stat(path,&file) : ::lstat(path,&file);
            if (status!=0 || !S_ISREG(file.st_mode)) return false;
            result.emplace_back(file.st_dev,file.st_ino,file.st_size,
                file.st_mtim.tv_sec,file.st_mtim.tv_nsec,file.st_ctim.tv_sec,file.st_ctim.tv_nsec);
            return true;
        };
        if (!record(selected->ca_file.c_str()) ||
            (!selected->ech_config_file.empty() && !record(selected->ech_config_file.c_str(),false))) return {};
        bool local=false;
        for (auto const& server:config.dns->servers) {
            if (!server.upstream) local=true;
            else if (server.upstream->tls && !record(server.upstream->tls->ca_file.c_str())) return {};
        }
        if (local && (!record("/etc/resolv.conf") || !record("/etc/hosts"))) return {};
        return result;
    }
