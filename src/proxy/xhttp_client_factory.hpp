#pragma once

        auto dispatch(std::unique_ptr<Profile> profile) -> TunnelFactory {
            using Worker=HttpWorker<HttpCarrier>;
            using Stream=HttpStream<HttpCarrier>;
            auto timeout=profile->timeout;
            auto options=profile->options;
            auto upload=profile->up.endpoint.version;
            auto download=profile->down ? profile->down->endpoint.version : upload;
            struct Workers {
                std::mutex mutex;
                std::unordered_map<nex::corosio::io_context*,std::shared_ptr<Worker>> contexts;
                auto get(nex::corosio::io_context& context) noexcept -> std::shared_ptr<Worker> {
                    std::lock_guard lock(mutex);
                    auto it=contexts.find(&context);
                    return it==contexts.end() ? nullptr : it->second;
                }
            };
            auto workers=std::make_shared<Workers>();
            auto mux=profile->transport.mux;
            TunnelFactory factory{[profile=std::move(profile),workers](Session& session,nex::corosio::io_context& context,bool local,
                TcpSocketOptions const* inherited) -> pro::proxy<TunnelFacade> {
                auto const& settings=inherited ? *inherited : profile->options;
                auto worker=workers->get(context);
                if (!worker) return {};
                return pro::make_proxy<TunnelFacade,Tunnel<Stream>>(session,context,*profile,local,settings,std::move(worker));
            },timeout,{},std::nullopt,options.configured()};
            factory.start_context=[workers,mux,upload,download](OutboundContext const& env,TunnelFactory const*,bool) {
                auto worker=std::make_shared<Worker>(env.context,mux,upload,download);
                std::lock_guard lock(workers->mutex);
                if (!workers->contexts.emplace(&env.context,worker).second) return false;
                Worker::start(std::move(worker));
                return true;
            };
            factory.stop_context=[workers](nex::corosio::io_context& context) noexcept {
                if (auto worker=workers->get(context)) worker->stop();
            };
            factory.finish_context=[workers](nex::corosio::io_context& context) noexcept {
                std::lock_guard lock(workers->mutex);
                workers->contexts.erase(&context);
            };
            factory.packet_dual_family=true;
            return factory;
        }
