// Private to the proxy DNS implementation.
        auto response_local(Session& session,nex::corosio::io_context& context,std::string const& name,std::uint16_t type,
            Clock::time_point deadline,LocalSnapshotRef retained,bool disabled,void*& dns_operation,void (*&cancel_dns)(void*) noexcept,
            bool const& canceled,std::size_t* rotation_override=nullptr,
            std::optional<std::string_view> fixed_candidate={},std::optional<dns::ClientSubnet> subnet={})
            -> nex::capy::task<std::expected<RawSelection,dns::detail::ResolveError>> {
            using Error=dns::detail::ResolveError;
            if (session.closed || canceled)co_return std::unexpected(Error::canceled);
            if (!retained || !*retained || cancel_dns)
                co_return std::unexpected(Error::state);
            auto& state=*session.dns;
            LocalResponseLookup lookup{context,state.response_coordinator ? &*state.response_coordinator : nullptr,
                state.local_views ? &*state.local_views : nullptr,subnet};
            auto rotation=rotation_override ? *rotation_override : ((*retained)->config.rotate ? session.local_dns->rotation++ : 0);
            dns::detail::BasicLocalResponseResolver resolver(lookup,*retained,rotation,rotation_override,subnet);
            struct Registration {void*& operation;void (*&cancel)(void*) noexcept;~Registration(){cancel=nullptr;operation=nullptr;}} registration{dns_operation,cancel_dns};
            dns_operation=&resolver;cancel_dns=[](void* value) noexcept {
                static_cast<dns::detail::BasicLocalResponseResolver<LocalResponseLookup>*>(value)->cancel();
            };
            auto result=co_await resolver.resolve(name,type,deadline,disabled,fixed_candidate);
            if (session.closed || canceled) co_return std::unexpected(Error::canceled);
            co_return result;
        }
        auto response_server(Session& session,nex::corosio::io_context& context,std::size_t selected,
            std::string const& name,std::uint16_t type,Clock::time_point deadline,LocalSnapshotRef retained,bool disabled,
            void*& dns_operation,void (*&cancel_dns)(void*) noexcept,bool const& canceled,std::size_t* rotation_override=nullptr,
            std::optional<std::string_view> fixed_candidate={},std::optional<dns::ClientSubnet> subnet={})
            -> nex::capy::task<std::expected<RawSelection,dns::detail::ResolveError>> {
            using Error=dns::detail::ResolveError;
            if(session.closed || canceled)co_return std::unexpected(Error::canceled);
            auto const& routing=session.dns->routing;
            std::vector<std::size_t> chain;auto current=selected;
            while (routing.servers[current].resolver) { chain.push_back(current);current=*routing.servers[current].resolver; }
            std::vector<nex::corosio::endpoint> upstreams;
            if (routing.servers[current].port) upstreams.push_back(session.dns->endpoint(current));
            for (auto it=chain.rbegin();it!=chain.rend();++it) {
                auto const& next=routing.servers[*it];
                auto resolved=co_await query_server<false>(session,context,current,upstreams,next.host,next.port,strategy(session),deadline,
                    dns_operation,cancel_dns,retained);
                if(session.closed || canceled)co_return std::unexpected(Error::canceled);
                if (!resolved) co_return std::unexpected(resolved.error());
                upstreams=std::move(*resolved);current=*it;
            }
            if (upstreams.empty()) co_return co_await response_local(session,context,name,type,deadline,retained,disabled,dns_operation,cancel_dns,canceled,rotation_override,fixed_candidate,subnet);
            auto const& server=routing.servers[current];
            auto* transports=session.dns_transports();
            auto const& protection=transports ? transports->queries[current] : server.protection;
            for (auto const& upstream:upstreams) {
                if (!valid_destination(upstream)) continue;
                if (session.closed || canceled)co_return std::unexpected(Error::canceled);
                if (type != 1 && type != 28) {
                    if (subnet || cancel_dns) co_return std::unexpected(Error::state);
                    auto response=co_await message_response_owned(context,upstream,name,type,deadline,server.tcp,routing.edns,dns_operation,cancel_dns,protection.get());
                    if (session.closed || canceled) co_return std::unexpected(Error::canceled);
                    if (response) co_return RawSelection{std::move(*response),upstream,server.tcp,name,false,protection};
                    if (response.error()!=Error::transport) co_return std::unexpected(response.error());
                    continue;
                }
                if (!session.dns->response_coordinator || !session.dns->views || cancel_dns)
                    co_return std::unexpected(Error::state);
                auto view=session.dns->views->view(current,upstream,subnet);
                if (!view) co_return std::unexpected(Error::limit);
                if (transports) *view=transports->address_view(*view);
                dns_hp_experiment::ResponseCoordinatorQuery operation(*session.dns->response_coordinator);
                struct Registration {void*& operation;void (*&cancel)(void*) noexcept;~Registration(){cancel=nullptr;operation=nullptr;}} registration{dns_operation,cancel_dns};
                dns_operation=&operation;
                cancel_dns=[](void* value) noexcept { static_cast<dns_hp_experiment::ResponseCoordinatorQuery*>(value)->cancel(); };
                auto response=co_await operation.resolve(upstream,*view,{name,type},deadline,server.tcp,routing.edns,disabled,subnet,protection);
                if (session.closed || canceled) co_return std::unexpected(Error::canceled);
                if (response) co_return RawSelection{std::move(*response),upstream,server.tcp,name,false,protection};
                if (response.error()!=Error::transport) co_return std::unexpected(response.error());
            }
            co_return std::unexpected(Error::transport);
        }
