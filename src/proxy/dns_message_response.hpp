        // Complete-message lookups such as HTTPS/SVCB do not use the address
        // response coordinator, whose singleflight keys admit only A/AAAA.
        auto message_response(dns::detail::MessageQuery& query, nex::corosio::endpoint upstream,
                              std::string const& name, std::uint16_t type, Clock::time_point deadline, bool edns)
            -> nex::capy::task<std::expected<dns::Response,dns::detail::ResolveError>> {
            dns::QueryMessage request{0, 0x0100, {name,type}, {}};
            if (edns) request.edns.emplace(dns::QueryEdns{1232,0,false,{}});
            auto wire = co_await query.run_borrowed(upstream, request, deadline);
            if (!wire) co_return std::unexpected(wire.error());
            auto response = dns::parse_owned_response(std::move(*wire), request.id, request.question);
            if (!response) co_return std::unexpected(dns::detail::ResolveError::protocol);
            co_return std::move(*response);
        }

        auto message_response_owned(nex::corosio::io_context& context, nex::corosio::endpoint upstream,
                                    std::string const& name, std::uint16_t type, Clock::time_point deadline, bool tcp, bool edns,
                                    void*& operation,void (*&cancel)(void*) noexcept,
                                    dns::detail::ProtectedQuery const* protection=nullptr)
            -> nex::capy::task<std::expected<dns::Response,dns::detail::ResolveError>> {
            dns::detail::MessageQuery query(context,tcp,protection);
            struct Registration {
                void*& operation;
                void (*&cancel)(void*) noexcept;
                ~Registration() { cancel=nullptr; operation=nullptr; }
            } registration{operation,cancel};
            operation=&query;
            cancel=[](void* active) noexcept { static_cast<dns::detail::MessageQuery*>(active)->cancel(); };
            co_return co_await message_response(query, upstream, name, type, deadline, edns);
        }
