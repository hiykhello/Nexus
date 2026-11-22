#pragma once

        template<class Incoming>
        struct MuxStream {
            Session& session;
            Incoming& incoming;
            auto read(std::span<std::uint8_t> data) -> nex::capy::task<std::expected<std::size_t,int>> {
                auto result=co_await incoming.read(data);
                if (!result) co_return std::unexpected(1);
                session.touched=Clock::now();
                co_return *result;
            }
            auto write(std::span<std::uint8_t const> data) {session.touched=Clock::now();return incoming.send(data);}
            auto cancel() noexcept -> void {session.close();}
        };
        struct MuxLookup {
            auto operator()(Session& session,nex::corosio::io_context& context,std::string name,std::uint16_t port,Clock::time_point until) const {
                return resolve_udp_domain(session,context,std::move(name),port,until);
            }
        };

        template<class Stream>
        auto payload(Session& session,nex::corosio::io_context& context,rules::RouteMatcher const& policy,
            InboundProfile const& profile,Stream& stream,Clock::time_point deadline) -> nex::capy::task<nex::capy::results<>> {
            struct Done {
                Session& session;
                ~Done(){session.close();}
            } done{session};
            auto handshake=profile.vless.vless_handshake();
            if (!handshake) co_return nex::capy::results<>{};
            vless::detail::TlsInbound<Socket,false,Stream&> incoming(stream,std::move(*handshake));
            if (!incoming.allow_mux()) co_return nex::capy::results<>{};
            auto header=co_await incoming.read_header(deadline);
            if (!header || session.closed) co_return nex::capy::results<>{};
            bool is_mux=std::holds_alternative<vless::UserId>(*header);
            if (!profile.names.empty()) {
                auto const& id=is_mux ? std::get<vless::UserId>(*header) : std::get<vless::TcpRequest>(*header).user;
                auto index=profile.vless.user_index(id);
                if (!index || !session.admit_principal(profile.names[*index])) co_return nex::capy::results<>{};
            }
            if (is_mux) {
                if (!co_await incoming.complete_dial(true,deadline)) co_return nex::capy::results<>{};
                session.relaying=true;
                MuxStream lower{session,incoming};
                vless_mux::Resolver<Session,MuxLookup> resolver{session,context};
                auto source=source_endpoint(session,policy);
                vless_mux::Server mux(lower,resolver,policy,256,65535,source ? &*source : nullptr,session.auth_user,
                    session.direct_tcp_options ? &session.direct_tcp_options->binding : nullptr,vless_mux::FlowAccounting(session));
                (void)co_await nex::capy::when_all(vless_mux::read(session,mux),vless_mux::poll(session,mux),vless_mux::timeout(session,mux,resolver));
                co_return nex::capy::results<>{};
            }
            auto const& request=std::get<vless::TcpRequest>(*header);
            socks5::Request target;
            target.status=socks5::Status::accepted;target.port=request.port;
            target.address_type=request.kind==vless::AddressKind::ipv4 ? 1 : request.kind==vless::AddressKind::ipv6 ? 4 : 3;
            target.address_length=static_cast<std::uint8_t>(request.address.size());
            std::ranges::copy(request.address,target.address.begin());
            session.begin_traffic(TrafficProtocol::vless,target.port);
            auto dialed=session.datagram_source ?
                co_await dial_destination(session,context,policy,target,*session.datagram_source,deadline) :
                co_await dial_destination(session,context,policy,target,deadline);
            if (dialed || session.closed) co_return nex::capy::results<>{};
            if (!co_await incoming.complete_dial(true,deadline)) co_return nex::capy::results<>{};
            session.relaying=true;
            auto download=[&]() -> nex::capy::task<nex::capy::results<>> {
                // Downlink completion retires an upload with no wire-level EOF.
                (void)co_await stream_relay::download(session,incoming);
                session.close();
                co_return nex::capy::results<>{std::make_error_code(std::errc::operation_canceled)};
            };
            if constexpr (requires {stream.packet_up();}) {
                if (stream.packet_up()) {
                    (void)co_await nex::capy::when_all(stream_relay::direction(session,stream_relay::upload(session,incoming)),download());
                    co_return nex::capy::results<>{};
                }
            }
            (void)co_await nex::capy::when_all(stream_relay::direction(session,stream_relay::upload(session,incoming)),
                stream_relay::direction(session,stream_relay::download(session,incoming)));
            co_return nex::capy::results<>{};
        }

