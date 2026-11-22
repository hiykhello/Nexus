// Private Linux transparent TCP adapter included by the session executor.
#pragma once
    namespace {
        auto redirected_target(io::tcp_socket const& client,io::endpoint bound) -> std::optional<io::endpoint> {
            if (bound.address().is_v6()) {
                sockaddr_in6 original{};
                socklen_t size=sizeof(original);
                if (::getsockopt(client.native_handle(),IPPROTO_IPV6,SO_ORIGINAL_DST,&original,&size)<0 ||
                    size!=sizeof(original) || original.sin6_family!=AF_INET6 || original.sin6_scope_id) return {};
                io::ipv6_address::bytes_type bytes;
                std::ranges::copy(original.sin6_addr.s6_addr,bytes.begin());
                return io::endpoint(io::ipv6_address(bytes),ntohs(original.sin6_port));
            }
            sockaddr_in original{};
            socklen_t size=sizeof(original);
            if (::getsockopt(client.native_handle(),IPPROTO_IP,SO_ORIGINAL_DST,&original,&size)<0 ||
                size!=sizeof(original) || original.sin_family!=AF_INET) return {};
            io::ipv4_address::bytes_type bytes;
            std::memcpy(bytes.data(),&original.sin_addr,bytes.size());
            return io::endpoint(io::ipv4_address(bytes),ntohs(original.sin_port));
        }
    }

    static auto forward_tcp_destination(Session& session,io::io_context& context,rules::RouteMatcher const& policy,
        socks5::Request const& destination,TrafficProtocol protocol,bool redirect_dns=false) -> capy::task<> {
        session.begin_traffic(protocol,destination.port);
        if (session.ordered_tcp) {
            co_await ordered_connect(session,context,destination,{},ConnectReply::none,redirect_dns);
            co_return;
        }
        if (co_await dial(session,context,policy,destination)) {
            session.close();
            session.done=true;
            co_return;
        }
        session.relaying=true;
        co_await relay_pair(session);
    }

    auto serve_fixed_tcp(Session& session,io::io_context& context,rules::RouteMatcher const& policy,
        socks5::Request const& destination) -> capy::task<> {
        session.inspect_source_owner(policy);
        return forward_tcp_destination(session,context,policy,destination,TrafficProtocol::fixed_tcp);
    }

    auto serve_transparent_tcp(Session& session,io::io_context& context,rules::RouteMatcher const& policy,
        io::endpoint listener,bool tproxy,bool redirect_dns) -> capy::task<> {
        auto fail=[&] {session.close();session.done=true;};
        // The epoll acceptor may retain its listening endpoint in the child
        // socket metadata. TPROXY preserves the destination on the accepted fd.
        auto bound=accepted_local(session.client);
        if (!bound.port()) {fail();co_return;}
        auto original=tproxy ? std::optional(bound) : redirected_target(session.client,bound);
        if (!original || !original->port() ||
            (!tproxy && *original==bound) ||
            (original->port()==listener.port() &&
                (listener.address().is_unspecified() || original->address()==listener.address()))) {
            fail();
            co_return;
        }
        socks5::Request destination;
        destination.status=socks5::Status::accepted;
        destination.port=original->port();
        if (original->address().is_v6()) {
            if (original->address().to_v6().scope_id()) {fail();co_return;}
            destination.address_type=4;
            destination.address_length=16;
            std::ranges::copy(original->address().to_v6().to_bytes(),destination.address.begin());
        } else {
            destination.address_type=1;
            destination.address_length=4;
            std::ranges::copy(original->address().to_v4().to_bytes(),destination.address.begin());
        }
        if (auto source=source_endpoint(session,session.network_monitor!=nullptr))
            session.ingress=ingress_metadata(session.network_monitor,*source);
        session.inspect_source_owner(policy,*original);
        co_await forward_tcp_destination(session,context,policy,destination,
            tproxy ? TrafficProtocol::tproxy : TrafficProtocol::redirect,redirect_dns);
    }
