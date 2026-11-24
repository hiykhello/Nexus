export module net.tcp_connect;
import std;
export import net.happy_eyeballs;
export import platform.socket_options;
import capy;
import corosio;

export namespace net {
    // The source and deadline stay with the caller. Preparation opens only a
    // physical socket and introduces no protocol-specific connection behavior.
    template<class Socket,class Endpoint>
    [[nodiscard]] auto prepare_tcp_socket(Socket& socket,Endpoint const& endpoint,
        platform::TcpSocketOptions const& options,
        platform::SocketDeadline deadline=platform::SocketDeadline::max()) noexcept -> std::error_code {
        if (!options.configured()) return {};
        if (!options.valid()) return std::make_error_code(std::errc::invalid_argument);
        auto multipath=options.multipath_tcp.value_or(false);
        if (multipath || !options.binding.network_namespace.empty()) {
            auto fd=platform::open_physical_socket(endpoint.is_v6(),false,multipath,options.binding.network_namespace);
            if(!fd)return fd.error();
            if(auto error=socket.assign(*fd)) { platform::close_unadopted_socket(*fd);return error; }
        } else if (auto error=socket.open(endpoint.address().family())) return error;
        if (auto error=platform::apply_tcp_options(socket.native_handle(),options,deadline)) return error;
        platform::tune_tcp_low_latency(socket.native_handle());
        if (endpoint.is_v4() && options.binding.inet4_bind_address)
            return socket.bind(Endpoint(corosio::ipv4_address(*options.binding.inet4_bind_address),0));
        if (endpoint.is_v6() && options.binding.inet6_bind_address)
            return socket.bind(Endpoint(corosio::ipv6_address(*options.binding.inet6_bind_address),0));
        return {};
    }

    namespace detail {
        [[nodiscard]] auto tcp_interfaces(platform::TcpSocketOptions const& options,bool ipv6)
            -> platform::network::InterfaceCandidates {
            if (options.binding.network) return (*options.binding.network)(ipv6);
            platform::network::InterfaceCandidates result;
            result.indices.push_back(0);
            return result;
        }

        auto tcp_attempt_deadline(platform::SocketDeadline deadline,
            platform::network::InterfaceCandidates const& interfaces,std::size_t candidate)
            -> platform::SocketDeadline {
            if (candidate+1==interfaces.indices.size()) return deadline;
            return std::min(deadline,std::chrono::steady_clock::now()+interfaces.fallback_delay);
        }

        [[nodiscard]] auto tcp_interface_options(platform::TcpSocketOptions const& options,
            std::uint32_t index,platform::TcpSocketOptions& selected) -> platform::TcpSocketOptions const& {
            if (!options.binding.network) return options;
            selected=options;
            selected.binding.network.reset();
            selected.binding.interface_index=index;
            return selected;
        }

        // The same candidate and cancellation rules as Corosio's range-connect,
        // preserving caller candidate order (required by stateful conditions),
        // with RFC 8305 dual-stack 300ms fast-fallback timeout and socket
        // preparation after each close and before each connect.
        template<class Socket,std::ranges::input_range Range,class Condition>
        auto connect_prepared(Socket& socket,Range endpoints,Condition condition,
            platform::TcpSocketOptions const& options,bool& preparation_failed,platform::SocketDeadline deadline,
            std::uint32_t* connected_interface)
            -> capy::task<capy::results<typename Socket::endpoint_type>> {
            using Endpoint=typename Socket::endpoint_type;
            std::vector<Endpoint> ordered;
            for (auto&& item:endpoints) ordered.emplace_back(item);
            auto is_v6=[](Endpoint const& ep) noexcept { return ep.is_v6(); };
            bool const dual_stack=has_dual_stack_families(std::span<Endpoint const>(ordered),is_v6);
            std::error_code last;
            for (std::size_t ep_idx=0;ep_idx<ordered.size();++ep_idx) {
                Endpoint endpoint=ordered[ep_idx];
                if (!condition(std::as_const(last),std::as_const(endpoint))) continue;
                auto interfaces=tcp_interfaces(options,endpoint.is_v6());
                if (interfaces.indices.empty()) {
                    last=std::make_error_code(std::errc::network_unreachable);
                    continue;
                }
                for (std::size_t index=0;index<interfaces.indices.size();++index) {
                    if (std::chrono::steady_clock::now()>=deadline)
                        co_return {std::make_error_code(std::errc::timed_out),Endpoint{}};
                    if (socket.is_open()) socket.close();
                    platform::TcpSocketOptions selected;
                    auto const& settings=tcp_interface_options(options,interfaces.indices[index],selected);
                    if (settings.configured()) {
                        if (auto error=prepare_tcp_socket(socket,endpoint,settings,deadline)) {
                            socket.close();
                            if (options.binding.network && platform::network::retry_interface_error(error)) {
                                last=error;
                                continue;
                            }
                            preparation_failed=true;
                            co_return {error,Endpoint{}};
                        }
                    } else if (auto error=socket.open(endpoint.address().family())) {
                        last=error;
                        continue;
                    }
                    auto stop=tcp_attempt_deadline(deadline,interfaces,index);
                    if (dual_stack && ep_idx+1<ordered.size() && interfaces.indices.size()==1)
                        stop=std::min(stop,std::chrono::steady_clock::now()+kHappyEyeballsFallbackDelay);
                    auto [error]=stop==deadline ? co_await socket.connect(endpoint) :
                        co_await corosio::timeout(socket.connect(endpoint),stop);
                    if (!error) {
                        if (!settings.configured()) platform::tune_tcp_low_latency(socket.native_handle());
                        if (interfaces.fallback_memory && index==0)
                            interfaces.fallback_memory->mark_healthy(interfaces.indices[0]);
                        if (connected_interface) *connected_interface=settings.binding.interface_index;
                        co_return {std::error_code{},std::move(endpoint)};
                    }
                    if (error==capy::cond::canceled) co_return {error,Endpoint{}};
                    if (interfaces.parallel_fallback && interfaces.fallback_memory && index==0 &&
                        interfaces.indices.size()>1) {
                        auto now_ms=std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now().time_since_epoch()).count();
                        interfaces.fallback_memory->mark_failed(interfaces.indices[0],now_ms);
                    }
                    last=error;
                }
            }
            if (!last) last=std::make_error_code(std::errc::no_such_device_or_address);
            co_return {last,Endpoint{}};
        }
    }

    // Returning the selected task directly retains one range-connect frame.
    template<class Socket,std::ranges::input_range Range,class Condition>
    auto connect_tcp_candidates(Socket& socket,Range endpoints,Condition condition,
        platform::TcpSocketOptions const& options,bool& preparation_failed,
        platform::SocketDeadline deadline=platform::SocketDeadline::max(),std::uint32_t* connected_interface=nullptr)
        -> capy::task<capy::results<typename Socket::endpoint_type>> {
        if (connected_interface) *connected_interface=0;
        if (!options.configured()) {
            bool dual_stack=false;
            if constexpr (std::ranges::forward_range<Range>) {
                bool v4=false,v6=false;
                for (auto const& item:endpoints) {
                    if (item.is_v6()) v6=true; else v4=true;
                    if (v4 && v6) { dual_stack=true; break; }
                }
            }
            if (!dual_stack) return corosio::connect(socket,std::move(endpoints),std::move(condition));
        }
        return detail::connect_prepared(socket,std::move(endpoints),std::move(condition),options,preparation_failed,deadline,connected_interface);
    }
}
