module;
#include <proxy/proxy_macros.h>
#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/endpoint.hpp>
#ifdef NEXUS_TEST_ROOT_LAUNCH
#include <boost/capy/ex/frame_allocator.hpp>
#endif
#include <boost/corosio/delay.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>
#include <boost/corosio/posix_stream_descriptor.hpp>
#include <boost/corosio/wait_type.hpp>
#include <cerrno>
#include <fcntl.h>
#include <netinet/in.h>
#if defined(__linux__)
#include <netinet/tcp.h>
#endif
#include <sys/socket.h>
#include <unistd.h>

module relay;
import std;
import functional;
import relay.dns_backend;
import relay.dns_state;
import corosio;
import :tcp_listener_helpers;

#ifdef NEXUS_TEST_START_THROW
extern "C" void nexus_test_start_throw();
#endif
#ifdef NEXUS_TEST_ROOT_LAUNCH
extern "C" void nexus_test_root_launch(unsigned);
extern "C" std::pmr::memory_resource* nexus_test_root_resource();
#endif
namespace relay {
    using namespace tcp_listener_detail;
    using namespace std::chrono_literals;

    auto TcpAdmission::attach(std::uint64_t gen, Server* srv, bool threaded) -> void {
        std::lock_guard lock(mutex);
        std::erase_if(entries, [srv](Entry const& e) { return e.server == srv; });
        entries.push_back({gen, srv, threaded});
    }
    auto TcpAdmission::detach(Server* srv) noexcept -> void {
        std::lock_guard lock(mutex);
        std::erase_if(entries, [srv](Entry const& e) { return e.server == srv; });
    }
    auto TcpAdmission::publish(std::uint64_t next, functional::function_ref<void() noexcept> prepare) -> bool {
        std::vector<Entry> retire_local, retire_threaded;
        {
            std::lock_guard lock(mutex);
            if (next <= generation.load(std::memory_order_relaxed)) return false;
            auto it = std::remove_if(entries.begin(), entries.end(), [&](Entry const& e) {
                if (e.generation >= next) return false;
                (e.threaded ? retire_threaded : retire_local).push_back(e);
                return true;
            });
            entries.erase(it, entries.end());
        }
        for (auto const& e : retire_local) e.server->retire_acceptor();
        if (!retire_threaded.empty()) {
            struct Quiesce {
                std::mutex m; std::condition_variable cv; std::size_t pending = 0;
                auto done() noexcept -> void { std::lock_guard lk(m); if (pending && --pending == 0) cv.notify_one(); }
                static auto retire_task(Server* srv, std::shared_ptr<Quiesce> st) -> capy::task<> { srv->retire_acceptor(); st->done(); co_return; }
            };
            auto state = std::make_shared<Quiesce>();
            state->pending = retire_threaded.size();
            for (auto const& e : retire_threaded) {
                capy::run_async(e.server->context.get_executor(), [] {}, [state](std::exception_ptr) noexcept { state->done(); })(Quiesce::retire_task(e.server, state));
            }
            std::unique_lock lk(state->m);
            state->cv.wait_for(lk, 500ms, [&] { return state->pending == 0; });
        }
        std::lock_guard lock(mutex);
        if (next <= generation.load(std::memory_order_relaxed)) return false;
        prepare();
        generation.store(next, std::memory_order_release);
        return true;
    }

    auto Server::RetainedListener::close() noexcept -> void { if (fd>=0) ::close(std::exchange(fd,-1)); }

    auto Server::accept_loop() -> capy::task<> {
        auto dispatch_peer = [&](io::tcp_socket&& accepted) {
            if (shedding_memory()) return;
            auto lease = quota.try_acquire();
            if (!lease) return;
            auto session = std::make_unique<Session>(context);
            session->client = std::move(accepted);
#if defined(__linux__)
            platform::enable_tcp_quickack(session->client.native_handle());
#else
            platform::tune_tcp_low_latency(session->client.native_handle());
#endif
            session->udp_advertise = udp_advertise;
            attach_session(*session, std::move(*lease));
#ifdef NEXUS_TEST_ROOT_LAUNCH
            nexus_test_root_launch(0);
#endif
            auto launch = [&]() -> capy::task<> {
#ifdef NEXUS_TEST_ROOT_LAUNCH
                struct RestoreFrameAllocator { std::pmr::memory_resource* previous; ~RestoreFrameAllocator() { capy::set_current_frame_allocator(previous); } } restore{capy::get_current_frame_allocator()};
                nexus_test_root_launch(1);
#endif
                return serve_session(std::move(session));
            };
            bool custom_inbound = false;
#ifdef NEXUS_ENABLE_SNELL
            custom_inbound |= inbound_type == Inbound::snell;
#endif
#ifdef NEXUS_ENABLE_ANYTLS
            custom_inbound |= inbound_type == Inbound::anytls;
#endif
#ifdef NEXUS_ENABLE_SHADOWTLS
            custom_inbound |= inbound_type == Inbound::shadowtls;
#endif
#ifdef NEXUS_ENABLE_TROJAN
            custom_inbound |= inbound_type == Inbound::trojan;
#endif
#ifdef NEXUS_ENABLE_VLESS
            custom_inbound |= inbound_type == Inbound::vless;
#endif
#ifdef NEXUS_ENABLE_SS2022
            custom_inbound |= inbound_type == Inbound::shadowsocks;
#endif
#ifdef NEXUS_ENABLE_NAIVE
            custom_inbound |= inbound_type == Inbound::naive || (inbound_type == Inbound::http && (http_modern_tcp_enabled || borrowed_http_modern_inbound));
#endif
            if (custom_inbound) { capy::run_async(context.get_executor(), [] {}, session_error(*session))(launch()); return; }
#ifdef NEXUS_TEST_ROOT_LAUNCH
            capy::run_async(context.get_executor(), session->stop.get_token(), nexus_test_root_resource(), [] {}, session_error(*session))(launch());
#else
            capy::run_async(context.get_executor(), session->stop.get_token(), [] {}, session_error(*session))(launch());
#endif
        };

        auto cleanup = [&]() noexcept { staged_listener.close(); if (admission) admission->detach(this); };
        if (admission) {
            while (accepting) {
                auto published = admission->generation.load(std::memory_order_acquire);
                if (published > listener_generation) { cleanup(); accepting = false; co_return; }
                if (published == listener_generation) break;
                auto [delay_error] = co_await io::delay(1ms);
                if (delay_error) {
                    if (accepting) { record_failure({FailureKind::accept, delay_error}); running = false; }
                    cleanup(); accepting = false; co_return;
                }
            }
            if (!accepting) { cleanup(); co_return; }
            if (int fd = std::exchange(staged_listener.fd, -1); fd >= 0) {
                if (auto error = listener->assign(fd)) {
                    ::close(fd);
                    if (accepting) { record_failure({FailureKind::accept, error}); running = false; }
                    cleanup(); accepting = false; co_return;
                }
            }
        }
        while (accepting) {
            if (admission && admission->generation.load(std::memory_order_acquire) != listener_generation) break;
            auto [error, accepted] = co_await listener->accept();
            if (!error && accepting) {
                if (!admission || admission->generation.load(std::memory_order_acquire) == listener_generation)
                    dispatch_peer(std::move(accepted));
                continue;
            }
            if (!accepting) break;
            if (transient_accept_error(error)) {
                auto [delay_error] = co_await io::delay(10ms);
                if (delay_error && accepting) record_failure({FailureKind::accept, delay_error});
                if (delay_error || !accepting) break;
                continue;
            }
            if (error) { if (running) record_failure({FailureKind::accept, error}); break; }
        }
        cleanup();
        if (accepting) { running = false; if (listener) listener->close(); }
        accepting = false;
    }

    auto Server::enable_transparent_udp() noexcept -> bool {
#ifdef NEXUS_TPROXY_UDP
        if (running) return false;
        transparent_datagrams=true;
        return true;
#else
        return false;
#endif
    }

    auto Server::start_one(io::endpoint endpoint,Inbound inbound,bool reuse,int shared_fd,bool threaded)
        -> std::expected<std::uint16_t,std::error_code> {
        if(!listener)return std::unexpected(std::make_error_code(std::errc::operation_not_supported));
        if(ordered_tcp && inbound!=Inbound::socks5 && inbound!=Inbound::mixed && inbound!=Inbound::http && inbound!=Inbound::naive && inbound!=Inbound::fixed_tcp && inbound!=Inbound::trojan && inbound!=Inbound::anytls && inbound!=Inbound::vless && inbound!=Inbound::shadowsocks && inbound!=Inbound::redirect && inbound!=Inbound::tproxy)
            return std::unexpected(std::make_error_code(std::errc::operation_not_supported));
#ifdef NEXUS_ENABLE_SNELL
        if(inbound==Inbound::snell && !(borrowed_snell_inbound ? *borrowed_snell_inbound : snell_inbound)) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
#else
        if(inbound==Inbound::snell) return std::unexpected(std::make_error_code(std::errc::operation_not_supported));
#endif
#ifdef NEXUS_ENABLE_ANYTLS
        if (inbound==Inbound::anytls && !(borrowed_anytls_inbound ? *borrowed_anytls_inbound : anytls_inbound)) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
#else
        if (inbound==Inbound::anytls) return std::unexpected(std::make_error_code(std::errc::operation_not_supported));
#endif
#ifdef NEXUS_ENABLE_SHADOWTLS
        if (inbound==Inbound::shadowtls && !(borrowed_shadowtls_inbound ? *borrowed_shadowtls_inbound : shadowtls_inbound)) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
#else
        if (inbound==Inbound::shadowtls) return std::unexpected(std::make_error_code(std::errc::operation_not_supported));
#endif
#ifdef NEXUS_ENABLE_TROJAN
        if (inbound==Inbound::trojan && !(borrowed_trojan_inbound ? *borrowed_trojan_inbound : trojan_inbound)) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
#else
        if (inbound==Inbound::trojan) return std::unexpected(std::make_error_code(std::errc::operation_not_supported));
#endif
        if (this->running || (this->listener && this->listener->is_open()) || !this->sessions.empty())
            return std::unexpected(std::make_error_code(std::errc::operation_in_progress));
#ifdef NEXUS_ENABLE_VLESS
        if (inbound==Inbound::vless && !(borrowed_vless_inbound ? *borrowed_vless_inbound : vless_inbound)) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
#else
        if (inbound==Inbound::vless) return std::unexpected(std::make_error_code(std::errc::operation_not_supported));
#endif
#ifdef NEXUS_ENABLE_SS2022
        if (inbound==Inbound::shadowsocks && !(borrowed_shadowsocks_inbound ? *borrowed_shadowsocks_inbound : shadowsocks_inbound)) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
#else
        if (inbound==Inbound::shadowsocks) return std::unexpected(std::make_error_code(std::errc::operation_not_supported));
#endif
#ifdef NEXUS_ENABLE_NAIVE
        if (inbound==Inbound::naive && naive_tcp_enabled && !(borrowed_naive_inbound ? *borrowed_naive_inbound : naive_inbound)) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        if (inbound==Inbound::http && http_modern_tcp_enabled && !(borrowed_http_modern_inbound ? *borrowed_http_modern_inbound : http_modern_inbound)) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
#else
        if (inbound==Inbound::naive) return std::unexpected(std::make_error_code(std::errc::operation_not_supported));
#endif
        if (inbound==Inbound::fixed_tcp) {
            if (!fixed_tcp_target && fixed_unix_target.empty()) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
            if (fixed_tcp_target && fixed_tcp_target->port==endpoint.port()) {
                auto const& target=*fixed_tcp_target;
                auto bytes=std::span(target.address).first(target.address_length);
                auto same_address=endpoint.is_v6() ?
                    target.address_type==4 && std::ranges::equal(bytes,endpoint.address().to_v6().to_bytes()) :
                    target.address_type==1 && std::ranges::equal(bytes,endpoint.address().to_v4().to_bytes());
                if (same_address) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
            }
        }
        if (credentials) {
            auto username=std::span(credentials->username).first(credentials->username_size);
            if ((inbound!=Inbound::socks5 && inbound!=Inbound::mixed && inbound!=Inbound::http) ||
                (inbound!=Inbound::socks5 && std::ranges::find(username,':')!=username.end()))
                return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        }
        struct Startup {
            Server& owner; bool done=false;
            ~Startup() {
                if (done) return;
                owner.staged_listener.close();
                if (owner.admission) owner.admission->detach(&owner);
                if (owner.shared_context) { owner.stop(); return; }
                owner.running=false;
#ifdef NEXUS_TPROXY_UDP
                owner.stop_transparent_udp();
#endif
                owner.stop_outbound_contexts();
                owner.context.restart(); (void)owner.context.run();
                owner.finish_outbound_contexts();
#ifdef NEXUS_TPROXY_UDP
                owner.transparent_udp.reset();
#endif
            }
        } startup{*this};
        if(auto active=activate_context();!active)return std::unexpected(active.error());
        auto bind_listener=[&]() -> std::error_code {
            auto ipv6=endpoint.address().is_v6();
            if (auto error=listener->open(ipv6 ? io::family::v6 : io::family::v4)) return error;
            if (admission) {
                int enabled=1;
                if (::setsockopt(listener->native_handle(),SOL_SOCKET,SO_REUSEADDR,&enabled,sizeof(enabled))<0)
                    return {errno,std::generic_category()};
            }
#if defined(__linux__)
            // Inherited by accepted child sockets on Linux; avoids per-accept setsockopt.
            int nodelay = 1;
            (void)::setsockopt(listener->native_handle(), IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
#ifdef TCP_USER_TIMEOUT
            std::uint32_t user_timeout = 20000;
            (void)::setsockopt(listener->native_handle(), IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout, sizeof(user_timeout));
#endif
#endif
            if (inbound==Inbound::tproxy) {
#if defined(IP_TRANSPARENT) && defined(IPV6_TRANSPARENT)
                int enabled=1;
                if (::setsockopt(listener->native_handle(),ipv6 ? IPPROTO_IPV6 : IPPROTO_IP,
                    ipv6 ? IPV6_TRANSPARENT : IP_TRANSPARENT,&enabled,sizeof(enabled))<0)
                    return {errno,std::generic_category()};
#else
                return std::make_error_code(std::errc::operation_not_supported);
#endif
            }
            if (redirect_socket_mark) {
#if defined(SO_MARK)
                if (::setsockopt(listener->native_handle(),SOL_SOCKET,SO_MARK,
                        &*redirect_socket_mark,sizeof(std::uint32_t))<0)
                    return {errno,std::generic_category()};
#else
                return std::make_error_code(std::errc::operation_not_supported);
#endif
            }
            if (ipv6)
                if (auto error=listener->set_option(corosio::socket_option::v6_only(!tun_redirect_dual_stack))) return error;
            if (reuse)
                if (auto error=listener->set_option(corosio::socket_option::reuse_port(true))) return error;
            return listener->bind(endpoint);
        };
        if (shared_fd<0) {
            if (auto error=bind_listener()) {
                listener->close();
                return std::unexpected(error);
            }
            endpoint=listener->local_endpoint();
        }
        if (admission) {
            // Keep fd staged until generation is published so io_uring multishot
            // accept does not steal connections from the previous generation.
            RetainedListener socket;
            if (shared_fd>=0) {
                socket.fd=::fcntl(shared_fd,F_DUPFD_CLOEXEC,0);
                if (socket.fd<0) return std::unexpected(std::error_code(errno,std::generic_category()));
            } else {
                auto [error,fd]=listener->release();
                if (error) return std::unexpected(error);
                socket.fd=fd;
                if (::listen(fd,SOMAXCONN)<0)
                    return std::unexpected(std::error_code(errno,std::generic_category()));
            }
            staged_listener=std::move(socket);
            admission->attach(listener_generation,this,threaded);
        } else if (auto error=listener->listen(SOMAXCONN)) {
            listener->close(); return std::unexpected(error);
        }
        this->inbound_type = inbound;
        bound_listener = endpoint;
        auto const bound_port = bound_listener.port();
#ifdef NEXUS_TPROXY_UDP
        if (inbound==Inbound::tproxy && transparent_datagrams) {
            if (auto error=start_transparent_udp(bound_listener,reuse)) {
                listener->close();
                return std::unexpected(error);
            }
        }
#endif
        this->running = true;
        sessions.reserve(64);
        accepting = true;
        accept_task_active = true;
        try {
#ifdef NEXUS_TEST_START_THROW
            nexus_test_start_throw();
#endif
            capy::run_async(this->context.get_executor(), [state=this]() noexcept { state->accept_task_active=false; },
                [state=this](std::exception_ptr) noexcept {
                try { state->record_failure({FailureKind::accept_task,{}}); } catch (...) {}
                state->running=false; state->accepting=false; state->accept_task_active=false; state->close_listener();
            })(this->accept_loop());
        } catch (...) {
            this->running=false; accepting=false; accept_task_active=false; close_listener(); throw;
        }
        startup.done=true;
        return bound_port;
    }

    auto Server::start_tun_redirect(bool ipv4,bool ipv6,bool dns) -> std::expected<std::uint16_t,std::error_code> {
        listener.emplace(context);
        tun_redirect_dual_stack=ipv4 && ipv6;
        redirect_tcp_dns=dns;
        redirect_socket_mark=direct_tcp_options.binding.routing_mark;
        return start(0,Inbound::redirect,1,ipv6,std::array<std::uint8_t,16>{});
    }

    auto Server::start(std::uint16_t port,Inbound inbound,unsigned count,bool ipv6,
        std::optional<std::array<std::uint8_t,16>> address) -> std::expected<std::uint16_t,std::error_code> {
        if (address && !ipv6 && std::ranges::any_of(std::span(*address).subspan(4),[](auto byte){return byte!=0;}))
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        return start_listeners(listener_endpoint(port,ipv6,address),inbound,count,nullptr);
    }

    auto Server::stage_tcp(std::shared_ptr<TcpAdmission> gate,std::uint64_t generation,
        std::uint16_t port,Inbound inbound,unsigned count,bool ipv6,
        std::optional<std::array<std::uint8_t,16>> address,Server const* previous)
        -> std::expected<std::uint16_t,std::error_code> {
        if (running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty())
            return std::unexpected(std::make_error_code(std::errc::operation_in_progress));
        if (!gate || generation<=gate->generation.load(std::memory_order_acquire) ||
            (address && !ipv6 && std::ranges::any_of(std::span(*address).subspan(4),[](auto byte){return byte!=0;})))
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
#ifdef NEXUS_TPROXY_UDP
        if (transparent_datagrams) return std::unexpected(std::make_error_code(std::errc::operation_not_supported));
#endif
        auto endpoint=listener_endpoint(port,ipv6,address);
        if (previous && (previous==this || previous->admission!=gate || !previous->healthy() ||
            previous->bound_listener!=endpoint || previous->retained_listeners.size()!=count ||
            std::ranges::any_of(previous->retained_listeners,[](auto const& r) { return r.fd<0; }) ||
            ((previous->inbound_type==Inbound::tproxy)!=(inbound==Inbound::tproxy))))
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        admission=std::move(gate);
        listener_generation=generation;
        struct Rollback {
            Server& server;
            bool committed=false;
            ~Rollback() {if (!committed) server.stop();}
        } rollback{*this};
        auto staged=start_listeners(endpoint,inbound,count,previous);
        rollback.committed=staged.has_value();
        return staged;
    }

    auto Server::start_listeners(io::endpoint endpoint,Inbound inbound,unsigned count,Server const* previous)
        -> std::expected<std::uint16_t,std::error_code> {
        auto& state=*this;
        if (state.running || (state.listener && state.listener->is_open()) || !state.sessions.empty() || !state.workers.empty())
            return std::unexpected(std::make_error_code(std::errc::operation_in_progress));
#ifdef NEXUS_ENABLE_VLESS
        if (inbound==Inbound::vless && vless_xhttp_inbound && count!=1)
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
#endif
        bool xhttp_listener=false;
#ifdef NEXUS_ENABLE_XHTTP_VLESS
        xhttp_listener=inbound==Inbound::vless && vless_xhttp_inbound;
#endif
        bool want_h3_only=false, want_dual_h3=false;
#ifdef NEXUS_ENABLE_NAIVE
        want_h3_only=(inbound==Inbound::naive && naive_h3_enabled && !naive_tcp_enabled) ||
                     (inbound==Inbound::http && http_modern_h3_enabled && !http_modern_tcp_enabled);
        want_dual_h3=(inbound==Inbound::naive && naive_h3_enabled && naive_tcp_enabled) ||
                     (inbound==Inbound::http && http_modern_h3_enabled && http_modern_tcp_enabled);
        if ((want_h3_only || want_dual_h3) && count!=1) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
#endif
        if (!count || (shared_context && count!=1) ||
            (endpoint.address().is_v6() && !xhttp_listener && inbound!=Inbound::socks5 && inbound!=Inbound::mixed && inbound!=Inbound::http && inbound!=Inbound::naive && inbound!=Inbound::fixed_tcp && inbound!=Inbound::fixed_udp && inbound!=Inbound::trojan && inbound!=Inbound::anytls && inbound!=Inbound::snell && inbound!=Inbound::shadowtls && inbound!=Inbound::redirect && inbound!=Inbound::tproxy))
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        drain_requested.store(false,std::memory_order_relaxed); drain_complete.store(false,std::memory_order_relaxed);
        if(auto prepared=prepare_routing(count);!prepared)return std::unexpected(prepared.error());
        if (inbound==Inbound::fixed_udp) return start_fixed_udp(endpoint);
#ifdef NEXUS_ENABLE_XHTTP_VLESS
        if (xhttp_listener && xhttp3_inbound) return start_xhttp3(endpoint);
#endif
#ifdef NEXUS_ENABLE_NAIVE
        if (want_h3_only) { auto h3_port=start_modern_h3(endpoint); if (h3_port) inbound_type=inbound; return h3_port; }
#endif
        auto start_worker=[&](Server& worker, int shared_fd, bool threaded) -> std::expected<std::uint16_t,std::error_code> {
            worker.admission=admission; worker.listener_generation=listener_generation;
            auto result=worker.start_one(endpoint,inbound,count>1,shared_fd,threaded);
            if (result && admission) {
                auto fd=::fcntl(worker.staged_listener.fd,F_DUPFD_CLOEXEC,0);
                if (fd<0) return std::unexpected(std::error_code(errno,std::generic_category()));
                retained_listeners.emplace_back(fd);
            }
            return result;
        };
        if (count==1) {
            int shared_fd=(previous && !previous->retained_listeners.empty()) ? previous->retained_listeners[0].fd : -1;
            auto tcp_port=start_worker(*this,shared_fd,false);
#ifdef NEXUS_ENABLE_NAIVE
            if (tcp_port && want_dual_h3) {
                if (auto h3_port=start_modern_h3(io::endpoint(endpoint.address(),*tcp_port)); !h3_port) { stop(); return std::unexpected(h3_port.error()); }
            }
#endif
            return tcp_port;
        }
        state.stopping=false; state.failed=false;
        auto bound=endpoint.port();
        try {
#if !defined(NEXUS_DNS_SHARED) && !defined(NEXUS_TEST_DNS_GROUP)
            if (state.dns_routing && !state.dns) state.dns=std::make_unique<DnsState>(*state.dns_routing);
#endif
            retained_listeners.reserve(count);
            for (unsigned i=0;i<count;++i) {
                auto worker=std::make_unique<Server>();
                worker->splice_max_idle_pipes=std::max<std::size_t>(2,(SplicePipePool::kMaxIdlePipes*2)/count);
                worker->inherit_routing(state,i,count);
                int shared_fd=(previous && i<previous->retained_listeners.size()) ? previous->retained_listeners[i].fd : -1;
                auto result=start_worker(*worker,shared_fd,true);
                if (!result) { state.workers.clear(); retained_listeners.clear(); return std::unexpected(result.error()); }
                bound=*result; endpoint=io::endpoint(endpoint.address(),bound);
                state.workers.push_back(std::move(worker));
            }
            state.bound_listener=endpoint; state.inbound_type=inbound; state.running=true;
            for (auto& worker : state.workers) state.threads.emplace_back([&state,ptr=worker.get()] { state.run_worker_thread(ptr); });
        } catch (std::system_error const& error) { stop(); return std::unexpected(error.code()); }
        catch (...) { stop(); throw; }
        return bound;
    }
}
