module endpoint.bootstrap;
import std;
import endpoint.config;
import net.udp_socket;
import platform.netlink_abi;
import endpoint.credentials;
import endpoint.process_signals;
import dns.local_config;
import dns.corosio_local;
import capy;
import corosio;

namespace endpoint {
    namespace {
        using Clock=std::chrono::steady_clock;
        namespace io = ::corosio;
        namespace capy = ::capy;
        namespace local=dns::detail;
        auto strategy(AddressStrategy input) noexcept -> local::AddressStrategy {
            switch(input) {
            case AddressStrategy::prefer_ipv4:return local::AddressStrategy::prefer_ipv4;
            case AddressStrategy::prefer_ipv6:return local::AddressStrategy::prefer_ipv6;
            case AddressStrategy::ipv4_only:return local::AddressStrategy::ipv4_only;
            case AddressStrategy::ipv6_only:return local::AddressStrategy::ipv6_only;
            }
            std::terminate();
        }
        // One temporary initialization context for the whole immutable batch.
        // DNS is the existing local resolver, including search/hosts/TCP fallback.
        // A direct optional resolver remains alive through cancellation and join.
        struct Batch {
            io::io_context& context;
            Wireguard const& config;
            Prepared& material;
            dns::LocalSnapshot const& snapshot;
            Clock::time_point deadline;
            std::optional<io::local_stream_socket> wake_reader,wake_writer;
            std::optional<process::WakeRegistration> notification;
            std::optional<local::LocalAddressResolver> active;
            std::expected<void,std::string> result;
            std::exception_ptr exception;
            bool done=false,joined=false;
            Batch(io::io_context& ctx,Wireguard const& cfg,Prepared& keys,dns::LocalSnapshot const& settings,Clock::time_point until)
                :context(ctx),config(cfg),material(keys),snapshot(settings),deadline(until) {}
            auto resolve() -> capy::task<capy::results<>> {
                struct Done { Batch& self; ~Done(){self.done=true;} } completion{*this};
                try {
                    for (std::size_t i=0;i<config.peers.size();++i) {
                        auto const& peer=config.peers[i];
                        if (!peer.server || peer.server->numeric) continue;
                        if (process::StopRequested{}()) {result=std::unexpected("endpoint startup canceled");break;}
                        if (Clock::now()>=deadline) {result=std::unexpected("endpoint startup deadline expired");break;}
                        active.emplace(context,snapshot.config,snapshot.hosts,strategy(peer.strategy.value_or(AddressStrategy::prefer_ipv4)));
                        auto addresses=co_await active->resolve(peer.server->host,deadline);
                        active.reset();
                        if (process::StopRequested{}()) {result=std::unexpected("endpoint startup canceled");break;}
                        if (!addresses) {
                            result=std::unexpected(addresses.error()==local::ResolveError::timeout ? "endpoint startup deadline expired" :
                                "peer "+peer.name+" local bootstrap failed");break;
                        }
                        std::optional<net::UdpEndpoint> selected;
                        for (auto const& address:*addresses) {
                            if (address.size!=4 && address.size!=16) continue;
                            net::UdpEndpoint candidate{address.size==4 ? std::uint8_t{4}:std::uint8_t{6},address.bytes,peer.server->port};
                            if (outer_allowed(config,candidate)) {selected=candidate;break;}
                        }
                        if (!selected) {result=std::unexpected("peer "+peer.name+" local bootstrap has no uncaptured usable address");break;}
                        material.peers[i].selected=*selected;
                    }
                } catch(std::bad_alloc const&) {result=std::unexpected("endpoint local bootstrap out of memory");}
                catch(std::exception const&) {result=std::unexpected("endpoint local bootstrap failed");}
                co_return capy::results<>{};
            }
            auto signal() -> capy::task<capy::results<>> {
                if(done || process::StopRequested{}()) {if(active && !done)active->cancel();co_return capy::results<>{};}
                std::array<char,1> byte{};
                auto [error,size]=co_await wake_reader->read_some(capy::mutable_buffer(byte.data(),byte.size()));
                if(process::StopRequested{}() && active)active->cancel();
                if(done || process::StopRequested{}())co_return capy::results<>{};
                co_return capy::results<>{error || size==1 ? error : std::make_error_code(std::errc::io_error)};
            }
            auto run() -> capy::task<> {
                try {
                    auto [error,input,notification]=co_await capy::when_all(resolve(),signal());
                    (void)input;(void)notification;
                    if(error && result) result=std::unexpected("endpoint local bootstrap join failed");
                } catch(...) {
                    // Exceptions from child task/when_all startup resume here,
                    // before returning to the process-published root. Retain
                    // only exception_ptr; allocating an error string may fail.
                    exception=std::current_exception();done=true;
                }
                joined=true;
            }
        };
    }
    auto bootstrap(Wireguard const& config,Prepared& material,Clock::time_point deadline,process::Signals& signals,bool use_uring) -> std::expected<void,std::string> {
        if (process::StopRequested{}()) return std::unexpected("endpoint startup canceled");
        if (Clock::now()>=deadline) return std::unexpected("endpoint startup deadline expired");
        if (!std::ranges::any_of(config.peers,[](auto const& peer){return peer.server && !peer.server->numeric;})) return {};
        auto snapshot=dns::load_local_snapshot("/etc/resolv.conf","/etc/hosts");
        if(!snapshot) return std::unexpected("cannot read static local resolver snapshot");
        // Declaration order also retains resolver owners if context teardown
        // must abandon a launch that threw before its root was published.
        std::optional<Batch> batch;
        auto context=io::make_io_context(use_uring);
        batch.emplace(context,config,material,*snapshot,deadline);
        bool launched=false,restored=true;
        auto cleanup=[&]() {
            process::SignalMask transition;
            if(!transition.active()) restored=false;
            // Disable publication before cancellation/close; a pending signal
            // later reaches the unchanged handler with no borrowed fd.
            batch->notification.reset();
            if(batch->active) batch->active->cancel();
            if(batch->wake_reader)batch->wake_reader->cancel();
            if(launched) {context.restart();context.run();}
            // Joining ends every borrow. Release concrete DNS socket owners
            // before context shutdown; no live implementation needs pinning.
            batch->active.reset();
            batch->wake_reader.reset();batch->wake_writer.reset();
            // Native epoll readiness can retain a closed implementation after
            // the last coroutine work guard is released. Keep work while a
            // nonblocking reactor pass drains those scheduler-owned references.
            auto executor=context.get_executor();executor.on_work_started();
            struct Work { decltype(executor)& value; ~Work(){value.on_work_finished();} } work{executor};
            context.restart();context.poll();
            restored=signals.restore_handlers() && restored;
        };
        try {
            {
                process::SignalMask transition;
                if(!transition.active()) return std::unexpected("cannot mask bootstrap signal transition");
                batch->wake_reader.emplace(context);batch->wake_writer.emplace(context);
                auto error=io::connect_pair(*batch->wake_reader,*batch->wake_writer);
                if(error){cleanup();return std::unexpected("cannot create bootstrap signal wake pair");}
                batch->notification.emplace(batch->wake_writer->native_handle());
                if(!batch->notification->active()){cleanup();return std::unexpected("cannot attach bootstrap signal wake");}
            }
            capy::run_async(context.get_executor())(batch->run());launched=true;
            while(!batch->done) {context.restart();context.run_one();}
            cleanup();
        } catch(...) {
            try {cleanup();} catch(...) {(void)signals.restore_handlers();}
            throw;
        }
        if(!restored) return std::unexpected("cannot restore endpoint stop handlers");
        if(!batch->joined) return std::unexpected("endpoint local bootstrap did not join");
        if(batch->exception) std::rethrow_exception(batch->exception);
        if(process::StopRequested{}()) return std::unexpected("endpoint startup canceled");
        if(Clock::now()>=deadline) return std::unexpected("endpoint startup deadline expired");
        return std::move(batch->result);
    }
}
