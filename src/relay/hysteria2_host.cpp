module relay.hysteria2_host;
import std;
import corosio;
import ngtcp2;
namespace relay {
auto Hysteria2Host::Worker::inherit(Server& routing,Server& parent,std::size_t index,std::size_t count,std::span<hysteria2::Password const> passwords,std::span<std::string const> names) -> Hysteria2Business {
    routing.inherit_routing(parent,index,count);return Hysteria2Business{routing,passwords,names};
}
Hysteria2Host::Worker::Worker(Server& parent,std::size_t index,std::size_t count,std::span<hysteria2::Password const> passwords,std::span<std::string const> names,tls::ServerCredential const& credential,hysteria2::TransportOptions options) :hooks(inherit(routing,parent,index,count,passwords,names)),listener(routing.executor_context(),hooks,credential,options) {
    hooks.udp_enabled=options.udp;hooks.listener=&listener;
}
Hysteria2Host::Worker::~Worker() {listener.stop();routing.stop();listener.maintain();}
auto Hysteria2Host::record(Hysteria2RuntimeFailure value) noexcept -> void {
    std::lock_guard lock(failure_mutex_);if(!failure_)failure_=std::move(value);failed_.store(true,std::memory_order_release);
}
auto Hysteria2Host::failure() const -> std::optional<Hysteria2RuntimeFailure> {std::lock_guard lock(failure_mutex_);return failure_;}
auto Hysteria2Host::loop(Worker& worker) noexcept -> void {
    auto capture=[&] {
        if(auto const& failure=worker.listener.failure();failure){Hysteria2RuntimeFailure out{Hysteria2RuntimeFailure::Kind::driver};
            std::visit([&](auto const& outer){using T=std::decay_t<decltype(outer)>;
                if constexpr(std::same_as<T,net::DatagramFailure>)out.driver=outer;
                else std::visit([&](auto const& inner){using V=std::decay_t<decltype(inner)>;if constexpr(std::same_as<V,quic::DatagramPortError>)out.port=inner;else out.retry=inner;},outer);
            },*failure);record(std::move(out));return;}
        if(auto const& failure=worker.listener.runtime_failure();failure){record({Hysteria2RuntimeFailure::Kind::callback,{},{},{},{},failure->exception});return;}
        if(auto const& failure=worker.listener.initialization_failure();failure){Hysteria2RuntimeFailure out{Hysteria2RuntimeFailure::Kind::initialization};out.native=failure->native;
            if(out.native==ngtcp2::err_nomem || out.native==ngtcp2::err_callback_failure)record(std::move(out));return;}
        if(auto failure=worker.listener.shutdown_failure()){Hysteria2RuntimeFailure out{Hysteria2RuntimeFailure::Kind::close};out.native=*failure;record(std::move(out));return;}
        if(worker.hooks.udp_failure()){Hysteria2RuntimeFailure out{Hysteria2RuntimeFailure::Kind::udp};out.native=worker.hooks.udp_error;out.system=worker.hooks.udp_system;out.exception=worker.hooks.udp_exception;record(std::move(out));}
    };
    try {
        auto& context=worker.routing.executor_context();
        while(!stop_.load(std::memory_order_acquire)) {
            worker.routing.start_pending_probe();
            context.run_for(std::chrono::milliseconds(20));
            worker.routing.maintain_dns_transports();
            worker.routing.process_traffic_closes();worker.hooks.maintain_udp();worker.listener.maintain();capture();if(!healthy())break;
        }
        worker.listener.begin_shutdown();auto deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(250);
        while(!worker.listener.shutdown_drained() && !worker.listener.failure() && std::chrono::steady_clock::now()<deadline) {context.run_for(std::chrono::milliseconds(10));worker.hooks.maintain_udp();worker.listener.maintain();}
        capture();if(!worker.listener.shutdown_drained() || worker.listener.shutdown_unsent())record({Hysteria2RuntimeFailure::Kind::timeout});
        worker.listener.stop();context.restart();while(!worker.listener.drained()) {context.run_for(std::chrono::milliseconds(20));worker.hooks.maintain_udp();worker.listener.maintain();}
        if(!worker.listener.clean())record({Hysteria2RuntimeFailure::Kind::unexpected});worker.routing.stop();
    } catch(...) {Hysteria2RuntimeFailure failure{Hysteria2RuntimeFailure::Kind::unexpected};failure.exception=std::current_exception();record(std::move(failure));worker.listener.stop();worker.routing.stop();}
}

Hysteria2Host::Hysteria2Host(Server& parent,tls::ServerCredential const& credential,std::span<hysteria2::Password const> passwords,std::span<std::string const> names,hysteria2::TransportOptions options) :parent_(parent),credential_(credential),passwords_(passwords),names_(names),options_(options) {}
Hysteria2Host::~Hysteria2Host() {stop();}
auto Hysteria2Host::start(std::uint16_t port,bool ipv6,unsigned count) -> std::expected<std::uint16_t,Hysteria2HostFailure> {
            auto local=ipv6 ? corosio::endpoint(corosio::ipv6_address::loopback(),port) :
                corosio::endpoint(corosio::ipv4_address::loopback(),port);
            return start(local,count);
        }
auto Hysteria2Host::start(corosio::endpoint local,unsigned count) -> std::expected<std::uint16_t,Hysteria2HostFailure> {
            if(!workers_.empty() || !count || count>16 || passwords_.empty() || passwords_.size()!=names_.size())
                return std::unexpected(Hysteria2HostFailure{std::make_error_code(std::errc::invalid_argument)});
            auto prepared=parent_.prepare_routing(count,true);if(!prepared)return std::unexpected(Hysteria2HostFailure{prepared.error()});
            stop_=false;failed_=false;{std::lock_guard lock(failure_mutex_);failure_.reset();}std::uint16_t bound=local.port();
            try {
                for(unsigned i=0;i<count;++i) {
                    auto worker=std::make_unique<Worker>(parent_,i,count,passwords_,names_,credential_,options_);
                    auto activated=worker->routing.activate_context();if(!activated)throw std::system_error(activated.error());
                    auto endpoint=corosio::endpoint(local,bound);
                    auto result=worker->listener.prepare(endpoint,count>1);
                    if(!result) {
                        auto error=std::visit([](auto const& value)->Hysteria2HostFailure{return value;},result.error());
                        stop();return std::unexpected(error);
                    }
                    bound=result->port();workers_.push_back(std::move(worker));
                }
                for(auto& worker:workers_)worker->listener.start();
                for(auto& worker:workers_)threads_.emplace_back([this,ptr=worker.get()]{loop(*ptr);});
            } catch(...) {auto error=std::current_exception();stop();return std::unexpected(Hysteria2HostFailure{error});}
            return bound;
        }
auto Hysteria2Host::stop() noexcept -> void {
            stop_.store(true,std::memory_order_release);
            for(auto& thread:threads_)if(thread.joinable())thread.join();
            for(std::size_t i=threads_.size();i<workers_.size();++i)loop(*workers_[i]);
            threads_.clear();workers_.clear();parent_.stop();
        }
}
