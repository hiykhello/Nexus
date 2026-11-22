module;
#include <sys/socket.h>
#include <netinet/in.h>
#include <cstring>
#include <cerrno>

module dns.message_tcp_listener;
import std;
import dns.message_tcp;
import dns.message_program;
import dns.message_cache;
import dns.policy;
import rules;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

namespace dns {
    // Executor-owned listener. Stop cancels all borrowers; destruction is
    // permitted only after the accept task and every connection have joined.
    struct MessageTcpListener::Impl {
        using Clock=std::chrono::steady_clock;
        struct Slot {
            nex::corosio::tcp_socket socket;
            MessageTcpConnection connection;
            std::array<std::uint8_t,16> source{};
            std::uint8_t source_size=0;std::uint16_t source_port=0;
            bool active=true;
            Slot(nex::corosio::tcp_socket peer,nex::corosio::io_context& context,std::span<policy::DnsRule const> rules,
                std::span<MessageUpstream const> upstreams,std::size_t fallback,MessageCache* cache,bool disable_cache,InputBudget* input_budget,InputBudget* query_budget,MessageRuleSource const& rule_source)
                :socket(std::move(peer)),connection(socket,context,rules,upstreams,fallback,cache,disable_cache,input_budget,query_budget,&rule_source) {
                sockaddr_storage address{};
                socklen_t size=sizeof(address);
                if (::getpeername(socket.native_handle(),reinterpret_cast<sockaddr*>(&address),&size)<0) return;
                if (address.ss_family==AF_INET && size>=sizeof(sockaddr_in)) {
                    auto const& remote=reinterpret_cast<sockaddr_in const&>(address);
                    source_size=4;
                    source_port=ntohs(remote.sin_port);
                    std::memcpy(source.data(),&remote.sin_addr,source_size);
                } else if (address.ss_family==AF_INET6 && size>=sizeof(sockaddr_in6)) {
                    auto const& remote=reinterpret_cast<sockaddr_in6 const&>(address);
                    source_size=16;
                    source_port=ntohs(remote.sin6_port);
                    std::memcpy(source.data(),&remote.sin6_addr,source_size);
                }
            }
            auto stop() noexcept -> void {connection.cancel();socket.close();}
        };
        nex::corosio::io_context& context_;
        nex::corosio::tcp_acceptor acceptor_;
        std::span<policy::DnsRule const> rules_;
        std::span<MessageUpstream const> upstreams_;
        std::size_t fallback_,limit_,max_requests_;
        MessageCache* cache_;bool disable_cache_;InputBudget* input_budget_;InputBudget* query_budget_;
        std::chrono::milliseconds timeout_;
        MessageRuleSource source_;
        std::vector<std::unique_ptr<Slot>> slots_;
        bool started_=false,stopped_=false,admitting_=false,accepting_=false;
        std::exception_ptr failure_;std::error_code io_failure_;
        auto reap() -> void {std::erase_if(slots_,[](auto const& slot){return !slot->active;});}
        static auto serve(Slot& slot,std::chrono::milliseconds timeout,std::size_t requests) -> nex::capy::task<> {
            policy::DnsContext input{.network=rules::Network::tcp,.source_port=slot.source_port,
                .source_ip_bytes=std::span<std::uint8_t const>(slot.source).first(slot.source_size)};
            (void)co_await slot.connection.run(input,timeout,requests);slot.socket.close();
        }
        auto accept_loop(bool const* admitted) -> nex::capy::task<> {
            struct Guard {Impl& owner;~Guard(){owner.accepting_=false;}} guard{*this};
            while (admitting_ && admitted && !*admitted) {
                auto [error]=co_await nex::corosio::delay(std::chrono::milliseconds(1));
                if (error && admitting_) {io_failure_=error; stop();}
            }
            while(admitting_) {
                auto [error,peer]=co_await acceptor_.accept();if(!admitting_)break;
                if(error){io_failure_=error;stop();break;}
                reap();if(slots_.size()>=limit_){peer.close();continue;}
                auto slot=std::make_unique<Slot>(std::move(peer),context_,rules_,upstreams_,fallback_,cache_,disable_cache_,input_budget_,query_budget_,source_);auto* ptr=slot.get();slots_.push_back(std::move(slot));
                try {
                    nex::capy::run_async(context_.get_executor(),[ptr]() noexcept {ptr->active=false;},
                        [this,ptr](std::exception_ptr error) noexcept {if(!failure_)failure_=std::move(error);ptr->stop();ptr->active=false;stop();})(serve(*ptr,timeout_,max_requests_));
                } catch(...) {ptr->stop();ptr->active=false;throw;}
            }
        }
    public:
        Impl(nex::corosio::io_context& context,std::span<policy::DnsRule const> rules,
            std::span<MessageUpstream const> upstreams,std::size_t fallback,std::size_t limit,
            std::chrono::milliseconds timeout,std::size_t max_requests,MessageCache* cache,bool disable_cache,InputBudget* input_budget,InputBudget* query_budget,MessageRuleSource source)
            :context_(context),acceptor_(context),rules_(rules),upstreams_(upstreams),fallback_(fallback),limit_(limit),max_requests_(max_requests),cache_(cache),disable_cache_(disable_cache),input_budget_(input_budget),query_budget_(query_budget),timeout_(timeout),source_(std::move(source)) {}
        Impl(Impl const&)=delete;
        auto operator=(MessageTcpListener const&) -> Impl& = delete;
        ~Impl(){stop();if(!drained())std::terminate();}
        auto start(nex::corosio::endpoint endpoint,bool const* admitted) -> std::error_code {
            auto resolver=source_ ? source_().resolver : nullptr;
            bool valid_upstream=resolver ? resolver->fallback<resolver->upstreams.size() : fallback_<upstreams_.size();
            if(started_ || stopped_ || !limit_ || limit_>4096 || !max_requests_ || max_requests_>1024 ||
                timeout_<=std::chrono::milliseconds::zero() || !valid_upstream)
                return std::make_error_code(std::errc::invalid_argument);
            if(auto error=acceptor_.open(endpoint.address().family()))return error;
            int enabled=1;
            if (::setsockopt(acceptor_.native_handle(),SOL_SOCKET,SO_REUSEADDR,&enabled,sizeof(enabled))<0) {
                auto error=std::error_code(errno,std::generic_category());
                acceptor_.close();
                return error;
            }
            if(endpoint.is_v6())if(auto error=acceptor_.set_option(nex::corosio::socket_option::v6_only(true))){acceptor_.close();return error;}
            if(auto error=acceptor_.bind(endpoint)){acceptor_.close();return error;}
            if(auto error=acceptor_.listen()){acceptor_.close();return error;}
            started_=true;admitting_=true;accepting_=true;
            try {nex::capy::run_async(context_.get_executor(),[] {},[this](std::exception_ptr error) noexcept {failure_=std::move(error);accepting_=false;stop();})(accept_loop(admitted));}
            catch(...) {accepting_=false;stop();throw;}
            return {};
        }
        auto local_endpoint() const -> nex::corosio::endpoint {return acceptor_.local_endpoint();}
        auto begin_drain() noexcept -> void {
            if (std::exchange(admitting_,false)) acceptor_.close();
        }
        auto stop() noexcept -> void {
            if (std::exchange(stopped_,true)) return;
            begin_drain();
            for (auto& slot : slots_) slot->stop();
        }
        auto drained() noexcept -> bool {reap();return !accepting_ && slots_.empty();}
        auto failure() const noexcept -> std::exception_ptr {return failure_;}
        auto io_failure() const noexcept -> std::error_code {return io_failure_;}
        auto healthy() const noexcept -> bool {return started_ && !stopped_ && !failure_ && !io_failure_;}
    };
    MessageTcpListener::MessageTcpListener(nex::corosio::io_context& context,std::span<policy::DnsRule const> rules,std::span<MessageUpstream const> upstreams,std::size_t fallback,std::size_t limit,std::chrono::milliseconds timeout,std::size_t max_requests,MessageCache* cache,bool disable_cache,InputBudget* input_budget,InputBudget* query_budget,MessageRuleSource source):impl_(std::make_unique<Impl>(context,rules,upstreams,fallback,limit,timeout,max_requests,cache,disable_cache,input_budget,query_budget,std::move(source))) {}
    MessageTcpListener::~MessageTcpListener()=default;
    auto MessageTcpListener::start(nex::corosio::endpoint endpoint,bool const* admitted) -> std::error_code {return impl_->start(endpoint,admitted);}
    auto MessageTcpListener::local_endpoint() const -> nex::corosio::endpoint {return impl_->local_endpoint();}
    auto MessageTcpListener::begin_drain() noexcept -> void {impl_->begin_drain();}
    auto MessageTcpListener::stop() noexcept -> void {impl_->stop();}
    auto MessageTcpListener::drained() noexcept -> bool {return impl_->drained();}
    auto MessageTcpListener::failure() const noexcept -> std::exception_ptr {return impl_->failure();}
    auto MessageTcpListener::io_failure() const noexcept -> std::error_code {return impl_->io_failure();}
    auto MessageTcpListener::healthy() const noexcept -> bool {return impl_->healthy();}
}
