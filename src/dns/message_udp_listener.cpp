module dns.message_udp_listener;
import std;
import dns.message;
import dns.message_program;
import dns.message_cache;
import dns.policy;
import dns.corosio_resolver;
import rules;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

namespace dns {
    struct MessageUdpListener::Impl {
        using Clock=std::chrono::steady_clock;
        struct Slot {
            struct Request {
                InputBudget::Lease lease;QueryMessage query;
                Request(InputBudget::Lease&& reservation,QueryMessage&& value) noexcept
                    :lease(std::move(reservation)),query(std::move(value)) {}
            };
            MessageRuleSnapshot snapshot;
            MessageProgram program;std::optional<Request> request;nex::corosio::endpoint peer;
            std::array<std::uint8_t,16> source{};std::uint8_t source_size=0;
            bool active=true;
            Slot(nex::corosio::io_context& context,std::span<policy::DnsRule const> rules,std::span<MessageUpstream const> upstreams,
                std::size_t fallback,QueryMessage query,InputBudget::Lease&& lease,nex::corosio::endpoint endpoint,MessageCache* cache,bool disable_cache,
                MessageRuleSnapshot retained)
                :snapshot(std::move(retained)),
                 program(context,snapshot.rules ? std::span<policy::DnsRule const>(*snapshot.rules) : rules,
                    snapshot.resolver ? *snapshot.resolver : MessageUpstreamSnapshot{upstreams,fallback,cache,disable_cache},
                    snapshot.view),
                 request(std::in_place,std::move(lease),std::move(query)),peer(endpoint) {
                if(peer.address().is_v4()){auto bytes=peer.address().to_v4().to_bytes();std::ranges::copy(bytes,source.begin());source_size=4;}
                else {auto bytes=peer.address().to_v6().to_bytes();std::ranges::copy(bytes,source.begin());source_size=16;}
            }
            auto finish() noexcept -> void {program.finish_send();request.reset();active=false;}
        };
        struct ErrorSlot { Bytes response;nex::corosio::endpoint peer;bool active=true; };
        nex::corosio::io_context& context_;nex::corosio::udp_socket socket_;
        std::span<policy::DnsRule const> rules_;std::span<MessageUpstream const> upstreams_;
        std::size_t fallback_,limit_;std::chrono::milliseconds timeout_;
        MessageCache* cache_;bool disable_cache_;InputBudget& input_budget_;InputBudget& query_budget_;
        std::optional<InputBudget::Lease> input_;
        MessageRuleSource source_;
        std::vector<std::unique_ptr<Slot>> slots_;nex::capy::async_mutex writer_;
        std::vector<std::unique_ptr<ErrorSlot>> errors_;
        std::stop_source receive_stop_;
        bool started_=false,stopped_=false,receiving_=false;std::exception_ptr failure_;std::error_code io_failure_;
        std::uint64_t dropped_=0,send_failures_=0;
        auto reap() -> void {std::erase_if(slots_,[](auto const& slot){return !slot->active;});std::erase_if(errors_,[](auto const& slot){return !slot->active;});}
        auto send_error(ErrorSlot& slot) -> nex::capy::task<> {
            auto deadline=Clock::now()+timeout_;
            auto [lock_error,lock]=co_await nex::corosio::timeout(writer_.scoped_lock(),deadline);
            if(lock_error || stopped_){if(!stopped_)++send_failures_;co_return;}
            auto [error,sent]=co_await nex::corosio::timeout(socket_.send_to(nex::capy::const_buffer(slot.response.data(),slot.response.size()),slot.peer),deadline);
            if(!stopped_ && (error || sent!=slot.response.size()))++send_failures_;
        }
        auto serve(Slot& slot) -> nex::capy::task<> {
            auto& query=slot.request->query;
            policy::DnsContext input{.network=rules::Network::udp,.source_port=slot.peer.port(),
                .source_ip_bytes=std::span<std::uint8_t const>(slot.source).first(slot.source_size)};
            auto deadline=Clock::now()+timeout_;auto result=co_await slot.program.run(query,deadline,input);
            if(stopped_)co_return;
            if(!result) {
                if(result.error()==detail::ResolveError::canceled || result.error()==detail::ResolveError::policy_dropped)co_return;
                policy::PredefinedResponse failure;failure.rcode=result.error()==detail::ResolveError::invalid_request ? 1 : result.error()==detail::ResolveError::policy_rejected || result.error()==detail::ResolveError::refused ? 5 : 2;
                auto wire=synthetic_message(query,failure);if(!wire)co_return;result=std::move(*wire);
            }
            auto wire=udp_response_fits(query,std::move(*result));
            if(!wire)co_return;
            auto [lock_error,lock]=co_await nex::corosio::timeout(writer_.scoped_lock(),deadline);
            if(lock_error || stopped_) {if(!stopped_)++send_failures_;co_return;}
            slot.program.begin_send();
            auto [error,size]=co_await nex::corosio::timeout(socket_.send_to(nex::capy::const_buffer(wire->data(),wire->size()),slot.peer),deadline);
            if(!stopped_ && (error || size!=wire->size())) ++send_failures_;
        }
        auto receive(std::unique_ptr<std::uint8_t[]> storage,bool const* admitted) -> nex::capy::task<> {
            struct Guard {Impl& owner;~Guard(){owner.input_.reset();owner.receiving_=false;}} guard{*this};
            while (!receive_stop_.stop_requested() && admitted && !*admitted) {
                auto [error]=co_await nex::corosio::delay(std::chrono::milliseconds(1));
                if (error && !receive_stop_.stop_requested()) {io_failure_=error; stop();}
            }
            auto bytes=std::span(storage.get(),std::size_t{65535});
            while(!receive_stop_.stop_requested()) {
                nex::corosio::endpoint peer;auto [error,size]=co_await socket_.recv_from(nex::capy::mutable_buffer(bytes.data(),bytes.size()),peer);
                if(receive_stop_.stop_requested())break;if(error){io_failure_=error;stop();break;}
                reap();if(size>bytes.size() || slots_.size()+errors_.size()>=limit_){++dropped_;continue;}
                auto query=parse_query(std::span(bytes).first(size));
                if(!query) {
                    auto response=query_error_response(std::span(bytes).first(size));
                    if(!response){++dropped_;continue;}
                    auto slot=std::make_unique<ErrorSlot>(ErrorSlot{std::move(*response),peer});auto* ptr=slot.get();errors_.push_back(std::move(slot));
                    try {nex::capy::run_async(context_.get_executor(),[ptr]() noexcept {ptr->active=false;},
                        [this,ptr](std::exception_ptr error) noexcept {if(!failure_)failure_=std::move(error);ptr->active=false;stop();})(send_error(*ptr));}
                    catch(...) {ptr->active=false;throw;}
                    continue;
                }
                auto cost=listener_query_cost(*query);if(!cost){++dropped_;continue;}
                auto lease=query_budget_.acquire(*cost);if(!lease){++dropped_;continue;}
                auto snapshot=source_ ? source_() : MessageRuleSnapshot{};
                auto slot=std::make_unique<Slot>(context_,rules_,upstreams_,fallback_,std::move(*query),std::move(*lease),
                    peer,cache_,disable_cache_,std::move(snapshot));
                auto* ptr=slot.get();slots_.push_back(std::move(slot));
                try {nex::capy::run_async(context_.get_executor(),[ptr]() noexcept {ptr->finish();},
                    [this,ptr](std::exception_ptr error) noexcept {if(!failure_)failure_=std::move(error);ptr->program.cancel();ptr->finish();stop();})(serve(*ptr));}
                catch(...) {ptr->program.cancel();ptr->finish();throw;}
            }
        }
    public:
        Impl(nex::corosio::io_context& context,std::span<policy::DnsRule const> rules,std::span<MessageUpstream const> upstreams,
            std::size_t fallback,std::size_t limit,std::chrono::milliseconds timeout,MessageCache* cache,bool disable_cache,InputBudget* input_budget,InputBudget* query_budget,MessageRuleSource source)
            :context_(context),socket_(context),rules_(rules),upstreams_(upstreams),fallback_(fallback),limit_(limit),timeout_(timeout),cache_(cache),disable_cache_(disable_cache),input_budget_(input_budget ? *input_budget : default_input_budget()),query_budget_(query_budget ? *query_budget : default_listener_query_budget()),source_(std::move(source)) {}
        Impl(Impl const&)=delete;
        auto operator=(MessageUdpListener const&) -> Impl& = delete;
        ~Impl(){stop();if(!drained())std::terminate();}
        auto start(nex::corosio::endpoint endpoint,bool const* admitted) -> std::error_code {
            auto resolver=source_ ? source_().resolver : nullptr;
            bool valid_upstream=resolver ? resolver->fallback<resolver->upstreams.size() : fallback_<upstreams_.size();
            if(started_ || stopped_ || !limit_ || limit_>4096 || timeout_<=std::chrono::milliseconds::zero() ||
                !valid_upstream) return std::make_error_code(std::errc::invalid_argument);
            auto input=input_budget_.acquire(65535);if(!input)return std::make_error_code(std::errc::no_buffer_space);
            if(auto error=socket_.open(endpoint.address().family()))return error;
            if(endpoint.is_v6())if(auto error=socket_.set_option(nex::corosio::socket_option::v6_only(true))){socket_.close();return error;}
            if(auto error=socket_.bind(endpoint)){socket_.close();return error;}
            started_=true;receiving_=true;input_.emplace(std::move(*input));
            try {
                auto storage=std::make_unique<std::uint8_t[]>(65535);
                nex::capy::run_async(context_.get_executor(),receive_stop_.get_token(),[] {},
                    [this](std::exception_ptr error) noexcept {failure_=std::move(error);receiving_=false;stop();})(receive(std::move(storage),admitted));
            }
            catch(...){input_.reset();receiving_=false;stop();throw;}return {};
        }
        auto local_endpoint() const -> nex::corosio::endpoint {return socket_.local_endpoint();}
        auto begin_drain() noexcept -> void {receive_stop_.request_stop();}
        auto stop() noexcept -> void {
            if (std::exchange(stopped_,true)) return;
            begin_drain();
            for (auto& slot : slots_) slot->program.cancel();
            socket_.close();
        }
        auto drained() noexcept -> bool {reap();return !receiving_ && slots_.empty() && errors_.empty();}
        auto dropped() const noexcept -> std::uint64_t {return dropped_;}
        auto send_failures() const noexcept -> std::uint64_t {return send_failures_;}
        auto failure() const noexcept -> std::exception_ptr {return failure_;}
        auto io_failure() const noexcept -> std::error_code {return io_failure_;}
        auto healthy() const noexcept -> bool {return started_ && !stopped_ && !failure_ && !io_failure_;}
    };
    MessageUdpListener::MessageUdpListener(nex::corosio::io_context& context,std::span<policy::DnsRule const> rules,std::span<MessageUpstream const> upstreams,std::size_t fallback,std::size_t limit,std::chrono::milliseconds timeout,MessageCache* cache,bool disable_cache,InputBudget* input_budget,InputBudget* query_budget,MessageRuleSource source):impl_(std::make_unique<Impl>(context,rules,upstreams,fallback,limit,timeout,cache,disable_cache,input_budget,query_budget,std::move(source))) {}
    MessageUdpListener::~MessageUdpListener()=default;
    auto MessageUdpListener::start(nex::corosio::endpoint endpoint,bool const* admitted) -> std::error_code {return impl_->start(endpoint,admitted);}
    auto MessageUdpListener::local_endpoint() const -> nex::corosio::endpoint {return impl_->local_endpoint();}
    auto MessageUdpListener::begin_drain() noexcept -> void {impl_->begin_drain();}
    auto MessageUdpListener::stop() noexcept -> void {impl_->stop();}
    auto MessageUdpListener::drained() noexcept -> bool {return impl_->drained();}
    auto MessageUdpListener::failure() const noexcept -> std::exception_ptr {return impl_->failure();}
    auto MessageUdpListener::io_failure() const noexcept -> std::error_code {return impl_->io_failure();}
    auto MessageUdpListener::healthy() const noexcept -> bool {return impl_->healthy();}
    auto MessageUdpListener::dropped() const noexcept -> std::uint64_t {return impl_->dropped();}
    auto MessageUdpListener::send_failures() const noexcept -> std::uint64_t {return impl_->send_failures();}
}
