export module dns.message_tcp;
import std;
import dns.message;
import dns.input_budget;
import dns.message_program;
import dns.message_cache;
import dns.response_race_walk;
import dns.policy;
import dns.corosio_resolver;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

export namespace dns {
    // The accepted socket and fallback policy outlive this connection. Each
    // request has one deadline and is completed before the next is admitted.
    class MessageTcpConnection {
        using Clock=std::chrono::steady_clock;
        nex::corosio::tcp_socket& socket_;
        nex::corosio::io_context& context_;
        std::span<policy::DnsRule const> rules_;
        std::span<MessageUpstream const> upstreams_;
        std::size_t fallback_;
        MessageCache* cache_;bool disable_cache_;
        InputBudget& input_budget_;InputBudget& query_budget_;
        std::optional<MessageProgram> operation_;
        MessageRuleSource const* source_;
        bool started_=false,canceled_=false;
        auto transfer(std::span<std::uint8_t> bytes,bool write,Clock::time_point deadline) -> nex::capy::task<bool> {
            while(!bytes.empty() && !canceled_) {
                if(Clock::now()>=deadline) co_return false;
                auto [error,size]=write ? co_await nex::corosio::timeout(socket_.write_some(nex::capy::const_buffer(bytes.data(),bytes.size())),deadline) :
                    co_await nex::corosio::timeout(socket_.read_some(nex::capy::mutable_buffer(bytes.data(),bytes.size())),deadline);
                if(error || !size || size>bytes.size()) co_return false;
                bytes=bytes.subspan(size);
            }
            co_return !canceled_;
        }
    public:
        MessageTcpConnection(nex::corosio::tcp_socket& socket,nex::corosio::io_context& context,
            std::span<policy::DnsRule const> rules,std::span<MessageUpstream const> upstreams,std::size_t fallback,MessageCache* cache=nullptr,bool disable_cache=false,InputBudget* input_budget=nullptr,InputBudget* query_budget=nullptr,MessageRuleSource const* source=nullptr) noexcept
            :socket_(socket),context_(context),rules_(rules),upstreams_(upstreams),fallback_(fallback),cache_(cache),disable_cache_(disable_cache),input_budget_(input_budget ? *input_budget : default_input_budget()),query_budget_(query_budget ? *query_budget : default_listener_query_budget()),source_(source) {}
        MessageTcpConnection(MessageTcpConnection const&)=delete;
        auto operator=(MessageTcpConnection const&) -> MessageTcpConnection& = delete;
        auto cancel() noexcept -> void {canceled_=true;if(operation_)operation_->cancel();socket_.cancel();}
        auto run(policy::DnsContext context,std::chrono::milliseconds timeout,std::size_t max_requests)
            -> nex::capy::task<std::expected<void,detail::ResolveError>> {
            using Error=detail::ResolveError;
            if(std::exchange(started_,true) || timeout<=std::chrono::milliseconds::zero() || !max_requests || max_requests>1024)
                co_return std::unexpected(Error::state);
            for(std::size_t count=0;count<max_requests;++count) {
                if(canceled_)co_return std::unexpected(Error::canceled);
                auto deadline=Clock::now()+timeout;std::array<std::uint8_t,2> length{};
                if(!co_await transfer(length,false,deadline))co_return std::unexpected(canceled_ ? Error::canceled : Clock::now()>=deadline ? Error::timeout : Error::transport);
                auto size=(std::size_t(length[0])<<8)|length[1];if(size<12)co_return std::unexpected(Error::protocol);
                auto input=input_budget_.acquire(size);if(!input)co_return std::unexpected(Error::limit);
                auto storage=std::make_unique<std::uint8_t[]>(size);
                auto wire=std::span(storage.get(),size);
                if(!co_await transfer(wire,false,deadline))co_return std::unexpected(canceled_ ? Error::canceled : Clock::now()>=deadline ? Error::timeout : Error::transport);
                // The lease is declared before the query so it outlives the
                // question even on cancellation, exceptions and early return.
                std::optional<InputBudget::Lease> query_lease;
                auto query=parse_query(wire);
                if(!query) {
                    auto response=query_error_response(wire);if(!response)co_return std::unexpected(Error::protocol);
                    storage.reset();input.reset();
                    Bytes frame;frame.reserve(response->size()+2);frame.push_back(0);frame.push_back(static_cast<std::uint8_t>(response->size()));
                    frame.insert(frame.end(),response->begin(),response->end());
                    if(!co_await transfer(frame,true,deadline))co_return std::unexpected(canceled_ ? Error::canceled : Clock::now()>=deadline ? Error::timeout : Error::transport);
                    continue;
                }
                storage.reset();input.reset();
                auto cost=listener_query_cost(*query);if(!cost)co_return std::unexpected(Error::limit);
                auto acquired=query_budget_.acquire(*cost);if(!acquired)co_return std::unexpected(Error::limit);
                query_lease.emplace(std::move(*acquired));
                auto snapshot=source_ && *source_ ? (*source_)() : MessageRuleSnapshot{};
                auto selected=snapshot.rules ? std::span<policy::DnsRule const>(*snapshot.rules) : rules_;
                auto resolver=snapshot.resolver ? *snapshot.resolver :
                    MessageUpstreamSnapshot{upstreams_,fallback_,cache_,disable_cache_};
                operation_.emplace(context_,selected,resolver,snapshot.view);
                struct Release {
                    std::optional<MessageProgram>& operation;
                    ~Release() { operation.reset(); }
                } release{operation_};
                auto response=co_await operation_->run(*query,deadline,context);
                if(!response) {
                    if(response.error()==Error::canceled || canceled_)co_return std::unexpected(Error::canceled);
                    if(response.error()==Error::policy_dropped)continue;
                    policy::PredefinedResponse failure;failure.rcode=response.error()==Error::invalid_request ? 1 : response.error()==Error::policy_rejected || response.error()==Error::refused ? 5 : 2;
                    auto wire=synthetic_message(*query,failure);
                    if(!wire)co_return std::unexpected(Error::protocol);
                    response=std::move(*wire);
                }
                if(response->size()>65535)co_return std::unexpected(Error::limit);
                Bytes frame;frame.reserve(response->size()+2);frame.push_back(static_cast<std::uint8_t>(response->size()>>8));frame.push_back(static_cast<std::uint8_t>(response->size()));
                frame.insert(frame.end(),response->begin(),response->end());
                operation_->begin_send();
                if(!co_await transfer(frame,true,deadline))co_return std::unexpected(canceled_ ? Error::canceled : Clock::now()>=deadline ? Error::timeout : Error::transport);
            }
            co_return std::expected<void,Error>{};
        }
    };
}
