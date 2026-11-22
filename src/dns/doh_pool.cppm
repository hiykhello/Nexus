module;
#include <proxy/proxy_macros.h>

export module dns.doh_pool;
import std;
export import nexus.compat;
import proxy.v4;
import dns.corosio_query;
import dns.doh_exchange;
import dns.input_budget;
import tls.byte_stream;
import tls.connector;
import tls.encrypted_extensions;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

export namespace dns::doh_detail {
    using StreamDeadline=std::optional<Clock::time_point>;
    using StreamRead=capy::task<std::expected<std::size_t,tls::detail::ByteStreamError>>;
    using Reply=capy::task<std::expected<Response,Error>>;

    PRO_DEF_MEM_DISPATCH(StreamStart,start);
    PRO_DEF_MEM_DISPATCH(StreamMultiplexed,multiplexed);
    PRO_DEF_MEM_DISPATCH(StreamRecv,read);
    PRO_DEF_MEM_DISPATCH(StreamSend,send);
    PRO_DEF_MEM_DISPATCH(StreamCloseOutput,close_output);
    PRO_DEF_MEM_DISPATCH(StreamCancel,cancel);
    PRO_DEF_MEM_DISPATCH(StreamFresh,fresh);

    struct StreamFacade : pro::facade_builder
        ::add_convention<StreamStart,capy::task<bool>(Clock::time_point)>
        ::add_convention<StreamMultiplexed,bool() const noexcept>
        ::add_convention<StreamRecv,StreamRead(std::span<std::uint8_t>,StreamDeadline)>
        ::add_convention<StreamSend,capy::task<bool>(std::span<std::uint8_t const>,StreamDeadline)>
        ::add_convention<StreamCloseOutput,capy::task<bool>(StreamDeadline)>
        ::add_convention<StreamCancel,void() noexcept>
        ::add_convention<StreamFresh,Reply(std::string_view,std::string_view,std::uint16_t,
            QueryMessage const&,std::uint16_t,std::span<std::uint8_t const>,Clock::time_point,InputBudget&,std::stop_token)>
        ::build {};
    using Stream=pro::proxy<StreamFacade>;

    template<class Owner>
    class StreamAdapter {
        using Connector=std::remove_reference_t<decltype(std::declval<Owner&>().connector)>;
        Owner owner_;
        std::optional<tls::detail::ByteStream<typename Connector::Socket>> lower_;
    public:
        template<class... Args>
        explicit StreamAdapter(Args&&... args):owner_(std::forward<Args>(args)...) {}

        auto start(Clock::time_point deadline) -> capy::task<bool> {
            if (co_await owner_.connector.start(deadline)!=tls::detail::ConnectResult::connected) co_return false;
            if constexpr (requires {owner_.connected();}) owner_.connected();
            lower_.emplace(*owner_.connector.application());
            co_return true;
        }
        [[nodiscard]] auto multiplexed() const noexcept -> bool {
            constexpr std::array<std::uint8_t,2> h2{'h','2'};
            auto* negotiated=owner_.connector.negotiated();
            return negotiated && negotiated->alpn && std::ranges::equal(*negotiated->alpn,h2);
        }
        auto read(std::span<std::uint8_t> bytes,StreamDeadline deadline) -> StreamRead {
            return lower_->read(bytes,deadline);
        }
        auto send(std::span<std::uint8_t const> bytes,StreamDeadline deadline) -> capy::task<bool> {
            if constexpr (requires {owner_.used();}) owner_.used();
            return lower_->send(bytes,deadline);
        }
        auto close_output(StreamDeadline deadline) -> capy::task<bool> {
            return lower_->close_output(deadline);
        }
        auto cancel() noexcept -> void {owner_.connector.cancel();}
        auto fresh(std::string_view authority,std::string_view path,std::uint16_t port,
            QueryMessage const& query,std::uint16_t id,std::span<std::uint8_t const> wire,
            Clock::time_point deadline,InputBudget& budget,std::stop_token stop) -> Reply {
            return doh_detail::exchange(owner_.connector,authority,path,port,query,id,wire,deadline,budget,stop);
        }
    };

    using NewStream=std::expected<Stream,Error>;
    using StreamFactory=nexus::move_only_function<NewStream(Io&,Endpoint) const>;
    auto pooled_query(StreamFactory,std::string authority,std::string path,
        std::optional<std::chrono::milliseconds>) -> dns::detail::ProtectedQuery;

    auto stop_pool(Io&) noexcept -> void;
    auto resume_pool(Io&) noexcept -> void;
    auto reap_pool(Io&,Clock::time_point) noexcept -> void;
}
