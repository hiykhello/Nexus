module cli.rule_fetch_h2;
import std;
import cli.rule_fetch_response;
import http.header;
import http2.client_channel;
import http2.headers;
import tls.byte_stream;
import capy;
import corosio;

namespace cli::rule_fetch {
    namespace detail {
        using Clock=std::chrono::steady_clock;
        namespace capy = ::capy;

        auto valid_headers(std::span<http2::Header const> headers,std::size_t maximum) -> bool {
            for(auto const& header:headers) {
                if(header.name=="content-encoding" && !std::ranges::equal(header.value,std::string_view("identity"),
                    [](char a,char b){return a==b || (a>='A' && a<='Z' && a-'A'+'a'==b);})) return false;
                if(header.name=="content-length") {
                    std::uint64_t length=0;
                    auto end=header.value.data()+header.value.size();
                    auto [parsed,error]=std::from_chars(header.value.data(),end,length);
                    if(error!=std::errc{} || parsed!=end || length>maximum)return false;
                }
            }
            return true;
        }

        auto request_fields(std::string_view authority,std::string_view target,
            std::span<http::HeaderField const> request_headers) -> std::vector<http2::FieldView> {
            std::vector<http2::FieldView> fields{
                {":method","GET"},{":scheme","https"},{":authority",authority},{":path",target},{"accept-encoding","identity"}
            };
            fields.reserve(fields.size()+request_headers.size());
            for (auto const& header:request_headers) fields.push_back({header.name,header.value});
            return fields;
        }

        template<class Channel>
        auto read_body(Channel& channel,http2::StreamTicket ticket,std::size_t maximum,
            Clock::time_point deadline,ResponsePolicy policy,ResponseHeaders const* headers,BodySink sink)
            -> capy::task<std::optional<unsigned>> {
            auto stop=co_await capy::this_coro::stop_token;
            std::size_t received=0;
            unsigned status=0;
            while (!stop.stop_requested() && Clock::now()<deadline) {
                auto response=channel.response(ticket);
                if(!response || response->failure)break;
                if(!status && response->status) {
                    status=response->status;
                    if (!policy.accepts(status)) break;
                    if (status!=304 && !valid_headers(response->headers,maximum)) break;
                    if (headers)
                        for (auto const& field:response->headers) (*headers)(field.name,field.value);
                }
                auto bytes=channel.peek(ticket);
                if (!bytes || bytes->size()>maximum-received) break;
                if (!bytes->empty()) {
                    if (!status || status==304) break;
                    // The channel's buffer may change while the consumer waits.
                    std::array<char,16*1024> chunk;
                    auto size=std::min(chunk.size(),bytes->size());
                    std::ranges::copy(bytes->first(size),chunk.begin());
                    if (!co_await sink({chunk.data(),size},deadline) || stop.stop_requested() || Clock::now()>=deadline ||
                        !channel.consume(ticket,size)) break;
                    received+=size;
                    continue;
                }
                if (response->closed) {
                    if (status && response->remote_end) co_return status;
                    break;
                }
                if (!co_await channel.wait_change(deadline)) break;
            }
            co_return std::nullopt;
        }
    }

    class Http2Pool::Impl {
        static constexpr std::size_t streams=8;
        struct Lower {
            Http2Stream& stream;

            auto read(std::span<std::uint8_t> bytes,Http2Deadline deadline)
                -> capy::task<std::expected<std::size_t,tls::detail::ByteStreamError>> {
                return stream->read(bytes,deadline);
            }
            auto send(std::span<std::uint8_t const> bytes,Http2Deadline deadline) -> capy::task<bool> {
                return stream->send(bytes,deadline);
            }
            auto close_output(Http2Deadline deadline) -> capy::task<bool> {
                return stream->close_output(deadline);
            }
            auto cancel() noexcept -> void {stream->cancel();}
        };
        using Channel=http2::ClientChannel<Lower,streams>;
        using Ticket=http2::StreamTicket;

        class Connection {
            Http2Stream stream_;
            Lower lower_{stream_};
            Channel channel_;
            capy::async_event idle_changed_;
            std::array<std::optional<Ticket>,streams> retired_;
            detail::Clock::time_point idle_since_=detail::Clock::now();
            std::size_t active_=0;
            bool stopped_=false;

            auto release(Ticket ticket) noexcept -> void {
                if (auto released=channel_.release(ticket); released && !*released) retired_[ticket.slot]=ticket;
                if (!--active_) {
                    idle_since_=detail::Clock::now();
                    idle_changed_.set();
                }
            }

            auto drive() -> capy::task<capy::results<>> {
                struct Finish {
                    Connection& owner;
                    ~Finish(){owner.stop();}
                } finish{*this};
                co_return co_await channel_.run();
            }

            auto reap_idle() -> capy::task<capy::results<>> {
                while (!stopped_) {
                    if (obsolete(detail::Clock::now())) {
                        stop();
                        break;
                    }
                    idle_changed_.clear();
                    auto wait=idle_changed_.wait();
                    auto [error]=active_ ? co_await std::move(wait) :
                        co_await corosio::timeout(std::move(wait),idle_since_+std::chrono::seconds(15));
                    if (error && !capy::is_timeout(error)) stop();
                }
                co_return capy::results<>{};
            }

            auto run() -> capy::task<> {
                (void)co_await capy::when_all(drive(),reap_idle());
            }

        public:
            Connection(Http2Stream stream,std::unique_ptr<http2::Client<streams>> client)
                :stream_(std::move(stream)),channel_(lower_,std::move(client)) {}

            auto start(corosio::io_context& io,std::shared_ptr<Connection> owner) -> void {
                capy::run_async(io.get_executor(),[owner] {},
                    [owner](std::exception_ptr) noexcept {owner->stop();})(run());
            }

            auto stop() noexcept -> void {
                if (!std::exchange(stopped_,true)) {
                    idle_changed_.set();
                    channel_.cancel();
                }
            }

            [[nodiscard]] auto idle() const noexcept -> bool {return !active_;}

            [[nodiscard]] auto obsolete(detail::Clock::time_point now) const noexcept -> bool {
                return idle() && (stopped_ || channel_.failure() || channel_.goaway() ||
                    now-idle_since_>=std::chrono::seconds(15));
            }

            [[nodiscard]] auto submit(std::span<http2::FieldView const> fields) -> std::optional<Ticket> {
                if (stopped_ || channel_.failure() || channel_.goaway() || active_>=streams) return {};
                for (auto& entry:retired_)
                    if (entry && channel_.release(*entry).value_or(false)) entry.reset();
                if (auto ticket=channel_.submit(fields)) {
                    if (!active_++) idle_changed_.set();
                    return *ticket;
                }
                return {};
            }

            auto receive(Ticket ticket,Transfer request) -> capy::task<TransferResult> {
                struct Release {
                    Connection& owner;
                    Ticket ticket;
                    ~Release(){owner.release(ticket);}
                } release{*this,ticket};
                auto result=co_await detail::read_body(channel_,ticket,request.maximum,request.deadline,
                    request.policy,request.headers,request.sink);
                if (!result)
                    co_return std::unexpected("HTTP/2 response is incomplete, unsupported or exceeds its limit");
                co_return *result;
            }
        };

        std::array<std::shared_ptr<Connection>,2> connections_;

    public:
        auto stop() noexcept -> void {
            for (auto& connection:connections_) {
                if (!connection) continue;
                connection->stop();
                connection.reset();
            }
        }

        auto request(corosio::io_context& io,Transfer request,Http2Stream stream={})
            -> capy::task<std::optional<TransferResult>> {
            auto now=detail::Clock::now();
            if (now>=request.deadline)
                co_return TransferResult(std::unexpected("HTTP/2 request deadline expired"));
            auto fields=detail::request_fields(request.authority,request.target,request.extra_fields);
            for (auto& connection:connections_) {
                if (!connection || !connection->obsolete(now)) continue;
                connection->stop();
                connection.reset();
            }
            for (auto const& existing:connections_) {
                auto connection=existing;
                if (!connection) continue;
                if (auto ticket=connection->submit(fields)) {
                    stream={};
                    co_return co_await connection->receive(*ticket,request);
                }
            }
            if (!stream) co_return std::nullopt;
            auto slot=std::ranges::find_if(connections_,[](auto const& connection) {return !connection || connection->idle();});
            if (slot==connections_.end())
                co_return TransferResult(std::unexpected("HTTP/2 connection pool is full"));
            auto client=http2::Client<streams>::create();
            if (!client) co_return TransferResult(std::unexpected("cannot start HTTP/2 connection"));
            auto connection=std::make_shared<Connection>(std::move(stream),std::move(*client));
            auto ticket=connection->submit(fields);
            if (!ticket) co_return TransferResult(std::unexpected("HTTP/2 request could not be submitted"));
            connection->start(io,connection);
            if (*slot) (*slot)->stop();
            *slot=connection;
            co_return co_await connection->receive(*ticket,request);
        }
    };

    Http2Pool::Http2Pool()=default;
    Http2Pool::~Http2Pool() {stop();}

    auto Http2Pool::stop() noexcept -> void {
        if (impl_) impl_->stop();
    }

    auto Http2Pool::request(corosio::io_context& io,Transfer transfer,Http2Stream stream)
        -> capy::task<std::optional<TransferResult>> {
        if (!impl_) {
            if (!stream) co_return std::nullopt;
            impl_=std::make_unique<Impl>();
        }
        co_return co_await impl_->request(io,transfer,std::move(stream));
    }
}
