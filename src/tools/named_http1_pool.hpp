#pragma once

    struct Download {
        fetch::BodySink sink;
        Clock::time_point deadline;
        std::size_t received=0;
        std::optional<std::uint64_t> length;
        std::size_t maximum;
        unsigned status=0;
        fetch::ResponsePolicy policy;
        fetch::ResponseHeaders const* headers=nullptr;

        auto operator()(http::ResponseStep const& step) -> capy::task<bool> {
            if (step.informational) co_return true;
            if(step.event==http::ResponseEvent::header) {
                if (!policy.accepts(step.status_code)) co_return false;
                if (step.status_code!=304) {
                    if (!step.identity_encoding || (step.content_length && *step.content_length>maximum)) co_return false;
                    length=step.content_length;
                }
                status=step.status_code;
                if (headers) {
                    http::HeaderFieldCursor fields(http::inspect_header(step.wire).field_lines);
                    for (auto field=fields.next();field.status==http::HeaderFieldStatus::field;field=fields.next())
                        (*headers)(field.field.name,field.field.value);
                }
                co_return true;
            }
            if (!status || status==304 || step.wire.size()>maximum-received) co_return false;
            if (!co_await sink(step.wire,deadline) || Clock::now()>=deadline) co_return false;
            received+=step.wire.size();
            co_return true;
        }
    };


    struct Http1Attempt {
        fetch::TransferResult result;
        bool retry=false;
    };

    template<class Connector>
    auto download_http1(Connector& connector,fetch::Transfer const& transfer,bool& reusable)
        -> capy::task<Http1Attempt> {
        auto const& [authority,target,limit,deadline,request_headers,policy,headers,sink]=transfer;
        auto request="GET " + std::string(target) + " HTTP/1.1\r\nHost: " + std::string(authority) +
            "\r\nAccept-Encoding: identity\r\n";
        for (auto const& header:request_headers)
            request.append(header.name).append(": ").append(header.value).append("\r\n");
        request.append("\r\n");
        Download body{.sink=sink,.deadline=deadline,.maximum=limit,.policy=policy,.headers=headers};
        auto stop=co_await capy::this_coro::stop_token;
        auto status=co_await http::detail::https_exchange(connector,request,false,body,deadline,true,
            http::ChunkOutput::payload,&reusable);
        if (!status || !body.status || (body.length && body.received!=*body.length) ||
            Clock::now()>=deadline || stop.stop_requested()) {
            reusable=false;
            auto retry=!status && !body.status && Clock::now()<deadline && !stop.stop_requested() &&
                (status.error()==http::detail::HttpsError::tls || status.error()==http::detail::HttpsError::truncated);
            co_return Http1Attempt{std::unexpected("HTTPS response is incomplete, unsupported or exceeds its limit"),retry};
        }
        co_return Http1Attempt{body.status};
    }

    PRO_DEF_MEM_DISPATCH(Http1Exchange,exchange);
    PRO_DEF_MEM_DISPATCH(Http1Cancel,cancel);
    struct Http1Facade : pro::facade_builder
        ::add_convention<Http1Exchange,capy::task<Http1Attempt>(fetch::Transfer)>
        ::add_convention<Http1Cancel,void() noexcept>::build {};

    template<class Owner>
    struct Http1Transport {
        std::unique_ptr<Owner> owner;
        bool& reusable;

        auto exchange(fetch::Transfer transfer) -> capy::task<Http1Attempt> {
            if constexpr (requires {owner->session;}) owner->session.touched=Clock::now();
            bool idle=false;
            auto result=co_await download_http1(owner->connector,transfer,idle);
            reusable=idle;
            co_return result;
        }
        auto cancel() noexcept -> void {owner->connector.cancel();}
    };

    class Http1Connection {
        bool reusable_=true;
        pro::proxy<Http1Facade> stream_;
    public:
        template<class Owner>
        explicit Http1Connection(std::unique_ptr<Owner> owner)
            :stream_(pro::make_proxy<Http1Facade,Http1Transport<Owner>>(std::move(owner),reusable_)) {}
        Http1Connection(Http1Connection const&)=delete;
        auto operator=(Http1Connection const&) -> Http1Connection& = delete;

        [[nodiscard]] auto usable() const noexcept -> bool {return reusable_;}
        [[nodiscard]] auto drained() const noexcept -> bool {return true;}
        auto exchange(fetch::Transfer transfer) -> capy::task<Http1Attempt> {return stream_->exchange(transfer);}
        auto cancel() noexcept -> void {reusable_=false;stream_->cancel();}
    };

    class Http1Pool {
        net::ConnectionPool<Http1Connection> connections_{
            {.max_sessions=2,.idle_timeout=std::chrono::seconds(15),.check_interval=std::chrono::seconds(1)}};
        std::stop_source maintenance_stop_;
        bool maintaining_=false;

        auto maintain() -> capy::task<> {
            auto interval=connections_.options().check_interval;
            while (connections_.size()) {
                auto [error]=co_await io::delay(interval);
                if (error) break;
                connections_.reap(Clock::now());
            }
        }

    public:
        auto stop() noexcept -> void {
            maintenance_stop_.request_stop();
            connections_.stop();
        }

        auto request(fetch::Transfer request) -> capy::task<std::optional<Http1Attempt>> {
            connections_.reap(Clock::now());
            auto selected=connections_.acquire();
            if (!selected) co_return std::nullopt;
            co_return co_await selected->connection().exchange(request);
        }

        template<class Owner>
        auto fresh(io::io_context& context,std::unique_ptr<Owner> owner,fetch::Transfer transfer)
            -> capy::task<fetch::TransferResult> {
            bool reusable=false;
            auto result=co_await download_http1(owner->connector,transfer,reusable);
            if (result.result && reusable) {
                if (auto slot=connections_.reserve()) {
                    if constexpr (requires {owner->session;}) owner->session.relaying=true;
                    auto connection=std::make_unique<Http1Connection>(std::move(owner));
                    if (slot->commit(std::move(connection)) && !maintaining_) {
                        maintaining_=true;
                        auto finished=[this] noexcept {maintaining_=false;};
                        try {
                            capy::run_async(context.get_executor(),maintenance_stop_.get_token(),finished,
                                [finished](std::exception_ptr) noexcept {finished();})(maintain());
                        } catch (...) {
                            finished();
                            throw;
                        }
                    }
                }
            }
            co_return std::move(result.result);
        }
    };

