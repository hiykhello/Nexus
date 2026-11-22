// Included in the Client template after its module imports.
    public:
        auto wait_http_ready(Clock::time_point deadline,std::stop_token external={}) -> nex::capy::task<bool> {
            std::stop_callback cancel(external,[this] noexcept {driver_.changed().set();});
            while (!external.stop_requested() && factory_.bundle && !factory_.bundle->app.stopping() && !factory_.bundle->app.can_request()) {
                driver_.changed().clear();
                if (external.stop_requested()) co_return false;
                auto [error]=co_await nex::corosio::timeout(driver_.changed().wait(),deadline);
                if (error || !driver_.running()) co_return false;
            }
            co_return !external.stop_requested() && factory_.bundle && factory_.bundle->app.can_request() &&
                Clock::now()<deadline;
        }

        [[nodiscard]] auto retryable_http_handshake(Clock::time_point deadline) const noexcept -> bool {
            if (factory_.failure) return factory_.failure==nex::ngtcp2::err_handshake_timeout;
            auto const& failure=driver_.failure();
            if (!failure) return Clock::now()>=deadline;
            auto* socket=std::get_if<net::DatagramFailure>(&*failure);
            return socket && (socket->system==std::errc::network_unreachable ||
                socket->system==std::errc::host_unreachable || socket->system==std::errc::connection_refused);
        }

        [[nodiscard]] auto reusable_http() const noexcept -> bool {
            return factory_.bundle && factory_.bundle->app.can_request() && !factory_.bundle->hooks.conn_closed &&
                !factory_.bundle->hooks.http_goaway;
        }

        [[nodiscard]] auto can_submit_http() const noexcept -> bool {
            return reusable_http() && factory_.bundle->hooks.stream<0 &&
                std::ranges::any_of(factory_.bundle->hooks.responses,[](auto const& entry) {
                return !entry;
            });
        }

    private:
        auto release_http(Bundle& bundle,std::optional<typename Hooks::Response>& entry) noexcept -> void {
            auto& response=*entry;
            bundle.app.discard_body(std::exchange(response.uncredited,0));
            if (response.closed) entry.reset();
            else {
                response.returned=true;
                if (!response.complete && !response.reset_sent) {
                    response.rejected=true;
                    response.reset=true;
                    if (bundle.app.flush_pending()) request_stop();
                }
            }
            driver_.notify();
        }

        auto exchange_http(std::string_view path,std::size_t limit,Clock::time_point deadline,
            std::optional<HttpPost> post,std::span<http::HeaderField const> headers={},bool allow_not_modified=false,
            bool allow_redirect=false,std::optional<HttpBodySink> sink={},std::optional<HttpHeaderSink> observe={},
            std::stop_token external={}) -> nex::capy::task<std::expected<HttpResponse,HttpError>> {
            if (!co_await wait_http_ready(deadline,external)) co_return std::unexpected(HttpError::transport);
            std::stop_callback cancel(external,[this] noexcept {driver_.changed().set();});
            auto& bundle=*factory_.bundle;
            auto& hooks=bundle.hooks;
            auto stop=co_await nex::capy::this_coro::stop_token;
            std::optional<typename Hooks::Response>* entry=nullptr;
            for (;;) {
                if (stop.stop_requested() || external.stop_requested() || Clock::now()>=deadline ||
                    !reusable_http() || hooks.stream>=0)
                    co_return std::unexpected(HttpError::transport);
                auto it=std::ranges::find_if(hooks.responses,[](auto const& candidate){return !candidate;});
                if (it==hooks.responses.end()) co_return std::unexpected(HttpError::transport);
                std::int64_t id=-1;
                auto error=nex::ngtcp2::ngtcp2_conn_open_bidi_stream(bundle.session.transport().native(),&id,nullptr);
                if (!error) {
                    it->emplace(id,limit);
                    entry=&*it;
                    break;
                }
                if (error!=nex::ngtcp2::err_stream_id_blocked) co_return std::unexpected(HttpError::transport);
                driver_.changed().clear();
                if (external.stop_requested()) co_return std::unexpected(HttpError::transport);
                auto [wait_error]=co_await nex::corosio::timeout(driver_.changed().wait(),deadline);
                if (wait_error || !driver_.running()) co_return std::unexpected(HttpError::transport);
            }
            struct Release {
                Client& client;
                Bundle& bundle;
                std::optional<typename Hooks::Response>& entry;
                ~Release(){client.release_http(bundle,entry);}
            } release{*this,bundle,*entry};
            auto& response=**entry;
            response.allow_not_modified=allow_not_modified;
            response.allow_redirect=allow_redirect;
            response.streaming=sink.has_value();
            std::array fields{field(":method",post ? "POST" : "GET"),field(":scheme","https"),
                field(":authority",profile_.authority()),field(":path",path),field("accept-encoding","identity"),
                field("accept",{}),field("content-type",{}),field("content-length",{})};
            std::string length;
            auto count=std::size_t{5};
            if (post) {
                length=std::to_string(post->bytes.size());
                fields[5]=field("accept",post->media_type);
                fields[6]=field("content-type",post->media_type);
                fields[7]=field("content-length",length);
                count=fields.size();
                response.request.emplace(post->bytes.begin(),post->bytes.end());
            }
            auto request_fields=std::span<nex::nghttp3::nghttp3_nv const>(fields).first(count);
            std::vector<nex::nghttp3::nghttp3_nv> extended;
            if (!headers.empty()) {
                extended.reserve(count+headers.size());
                extended.assign(request_fields.begin(),request_fields.end());
                for (auto const& header:headers) {
                    auto value=field(header.name,header.value);
                    value.flags=nex::nghttp3::nv_flag_never_index;
                    extended.push_back(value);
                }
                request_fields=extended;
            }
            if (bundle.app.h3().request(response.id,request_fields,post.has_value())) co_return std::unexpected(HttpError::transport);
            driver_.notify();
            while (!stop.stop_requested() && !external.stop_requested() && !response.rejected && !hooks.conn_closed &&
                   !bundle.app.stopping() && Clock::now()<deadline) {
                if (observe && response.headers) {
                    for (auto const& [name,value]:response.result.fields)
                        if (!name.starts_with(':')) (*observe)(name,value);
                    observe.reset();
                }
                if (sink && !response.result.body.empty()) {
                    // The driver may append to the receive buffer while the sink waits.
                    // The bytes occupy QUIC receive credit until the sink accepts them.
                    auto chunk=std::exchange(response.result.body,std::string{});
                    if (!co_await (*sink)(chunk,deadline) || stop.stop_requested() || Clock::now()>=deadline)
                        break;
                    if (response.complete || response.closed || response.rejected)
                        bundle.app.discard_body(chunk.size());
                    else if (!bundle.app.consume_body(response.id,chunk.size())) break;
                    response.uncredited-=chunk.size();
                    driver_.notify();
                    continue;
                }
                if (response.complete) co_return std::move(response.result);
                driver_.changed().clear();
                if (external.stop_requested()) break;
                auto [error]=co_await nex::corosio::timeout(driver_.changed().wait(),deadline);
                if (error || !driver_.running()) break;
            }
            co_return std::unexpected(response.rejected ? HttpError::response : HttpError::transport);
        }

    public:
        auto get_response(std::string_view path,std::size_t limit,Clock::time_point deadline,
            std::span<http::HeaderField const> headers,bool allow_not_modified,bool allow_redirect=false,
            std::optional<HttpBodySink> sink={},std::optional<HttpHeaderSink> observe={}) -> nex::capy::task<std::optional<HttpResponse>> {
            auto result=co_await exchange_http(path,limit,deadline,{},headers,allow_not_modified,allow_redirect,sink,observe);
            if (!result) co_return std::nullopt;
            co_return std::move(*result);
        }

        auto get(std::string_view path,std::size_t limit,Clock::time_point deadline)
            -> nex::capy::task<std::optional<std::string>> {
            auto response=co_await get_response(path,limit,deadline,{},false);
            if (!response) co_return std::nullopt;
            co_return std::move(response->body);
        }

        auto post(std::string_view path,HttpPost body,std::size_t limit,Clock::time_point deadline,std::stop_token stop={})
            -> nex::capy::task<std::expected<HttpResponse,HttpError>> {
            return exchange_http(path,limit,deadline,body,{},false,false,{},{},stop);
        }
