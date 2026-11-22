// Included in the Client template after its module imports.
        struct OutboundPacket { std::uint64_t stream = 0; std::vector<std::uint8_t> payload; };
        struct OutboundView { std::uint64_t stream = 0; std::span<std::uint8_t const> payload; };

        struct IpSink {
            std::deque<std::vector<std::uint8_t>>& rx_dgrams;
            nex::capy::async_event& changed_event;
            std::array<AddressEntry, 8> addresses;
            std::array<RouteEntry, 16> routes_list;
            std::size_t address_count = 0, route_count = 0;
            std::uint64_t epoch = 0, route_epoch = 0;
            bool requested_v4 = false, requested_v6 = false;

            auto assigned(std::span<AddressEntry const> v) noexcept -> bool {
                for (auto const& address : v) {
                    if (!address.request_id) continue;
                    if (address.request_id != address.version ||
                        !(address.version == 4 ? requested_v4 : requested_v6)) return false;
                }
                std::ranges::copy(v, addresses.begin());
                address_count = v.size();
                ++epoch;
                changed_event.set();
                return true;
            }
            auto routes(std::span<RouteEntry const> v) noexcept -> bool {
                if (route_epoch && std::ranges::equal(v, std::span(routes_list).first(route_count),
                    [](RouteEntry const& a, RouteEntry const& b) {
                        return a.version == b.version && a.protocol == b.protocol && a.first == b.first && a.last == b.last;
                    })) return true;
                std::ranges::copy(v, routes_list.begin());
                route_count = v.size();
                ++route_epoch;
                changed_event.set();
                return true;
            }
            auto requested(std::span<AddressEntry const>) noexcept -> bool { return true; }
            auto packet(std::span<std::uint8_t const> pkt) noexcept -> void {
                if (rx_dgrams.size() >= 256) return;
                try { rx_dgrams.emplace_back(pkt.begin(), pkt.end()); }
                catch (std::bad_alloc const&) { return; }
                changed_event.set();
            }
        };

        struct Hooks {
            Registry& registry;
            quic::SessionHandle owner;
            nex::capy::async_event& changed_event;
            bool ready = false;
            bool rejected = false;
            bool conn_closed = false;
            bool ip_mode = false;
            struct Response {
                std::int64_t id;
                std::size_t limit;
                std::optional<std::uint64_t> length;
                HttpResponse result;
                std::size_t received=0,uncredited=0;
                std::vector<std::pair<std::string,std::string>> fields;
                bool streaming=false,reset=false,reset_sent=false,rejected=false,closed=false,returned=false;
                std::optional<std::vector<std::uint8_t>> request;
                bool request_sent=false, headers=false, complete=false, allow_not_modified=false, allow_redirect=false;
            };
            std::array<std::optional<Response>,4> responses;
            bool http_goaway=false;
            std::size_t max_budget = 1200;
            std::int64_t stream = -1;
            std::vector<std::pair<std::string, std::string>> fields;
            std::deque<OutboundPacket> tx_dgrams;
            std::deque<std::vector<std::uint8_t>> rx_dgrams;
            std::vector<std::uint8_t> tx_capsule;
            std::size_t tx_cap_off = 0, tx_cap_acked = 0;
            bool tx_cap_submitted = false, tx_cap_packet = false, requested_addresses = false;
            UdpCapsules<65527> capsules;
            IpSink ip_sink{rx_dgrams, changed_event};
            IpReceiver<IpSink, 65535, 8, 16, 4> ip_rx{ip_sink};
            std::optional<std::pair<std::int64_t, std::uint64_t>> abort;

            Hooks(Registry& r, quic::SessionHandle h, nex::capy::async_event& ev) noexcept
                : registry(r), owner(h), changed_event(ev) {}

            auto changed() noexcept -> void { changed_event.set(); }
            auto h3_closed() noexcept -> void { conn_closed = true; ready = false; }
            auto transport_closed() noexcept -> void { conn_closed = true; ready = false; }
            auto stream_capacity() const noexcept -> std::size_t {return responses.size();}
            auto http_response(std::int64_t id) noexcept -> std::optional<Response>* {
                auto entry=std::ranges::find_if(responses,[id](auto const& item) {return item && item->id==id;});
                return entry==responses.end() ? nullptr : &*entry;
            }
            auto has_http_response(std::int64_t id) const noexcept -> bool {
                return std::ranges::any_of(responses,[id](auto const& item) {return item && item->id==id;});
            }
            auto reject_http(Response& response) noexcept -> int {
                response.rejected=true;
                response.reset=!response.closed && !response.reset_sent;
                changed();
                return 0;
            }
            auto stream_state(std::uint64_t id) noexcept -> Http3StreamState {
                if(has_http_response(static_cast<std::int64_t>(id)))
                    return {Http3StreamKind::no_datagram,true,false};
                return static_cast<std::int64_t>(id) == stream && ready
                    ? Http3StreamState{Http3StreamKind::datagram, true, true}
                    : Http3StreamState{};
            }
            auto datagram(std::uint64_t id, std::span<std::uint8_t const> pkt) -> int {
                if (static_cast<std::int64_t>(id) != stream || !ready) return nex::ngtcp2::err_callback_failure;
                if (ip_mode) {
                    if (ip_rx.datagram(pkt) != IpReceiveStatus::active) {
                        ready = false; abort = {id, 0x33};
                    }
                    changed();
                    return 0;
                }
                auto parsed = parse_proxy_datagram(pkt, true);
                if (!parsed) {
                    ready = false;
                    abort = {id, 0x33};
                    return 0;
                }
                if (parsed->context_id == 0 && rx_dgrams.size() < 256)
                    rx_dgrams.emplace_back(parsed->payload.begin(), parsed->payload.end());
                changed();
                return 0;
            }
            auto datagram_output() -> std::optional<OutboundView> {
                if (tx_dgrams.empty()) return {};
                return OutboundView{tx_dgrams.front().stream, tx_dgrams.front().payload};
            }
            auto datagram_accepted() -> void { if (!tx_dgrams.empty()) tx_dgrams.pop_front(); }
            auto datagram_rejected() -> void { if (!tx_dgrams.empty()) tx_dgrams.pop_front(); }
            auto datagram_budget() const noexcept -> std::size_t { return max_budget; }
            auto closed_cb(std::int64_t id) noexcept -> void { if (id == stream) ready = false; }
            auto closed(std::int64_t id,std::uint64_t,std::uint64_t) noexcept -> void {
                closed_cb(id);
                if (auto* entry=http_response(id)) {
                    if ((*entry)->returned) entry->reset();
                    else {
                        (*entry)->closed=true;
                        if (!(*entry)->complete) (*entry)->rejected=true;
                    }
                }
            }
            auto receive_closed(std::int64_t id, std::uint64_t) noexcept -> void {
                closed_cb(id);
                if (auto* entry=http_response(id); entry && !(*entry)->complete)
                    (void)reject_http(**entry);
            }
            auto send_closed(std::int64_t id, std::uint64_t code) noexcept -> void { receive_closed(id,code); }
            auto begin_headers(std::int64_t id, bool trailers) -> int {
                if (auto* entry=http_response(id)) {
                    (*entry)->fields.clear();
                    return 0;
                }
                if (id!=stream || trailers) return nex::nghttp3::err_callback_failure;
                fields.clear();
                return 0;
            }
            auto header(std::int64_t id,nex::nghttp3::nghttp3_rcbuf* k,nex::nghttp3::nghttp3_rcbuf* v,bool) -> int {
                auto* entry=http_response(id);
                if (entry && (*entry)->rejected) return 0;
                if (!entry && id!=stream) return nex::nghttp3::err_callback_failure;
                auto& target=entry ? (*entry)->fields : fields;
                auto a = nex::nghttp3::nghttp3_rcbuf_get_buf(k);
                auto b = nex::nghttp3::nghttp3_rcbuf_get_buf(v);
                if (target.size()>=16 || a.len>1024 || b.len>1024-a.len)
                    return entry ? reject_http(**entry) : nex::nghttp3::err_callback_failure;
                target.emplace_back(std::string(reinterpret_cast<char const*>(a.base),a.len),
                                    std::string(reinterpret_cast<char const*>(b.base),b.len));
                return 0;
            }
            auto regular_headers(Response& response,bool trailers) -> int {
                if (response.rejected) return 0;
                if (trailers) return response.headers ? 0 : reject_http(response);
                auto& fields=response.fields;
                auto status=std::ranges::find(fields,std::string(":status"),&std::pair<std::string,std::string>::first);
                if(status==fields.end() || status->second.size()!=3)
                    return reject_http(response);
                auto const& value=status->second;
                unsigned code=0;
                auto [end,error]=std::from_chars(value.data(),value.data()+value.size(),code);
                if (error!=std::errc{} || end!=value.data()+value.size())
                    return reject_http(response);
                if (code>=100 && code<200) return 0;
                auto unchanged=code==304 && response.allow_not_modified;
                auto redirect=response.allow_redirect && http::redirect_status(code);
                auto accepted=response.request ? code>=200 && code<300 : code==200 || unchanged || redirect;
                if (response.headers || !accepted) return reject_http(response);
                for(auto const& [name,value]:fields) {
                    if (unchanged) break;
                    if(name=="content-encoding" && !std::ranges::equal(value,std::string_view("identity"),
                        [](char a,char b){return a==b || (a>='A' && a<='Z' && a-'A'+'a'==b);}))
                        return reject_http(response);
                    if(name=="content-length") {
                        std::uint64_t length=0;
                        auto end=value.data()+value.size();
                        auto [parsed,error]=std::from_chars(value.data(),end,length);
                        if(response.length || error!=std::errc{} || parsed!=end || length>response.limit)
                            return reject_http(response);
                        response.length=length;
                    }
                }
                response.result.status=code;
                if (unchanged) response.length=0;
                response.result.fields=std::move(fields);
                response.headers=true;
                changed();
                return 0;
            }
            auto end_headers(std::int64_t id,bool fin,bool trailers) -> int {
                if (auto* entry=http_response(id)) return regular_headers(**entry,trailers);
                if (trailers) return nex::nghttp3::err_callback_failure;
                if (ip_mode) {
                    auto status = std::ranges::find_if(fields, [](auto const& header) { return header.first == ":status"; });
                    if (status != fields.end() && status->second.size() == 3 &&
                        status->second[0] == '1' && status->second != "101") return 0;
                    std::array<http::HeaderField, 16> headers{};
                    for (std::size_t i = 0; i < fields.size(); ++i)
                        headers[i] = {fields[i].first, fields[i].second};
                    ready = !fin && parse_connect_ip_response(std::span(headers).first(fields.size())).has_value();
                    rejected = !ready;
                    changed();
                    return 0;
                }
                for (auto const& [k, v] : fields) {
                    if (k == ":status") {
                        if (v == "200") ready = true;
                        else rejected = true;
                    }
                }
                if (fin && !rejected) return nex::nghttp3::err_callback_failure;
                changed();
                return 0;
            }
            auto defer_body_credit(std::int64_t id) noexcept -> bool {
                auto* entry=http_response(id);
                return entry && (*entry)->streaming && !(*entry)->rejected;
            }
            auto data(std::int64_t id, std::span<std::uint8_t const> bytes) -> int {
                if (auto* entry=http_response(id)) {
                    auto& response=**entry;
                    if (response.rejected) return 0;
                    auto limit=response.length.value_or(response.limit);
                    auto& body=response.result.body;
                    if (!response.headers || bytes.size()>limit-response.received ||
                        (response.streaming && bytes.size()>stream_window-response.uncredited))
                        return reject_http(response);
                    body.append(reinterpret_cast<char const*>(bytes.data()),bytes.size());
                    response.received+=bytes.size();
                    if (response.streaming) {
                        response.uncredited+=bytes.size();
                        changed();
                    }
                    return 0;
                }
                if (id!=stream) return nex::nghttp3::err_callback_failure;
                if (ip_mode) {
                    if (ip_rx.feed(bytes).status != IpReceiveStatus::active) {
                        ready = false; abort = {id, 0x10e};
                    }
                    changed();
                    return 0;
                }
                auto r = capsules.feed(bytes, [&](auto pkt) {
                    if (ready && rx_dgrams.size() < 256) rx_dgrams.emplace_back(pkt.begin(), pkt.end());
                });
                if (r == UdpInput::malformed || r == UdpInput::too_large) {
                    ready = false;
                    abort = {id, 0x10e};
                }
                changed();
                return 0;
            }
            auto take_abort() noexcept -> std::optional<std::pair<std::int64_t, std::uint64_t>> {
                if (abort) return std::exchange(abort,{});
                for (auto& response:responses)
                    if (response && std::exchange(response->reset,false)) {
                        response->reset_sent=true;
                        return std::pair{response->id,std::uint64_t{nex::nghttp3::h3_request_cancelled}};
                    }
                return {};
            }
            auto data_acked(std::int64_t id, std::uint64_t size) -> int {
                if (id == stream && size <= tx_capsule.size() - tx_cap_acked) {
                    tx_cap_acked += size;
                    if (tx_cap_acked == tx_capsule.size()) {
                        tx_capsule.clear(); tx_cap_off = 0; tx_cap_acked = 0; tx_cap_submitted = false;
                    }
                }
                return 0;
            }
            auto end_stream(std::int64_t id) -> int {
                if (auto* entry=http_response(id)) {
                    auto& response=**entry;
                    if (response.rejected) return 0;
                    response.complete=response.headers && (!response.length || response.received==*response.length);
                    if (!response.complete) return reject_http(response);
                    changed();
                    return 0;
                }
                if (id!=stream || rejected) return 0;
                if (ip_mode) { (void)ip_rx.finish(); }
                else {
                    (void)capsules.finish([&](auto pkt) {
                        if (ready && rx_dgrams.size() < 256) rx_dgrams.emplace_back(pkt.begin(), pkt.end());
                    });
                }
                ready = false;
                changed();
                return 0;
            }
            auto shutdown(std::int64_t first_unprocessed) -> int {
                if (first_unprocessed==stream) ready=false;
                http_goaway=true;
                for (auto& response:responses)
                    if (response && response->id>=first_unprocessed && !response->complete)
                        (void)reject_http(*response);
                return 0;
            }
            auto read_data(std::int64_t id, std::span<nex::nghttp3::nghttp3_vec> out, std::uint32_t& flags) -> nex::nghttp3::nghttp3_ssize {
                if (auto* entry=http_response(id); entry && (*entry)->request) {
                    auto& response=**entry;
                    flags=nex::nghttp3::data_flag_eof;
                    auto& request=*response.request;
                    if (response.request_sent || request.empty()) return 0;
                    if (out.empty()) return nex::nghttp3::err_wouldblock;
                    out[0]={request.data(),request.size()};
                    response.request_sent=true;
                    return 1;
                }
                if (id != stream || tx_cap_submitted || tx_cap_off >= tx_capsule.size() || out.empty())
                    return nex::nghttp3::err_wouldblock;
                out[0] = {tx_capsule.data() + tx_cap_off, tx_capsule.size() - tx_cap_off};
                tx_cap_submitted = true;
                flags = nex::nghttp3::data_flag_none;
                return 1;
            }
            auto add_connection_id(nex::ngtcp2::ngtcp2_cid const& id, nex::ngtcp2::ngtcp2_stateless_reset_token const&) noexcept -> int {
                return registry.insert(owner, {id.data, id.datalen}) ? 0 : nex::ngtcp2::err_callback_failure;
            }
            auto remove_connection_id(nex::ngtcp2::ngtcp2_cid const& id) noexcept -> int {
                (void)registry.remove(owner, {id.data, id.datalen});
                return 0;
            }
        };
