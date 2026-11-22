#pragma once

        template<class Carrier>
        class HttpPool {
            struct Key {
                TcpSocketOptions options;
                std::shared_ptr<RouteSnapshot const> route;
                std::shared_ptr<dns::detail::TransportSnapshot const> dns_transports;
                std::optional<std::string> inbound,user,source_interface;
            };
            struct Slot {
                Key key;
                std::shared_ptr<Carrier> carrier;
                xhttp::Mux::Ticket ticket;
                Clock::time_point idle_since{};
            };
            nex::corosio::io_context& context_;
            xhttp::Mux mux_;
            std::vector<std::optional<Slot>> slots_;
            nex::capy::async_event changed_;
            bool stopped_=false;

            auto sweep(Clock::time_point now) noexcept -> void {
                for (auto& slot:slots_) {
                    if (!slot) continue;
                    auto ticket=slot->ticket;
                    if (slot->carrier->failed() ||
                        (mux_.idle(ticket) && now-slot->idle_since>=std::chrono::seconds(2)))
                        mux_.retire(ticket);
                    if (!mux_.reclaimable(ticket,now)) continue;
                    mux_.remove(ticket);
                    slot->carrier->retire();
                    slot.reset();
                    changed_.set();
                }
            }
            auto release(xhttp::Mux::Ticket ticket) noexcept -> void {
                if (!mux_.release(ticket)) return;
                auto now=Clock::now();
                if (mux_.idle(ticket)) slots_[ticket.slot]->idle_since=now;
                sweep(now);
                changed_.set();
            }
        public:
            class Lease {
                friend class HttpPool;
                HttpPool* pool_=nullptr;
                xhttp::Mux::Ticket ticket_{};
                std::shared_ptr<Carrier> carrier_;
                Lease(HttpPool& pool,Slot const& slot)
                    :pool_(&pool),ticket_(slot.ticket),carrier_(slot.carrier) {}
            public:
                Lease()=default;
                Lease(Lease const&)=delete;
                auto operator=(Lease const&) -> Lease& = delete;
                Lease(Lease&& other) noexcept
                    :pool_(std::exchange(other.pool_,nullptr)),ticket_(other.ticket_),carrier_(std::move(other.carrier_)) {}
                auto operator=(Lease&& other) noexcept -> Lease& {
                    reset();
                    pool_=std::exchange(other.pool_,nullptr);
                    ticket_=other.ticket_;
                    carrier_=std::move(other.carrier_);
                    return *this;
                }
                ~Lease() {reset();}
                auto reset() noexcept -> void {
                    if (auto* pool=std::exchange(pool_,nullptr)) pool->release(ticket_);
                    carrier_.reset();
                }
                explicit operator bool() const noexcept {return carrier_!=nullptr;}
                auto operator->() const noexcept -> Carrier* {return carrier_.get();}
                auto request() noexcept -> bool {
                    return !carrier_->failed() && pool_->mux_.request(ticket_,Clock::now());
                }
            };

            HttpPool(nex::corosio::io_context& context,xhttp::MuxLimits limits)
                :context_(context),mux_(limits),slots_(limits.connections) {}
            auto tick() noexcept -> void {sweep(Clock::now());}
            auto stop() noexcept -> void {
                stopped_=true;
                for (auto& slot:slots_) if (slot) slot->carrier->retire();
                changed_.set();
            }
            auto acquire(Session& session,Peer const& peer,std::optional<std::size_t> bootstrap,
                TcpSocketOptions const& options,Clock::time_point until) -> nex::capy::task<Lease> {
                auto matches=[&](std::size_t index) noexcept {
                    auto const& key=slots_[index]->key;
                    return options==key.options && (!bootstrap || (session.route_snapshot==key.route &&
                        session.dns_transport_override==key.dns_transports && session.inbound==key.inbound && session.auth_user==key.user &&
                        session.source_interface==key.source_interface));
                };
                while (!stopped_ && !session.closed && Clock::now()<until) {
                    auto now=Clock::now();
                    sweep(now);
                    auto selection=mux_.acquire(now,matches);
                    if (!selection) {
                        for (auto& slot:slots_) {
                            if (slot && mux_.idle(slot->ticket) && !matches(slot->ticket.slot))
                                mux_.retire(slot->ticket);
                        }
                        sweep(now);
                        selection=mux_.acquire(now,matches);
                    }
                    if (!selection) {
                        changed_.clear();
                        auto [error]=co_await nex::corosio::timeout(changed_.wait(),until);
                        if (error) break;
                        continue;
                    }
                    auto ticket=selection->ticket;
                    auto& slot=slots_[ticket.slot];
                    if (selection->create) {
                        try {
                            auto copy=[](std::optional<std::string_view> value) -> std::optional<std::string> {
                                if (value) return std::string(*value);
                                return {};
                            };
                            Key key{options};
                            if (bootstrap) key={options,session.route_snapshot,session.dns_transport_override,copy(session.inbound),copy(session.auth_user),
                                copy(session.source_interface)};
                            slot.emplace(std::move(key),std::make_shared<Carrier>(session,context_,peer,bootstrap,options),ticket);
                        } catch (...) {
                            mux_.release(ticket);
                            mux_.remove(ticket);
                            changed_.set();
                            throw;
                        }
                    }
                    Lease lease(*this,*slot);
                    if (selection->create) {
                        auto carrier=slot->carrier;
                        if (!co_await carrier->connect(carrier,context_,until)) co_return Lease{};
                    } else if (!co_await lease->wait_ready(until)) co_return Lease{};
                    if (session.closed || stopped_) co_return Lease{};
                    lease->record_peer(session);
                    co_return std::move(lease);
                }
                co_return Lease{};
            }
        };

        template<class Carrier>
        class HttpWorker {
            nex::capy::async_event stopping_;
            bool stopped_=false;
            static auto for_version(xhttp::MuxLimits limits,xhttp::HttpVersion version) noexcept -> xhttp::MuxLimits {
                if (version==xhttp::HttpVersion::http1) limits.concurrency=1;
                return limits;
            }
            auto run() -> nex::capy::task<> {
                while (!stopped_) {
                    auto [error]=co_await nex::corosio::timeout(stopping_.wait(),Clock::now()+std::chrono::seconds(1));
                    if (stopped_ || error!=nex::capy::cond::timeout) break;
                    up.tick();
                    down.tick();
                }
            }
        public:
            nex::corosio::io_context& context;
            HttpPool<Carrier> up,down;
            HttpWorker(nex::corosio::io_context& io,xhttp::MuxLimits limits,xhttp::HttpVersion upload,xhttp::HttpVersion download)
                :context(io),up(io,for_version(limits,upload)),down(io,for_version(limits,download)) {}
            static auto start(std::shared_ptr<HttpWorker> worker) -> void {
                nex::capy::run_async(worker->context.get_executor(),[worker]{},[worker](std::exception_ptr){worker->stop();})(worker->run());
            }
            auto stop() noexcept -> void {
                stopped_=true;
                stopping_.set();
                up.stop();
                down.stop();
            }
        };
