// Private native TCP DNS adapter for the transparent listener.
#pragma once
        auto serve_redirect_dns(Session& session,nex::corosio::io_context& context,std::span<std::uint8_t const> prefetched,
            Clock::time_point first_deadline) -> nex::capy::task<> {
            auto source=source_endpoint(session,true);
            if (!source) co_return;
            auto& socket=session.client;
            session.relaying=true;
            session.select_traffic_path(ConnectPath::datagrams);
            auto read=[&](std::span<std::uint8_t> pending,Clock::time_point deadline) -> nex::capy::task<bool> {
                auto size=std::min(pending.size(),prefetched.size());
                std::ranges::copy(prefetched.first(size),pending.begin());
                prefetched=prefetched.subspan(size);
                pending=pending.subspan(size);
                while (!pending.empty()) {
                    auto operation=socket.read_some(nex::capy::mutable_buffer(pending.data(),pending.size()));
                    auto [error,count]=co_await nex::corosio::timeout(std::move(operation),deadline);
                    if (error || !count || count>pending.size()) co_return false;
                    pending=pending.subspan(count);
                }
                co_return true;
            };
            auto send=[&](std::span<std::uint8_t const> pending,Clock::time_point deadline) -> nex::capy::task<bool> {
                while (!pending.empty()) {
                    auto operation=socket.write_some(nex::capy::const_buffer(pending.data(),pending.size()));
                    auto [error,count]=co_await nex::corosio::timeout(std::move(operation),deadline);
                    if (error || !count || count>pending.size()) co_return false;
                    session.count_traffic(false,count);
                    pending=pending.subspan(count);
                }
                co_return true;
            };
            for (unsigned count=0;count<64 && !session.closed;++count) {
                auto deadline=Clock::now()+std::chrono::seconds(5);
                if (!count) deadline=std::min(deadline,first_deadline);
                std::array<std::uint8_t,2> prefix{};
                if (!co_await read(prefix,deadline)) break;
                auto size=(std::size_t(prefix[0])<<8)|prefix[1];
                if (size<12) break;
                auto lease=dns::default_input_budget().acquire(size);
                if (!lease) break;
                dns::Bytes query(size);
                if (!co_await read(query,deadline)) break;
                session.count_traffic(true,query.size()+prefix.size());
                session.touched=Clock::now();
                auto answer=co_await hijack_dns_query(session,context,query,*source,deadline,rules::Network::tcp);
                if (session.closed || Clock::now()>=deadline) break;
                if (!answer) continue;
                if (answer->size()>65535) break;
                prefix={static_cast<std::uint8_t>(answer->size()>>8),static_cast<std::uint8_t>(answer->size())};
                if (!co_await send(prefix,deadline) || !co_await send(*answer,deadline)) break;
                session.touched=Clock::now();
            }
            (void)socket.shutdown(nex::corosio::shutdown_send);
        }
