// Unified FakeIP store for the DNS listener.
#pragma once

    auto unified_fakeip(config::DnsFakeIp const& spec,std::optional<dns::FakeIpIpv6Range> ipv6)
        -> std::expected<std::shared_ptr<dns::FakeIpShared>,std::string> {
        auto first=spec.first,last=spec.last;
        if (last-first>=3) {++first;--last;}
        ::state::FakeIpScope scope{spec.first,spec.last,first,last};
        if (ipv6) {
            std::array<std::uint8_t,13> identity{};
            std::ranges::copy(ipv6->network,identity.begin());
            identity.back()=ipv6->length;
            scope.identity=::state::fingerprint(std::as_bytes(std::span(identity)));
        }
        if (first!=spec.first) scope.exclude_cidrs={{spec.first,spec.first},{spec.last,spec.last}};
        auto opened=::state::FakeIpStore::open(std::filesystem::path(spec.state_directory).parent_path(),
            std::move(scope),spec.per_mapping ? ::state::CrashMode::per_mapping : ::state::CrashMode::range_reserve);
        if (!opened) return std::unexpected(std::format("cannot open FakeIP state ({})",::state::describe(opened.error().stage)));
        std::shared_ptr<::state::FakeIpStore> store(std::move(*opened));
        auto pool=dns::FakeIpPool::create(first,last,std::chrono::seconds(spec.ttl_seconds),std::chrono::seconds(5));
        if (!pool) return std::unexpected("cannot create FakeIP pool");
        if (!store->visit_recovered([&](auto const& row) {
            return (*pool)->restore(row.address,row.view,row.domain);
        })) return std::unexpected("invalid recovered FakeIP mapping");
        (*pool)->attach(store.get(),[](void* owner,std::string_view domain,std::uint64_t view)
            -> std::optional<std::uint32_t> {
            auto assigned=static_cast<::state::FakeIpStore*>(owner)->assign(domain,view);
            return assigned ? std::optional(*assigned) : std::nullopt;
        });
        auto shared=std::make_shared<dns::FakeIpShared>(1,std::move(store),ipv6);
        if (!shared->add_pool(spec.first,spec.last,std::move(*pool)) || !shared->seal())
            return std::unexpected("cannot register durable FakeIP pool");
        return shared;
    }
