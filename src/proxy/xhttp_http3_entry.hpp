#pragma once

    auto Server::prepare_xhttp3(std::string_view certificate,std::string_view key,std::span<std::string const> users,
        std::span<std::string const> names,xhttp::Profile transport) -> std::expected<void,std::string> {
        auto profile=load_xhttp_inbound(certificate,key,users,names,std::move(transport),{});
        if (!profile) return std::unexpected(profile.error());
        auto credential=tls::load_server_credential(certificate,key);
        if (!credential) return std::unexpected(credential.error());
        xhttp3_inbound=std::make_shared<Xhttp3Inbound>(*this,std::move(*profile),std::move(*credential));
        vless_xhttp_inbound=true;
        return {};
    }

    auto Server::start_xhttp3(nex::corosio::endpoint endpoint) -> std::expected<std::uint16_t,std::error_code> {
        if (ordered_tcp || admission) return std::unexpected(std::make_error_code(std::errc::operation_not_supported));
        if (auto active=activate_context();!active) {stop();return std::unexpected(active.error());}
        try {
            if (auto owner=xhttp3_inbound->restart_owner()) xhttp3_inbound=std::move(owner);
            auto bound=xhttp3_inbound->start(endpoint,[this] {record_failure({FailureKind::accept_task,{}});});
            if (!bound) {stop();return std::unexpected(bound.error());}
            bound_listener=*bound;
            inbound_type=Inbound::vless;
            accepting=true;
            return bound->port();
        } catch (...) {
            stop();
            throw;
        }
    }

    auto Server::drain_xhttp3() noexcept -> void {if (xhttp3_inbound) xhttp3_inbound->drain();}
    auto Server::stop_xhttp3() noexcept -> void {if (xhttp3_inbound) xhttp3_inbound->stop();}
