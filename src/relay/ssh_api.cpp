module relay;
import std;
import proxy.v4;

namespace relay {
    auto Server::add_ssh(std::string_view host, std::uint16_t port, std::string_view user,
        std::optional<std::string_view> password_file, std::optional<std::string_view> private_key_file,
        std::span<std::array<std::uint8_t, 32> const> host_key_sha256, std::string_view cipher,
        std::optional<std::size_t> bootstrap, std::uint32_t timeout_ms, std::uint32_t keepalive_ms,
        std::size_t max_sessions, TcpSocketOptions options, bool fast_open) -> std::expected<std::size_t, std::string> {
        if (running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty())
            return std::unexpected("stop the server before changing the outbound");
#ifdef NEXUS_ENABLE_SSH
        if (outbounds.size() >= 256) return std::unexpected("too many tunnel outbounds");
        if (bootstrap && (!dns_routing || *bootstrap >= dns_routing->resolver_count()))
            return std::unexpected("invalid bootstrap resolver");
        auto factory = make_ssh_factory(host, port, user, password_file, private_key_file,
            host_key_sha256, cipher, bootstrap, timeout_ms, keepalive_ms, max_sessions, options, fast_open);
        if (!factory) return std::unexpected(factory.error());
        auto index = outbounds.size() + 2;
        outbounds.push_back(std::move(*factory));
        if (bootstrap && (!max_bootstrap_index || *bootstrap > *max_bootstrap_index)) max_bootstrap_index = bootstrap;
        return index;
#else
        (void)host; (void)port; (void)user; (void)password_file; (void)private_key_file;
        (void)host_key_sha256; (void)cipher; (void)bootstrap; (void)timeout_ms;
        (void)keepalive_ms; (void)max_sessions; (void)options; (void)fast_open;
        return std::unexpected("SSH outbound is not available in this build");
#endif
    }
}
