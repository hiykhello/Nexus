module relay;
import std;
import rules;
import platform.process_owner;
import corosio;

namespace relay {
    namespace {
        auto endpoint_ip_bytes(io::endpoint const& endpoint, std::array<std::uint8_t, 16>& storage) noexcept
            -> std::span<std::uint8_t const> {
            auto address = endpoint.address();
            if (address.is_v4()) {
                auto bytes = address.to_v4().to_bytes();
                std::ranges::copy(bytes, storage.begin());
                return std::span<std::uint8_t const>(storage.data(), 4);
            }
            auto bytes = address.to_v6().to_bytes();
            std::ranges::copy(bytes, storage.begin());
            return std::span<std::uint8_t const>(storage.data(), 16);
        }
    }

    auto Session::inspect_source_owner(rules::RouteMatcher const& policy, std::optional<io::endpoint> original) -> void {
        auto const* program = ordered_tcp ? &ordered_tcp->program : nullptr;
        auto needs_process = policy.uses_process() || (program && program->uses_process());
        auto needs_uid = policy.uses_source_uid() || (program && program->uses_source_uid());
        if (!needs_process && !needs_uid) return;

        auto peer = accepted_peer(client);
        auto destination = original ? *original : accepted_local(client);
        std::array<std::uint8_t, 16> peer_storage{}, dst_storage{};
        auto peer_bytes = endpoint_ip_bytes(peer, peer_storage);
        auto dst_bytes = endpoint_ip_bytes(destination, dst_storage);
        auto tuple = platform::make_loopback_socket_tuple(false, peer_bytes, peer.port(), dst_bytes, destination.port());
        if (!tuple) return;

        auto owner = platform::lookup_socket_owner(*tuple);
        if (!owner) return;
#if !defined(_WIN32)
        source_uid = owner->uid;
        source_gid = owner->gid;
#endif
        if (!owner->user.empty()) source_user = std::move(owner->user);
        if (needs_process && !owner->executable.empty()) process_path = std::move(owner->executable);
        if (needs_process && !owner->package_name.empty()) package_name = std::move(owner->package_name);
    }
}
