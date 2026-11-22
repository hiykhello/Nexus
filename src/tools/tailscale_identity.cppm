export module cli.tailscale_identity;
import std;
import wireguard.crypto;

export namespace cli::tailscale_identity {
    struct Keys {
        wireguard::SecretKey machine, node;
        int directory = -1;
        Keys() = default;
        Keys(Keys const&) = delete;
        auto operator=(Keys const&) -> Keys& = delete;
        Keys(Keys&&) noexcept;
        ~Keys();
    };

    // A normal endpoint keeps both private identities in one atomic record.
    // Offline validation checks the directory and any existing key record.
    auto load(std::string_view state_dir, bool ephemeral, bool check)
        -> std::expected<Keys,std::string>;
}
