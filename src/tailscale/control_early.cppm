export module tailscale.control_early;
import std;
import tailscale.control;

export namespace tailscale::control_early {
    struct ChallengeTag;
    using ChallengePublic=control::PublicKey<ChallengeTag>;
    enum class Error {json,schema,capacity,identity};
    struct Info {ChallengePublic challenge;bool present=false;};
    auto parse(std::span<std::uint8_t const> input) -> std::expected<Info,Error>;
}
