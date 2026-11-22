module tls.fingerprint;
import std;

namespace tls {
    auto parse_fingerprint(std::string_view name) noexcept -> std::optional<Fingerprint> {
        if (name=="native") return Fingerprint::native;
        if (name=="tls13-grease") return Fingerprint::tls13_grease;
        if (name=="tls13-randomized") return Fingerprint::tls13_randomized;
        if ((name=="chrome" || name=="chrome-133")) return Fingerprint::chrome;
        if ((name=="firefox" || name=="firefox-135")) return Fingerprint::firefox;
        if ((name=="safari" || name=="safari-18")) return Fingerprint::safari;
        if (name=="ios") return Fingerprint::ios;
        if (name=="android") return Fingerprint::android;
        if (name=="edge") return Fingerprint::edge;
        if (name=="random") return Fingerprint::random;
        if (name=="tls12") return Fingerprint::tls12;
        return std::nullopt;
    }
    auto fingerprint_name(Fingerprint profile) noexcept -> std::string_view {
        switch (profile) {
        case Fingerprint::native: return "native";
        case Fingerprint::tls13_grease: return "tls13-grease";
        case Fingerprint::tls13_randomized: return "tls13-randomized";
        case Fingerprint::chrome: return "chrome";
        case Fingerprint::firefox: return "firefox";
        case Fingerprint::safari: return "safari";
        case Fingerprint::ios: return "ios";
        case Fingerprint::android: return "android";
        case Fingerprint::edge: return "edge";
        case Fingerprint::random: return "random";
        case Fingerprint::tls12: return "tls12";
        }
        return "native";
    }
    auto make_profile_fingerprint_config(Fingerprint profile,std::uint16_t primary_group,bool hybrid_only,
        HandshakeTransport transport,std::optional<std::uint16_t> record_size_limit) -> FingerprintConfig {
        FingerprintConfig config;
        config.profile=profile;
        config.allow_tls12=!hybrid_only;
        if (transport==HandshakeTransport::tcp) config.record_size_limit=record_size_limit;
        if (primary_group==0x11ec) {
            config.shares=FingerprintShares::hybrid;
            if (hybrid_only) {
                config.group_count=1;config.group_order[0]=0x11ec;
                config.key_share_count=1;config.key_share_groups[0]=0x11ec;
            } else if (profile!=Fingerprint::native && profile!=Fingerprint::tls13_grease && profile!=Fingerprint::tls13_randomized) {
                config.group_count=4;config.group_order={0x11ec,29,23,24,25};
                config.key_share_count=2;config.key_share_groups={0x11ec,29};
            }
        } else {
            if (profile==Fingerprint::native || profile==Fingerprint::tls13_grease || profile==Fingerprint::tls13_randomized) {
                config.group_count=1;config.group_order[0]=primary_group;
                config.key_share_count=1;config.key_share_groups[0]=primary_group;
            } else {
                config.group_order[0]=primary_group;
                std::uint8_t count=1;
                for (std::uint16_t candidate:{std::uint16_t{29},std::uint16_t{23},std::uint16_t{24}}) {
                    if (candidate!=primary_group) config.group_order[count++]=candidate;
                }
                config.group_count=count;
                config.key_share_count=1;config.key_share_groups={primary_group,23};
            }
        }
        return config;
    }
}
