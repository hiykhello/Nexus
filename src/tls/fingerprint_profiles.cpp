module tls.fingerprint;
import std;
import tls.browser_profiles;

namespace tls {
    auto parse_fingerprint(std::string_view name) noexcept -> std::optional<Fingerprint> {
        return utility::parse_tls_fingerprint_id(name);
    }
    auto fingerprint_name(Fingerprint profile) noexcept -> std::string_view {
        return utility::tls_fingerprint_id_name(profile);
    }
    auto fingerprint_baseline(Fingerprint profile) noexcept -> std::string_view {
        return utility::tls_fingerprint_baseline(profile);
    }
    auto make_profile_fingerprint_config(Fingerprint profile,std::uint16_t primary_group,bool hybrid_only,
        HandshakeTransport transport,std::optional<std::uint16_t> record_size_limit) -> FingerprintConfig {
        FingerprintConfig config;
        config.profile=profile;
        config.allow_tls12=!hybrid_only;
        if (transport==HandshakeTransport::tcp) config.record_size_limit=record_size_limit;
        auto spec=browser_preset_spec(profile);
        bool is_browser=spec.browser || profile==Fingerprint::random;
        bool with_p521=spec.include_p521;
        if (primary_group==0x11ec) {
            config.shares=FingerprintShares::hybrid;
            if (hybrid_only) {
                config.group_count=1;config.group_order[0]=0x11ec;
                config.key_share_count=1;config.key_share_groups[0]=0x11ec;
            } else if (is_browser) {
                config.group_count=with_p521 ? 5 : 4;
                config.group_order={0x11ec,29,23,24,25};
                if (spec.third_key_share_p256) {
                    config.key_share_count=3;
                    config.key_share_groups={0x11ec,29,23};
                } else {
                    config.key_share_count=2;
                    config.key_share_groups={0x11ec,29,0};
                }
            }
        } else {
            if (!is_browser) {
                config.group_count=1;config.group_order[0]=primary_group;
                config.key_share_count=1;config.key_share_groups[0]=primary_group;
            } else {
                config.group_order[0]=primary_group;
                std::uint8_t count=1;
                for (std::uint16_t candidate:{std::uint16_t{29},std::uint16_t{23},std::uint16_t{24},std::uint16_t{25}}) {
                    if (candidate==25 && !with_p521) continue;
                    if (candidate!=primary_group) config.group_order[count++]=candidate;
                }
                config.group_count=count;
                if (spec.third_key_share_p256 && primary_group==29) {
                    config.key_share_count=2;
                    config.key_share_groups={29,23,0};
                } else {
                    config.key_share_count=1;
                    config.key_share_groups={primary_group,23,0};
                }
            }
        }
        return config;
    }
}
