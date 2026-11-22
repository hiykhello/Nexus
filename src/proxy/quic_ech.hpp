    namespace quic_ech {
        struct Profile {
            std::optional<quic::EchConfig> config;
            std::string dns_name;
            using Result = std::expected<std::optional<quic::EchConfig>, std::string>;

            static auto load(config::QuicEchOptions const&, std::string_view, bool)
                -> std::expected<Profile, std::string>;
            auto resolve(Session&, nex::corosio::io_context&, DnsSlot&, std::optional<std::size_t>, std::uint16_t,
                         Clock::time_point) const -> nex::capy::task<Result>;
        };
    }
