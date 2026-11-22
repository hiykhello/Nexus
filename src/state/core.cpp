module state.core;
import std;
import nexus.thirdparty.blake3;

namespace state {
    namespace {
        template<class Integer>
        auto put(std::span<std::byte> bytes, std::size_t offset, Integer value) noexcept -> void {
            for (std::size_t index = 0; index < sizeof(Integer); ++index) {
                bytes[offset + index] = static_cast<std::byte>(value & 0xff);
                value >>= 8;
            }
        }

        template<class Integer>
        auto get(std::span<std::byte const> bytes, std::size_t offset) noexcept -> Integer {
            Integer result = 0;
            for (std::size_t index = 0; index < sizeof(Integer); ++index)
                result |= static_cast<Integer>(std::to_integer<std::uint8_t>(bytes[offset + index])) << (index * 8);
            return result;
        }

        auto digest(std::span<std::byte const> prefix, Fingerprint const& fingerprint,
                    std::span<std::byte const> payload) noexcept -> Fingerprint {
            nex::blake3::blake3_hasher hash;
            nex::blake3::blake3_hasher_init(&hash);
            nex::blake3::blake3_hasher_update(&hash, prefix.data(), prefix.size());
            nex::blake3::blake3_hasher_update(&hash, fingerprint.data(), fingerprint.size());
            if (!payload.empty()) nex::blake3::blake3_hasher_update(&hash, payload.data(), payload.size());
            Fingerprint result;
            nex::blake3::blake3_hasher_finalize(&hash, reinterpret_cast<std::uint8_t*>(result.data()), result.size());
            return result;
        }

        auto valid_tier(Tier tier) noexcept -> bool {
            return tier >= Tier::authority && tier <= Tier::secret;
        }
    }

    auto fingerprint(std::span<std::byte const> bytes) noexcept -> Fingerprint {
        return digest({}, {}, bytes);
    }

    auto encode_header(EnvelopeHeader header, std::span<std::byte const> payload,
                       Fingerprint const& fingerprint) noexcept -> std::expected<EncodedHeader, StateError> {
        if (payload.size() != header.payload_bytes || !valid_tier(header.tier) ||
            header.schema_version == 0 || (header.flags & ~0x03))
            return std::unexpected(StateError{Stage::validate});
        EncodedHeader wire{};
        for (std::size_t i = 0; i < header.magic.size(); ++i) wire[i] = static_cast<std::byte>(header.magic[i]);
        put(wire, 6, header.schema_version);
        wire[8] = static_cast<std::byte>(header.tier);
        wire[9] = static_cast<std::byte>(header.flags);
        put(wire, 12, header.payload_bytes);
        put(wire, 16, header.revision);
        put(wire, 24, header.clear_epoch);
        auto hash = digest(std::span(wire).first<32>(), fingerprint, payload);
        std::ranges::copy(hash, wire.begin() + 32);
        return wire;
    }

    auto decode_header(std::span<std::byte const> wire, EnvelopeSpec const& spec) noexcept
        -> std::expected<EnvelopeHeader, StateError> {
        if (wire.size() != header_bytes) return std::unexpected(StateError{Stage::format});
        for (std::size_t i = 0; i < spec.magic.size(); ++i)
            if (wire[i] != static_cast<std::byte>(spec.magic[i])) return std::unexpected(StateError{Stage::format});
        auto version = get<std::uint16_t>(wire, 6);
        if (version != spec.schema_version) return std::unexpected(StateError{Stage::version});
        auto tier = static_cast<Tier>(wire[8]);
        auto flags = std::to_integer<std::uint8_t>(wire[9]);
        auto bytes = get<std::uint32_t>(wire, 12);
        if (!valid_tier(tier) || tier != spec.tier || (flags & ~0x03) ||
            get<std::uint16_t>(wire, 10) != 0 || bytes > spec.max_payload)
            return std::unexpected(StateError{Stage::format});
        EnvelopeHeader header{spec.magic, version, tier, flags, bytes,
            get<std::uint64_t>(wire, 16), get<std::uint64_t>(wire, 24)};
        std::ranges::copy(wire.subspan(32), header.checksum.begin());
        return header;
    }

    auto verify_payload(std::span<std::byte const> wire, EnvelopeHeader const& header,
                        std::span<std::byte const> payload, Fingerprint const& fingerprint) noexcept
        -> std::expected<void, StateError> {
        if (wire.size() != header_bytes || payload.size() != header.payload_bytes)
            return std::unexpected(StateError{Stage::format});
        if (!std::ranges::equal(digest(wire.first<32>(), fingerprint, payload), wire.subspan(32)))
            return std::unexpected(StateError{Stage::checksum});
        return {};
    }

    auto describe(Stage stage) noexcept -> std::string_view {
        constexpr std::array names{
            "validate request", "open private directory", "open private instance lock", "lock instance", "open file",
            "read file", "invalid envelope", "unsupported schema", "checksum mismatch", "invalid revision",
            "stale clear epoch", "remove staging file", "create staging file", "write file", "sync staging file",
            "close staging file", "replace snapshot", "sync directory", "isolate damaged file", "queue capacity",
            "owner stopped", "start worker", "remove cache blob", "remove cache index", "scan cache directory", "hash cache content"
        };
        return names[std::to_underlying(stage)];
    }

    auto ClearEpoch::advance(this ClearEpoch& self) -> std::expected<std::uint64_t, StateError> {
        std::lock_guard lock(self.gate_);
        auto epoch = self.current();
        if (epoch == std::numeric_limits<std::uint64_t>::max())
            return std::unexpected(StateError{Stage::validate});
        self.epoch_.store(++epoch, std::memory_order_release);
        return epoch;
    }

    auto ClearEpoch::publish(this ClearEpoch& self, std::uint64_t expected,
                             std::function_ref<std::expected<void, StateError>()> action)
        -> std::expected<void, StateError> {
        std::lock_guard lock(self.gate_);
        if (expected != self.current()) return std::unexpected(StateError{Stage::stale_epoch});
        return action();
    }
}
