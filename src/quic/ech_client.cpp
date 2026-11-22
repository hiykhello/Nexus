module quic.ech_client;
import std;
import crypto;
import tls.handshake;
import tls.handshake_secrets;
import tls.schedule;
import tls.transcript;

namespace quic {
    namespace {
        using Bytes = std::span<const std::uint8_t>;
        using Error = EchHandshakeError;
        constexpr std::uint16_t outer_extensions = 0xfd00;
        constexpr std::size_t hello_limit = 65531;

        auto append16(crypto::Bytes& bytes, std::size_t value) -> void {
            bytes.push_back(static_cast<std::uint8_t>(value >> 8));
            bytes.push_back(static_cast<std::uint8_t>(value));
        }

        auto public_sni(std::string_view name) -> tls::Extension {
            tls::Extension extension{0, {}};
            append16(extension.data, name.size() + 3);
            extension.data.push_back(0);
            append16(extension.data, name.size());
            extension.data.insert(extension.data.end(), name.begin(), name.end());
            return extension;
        }

        auto copy_to_outer(std::uint16_t type) noexcept -> bool {
            // TLS negotiation fields and QUIC transport parameters carry no
            // origin identity. Keep private extension data inside the envelope.
            constexpr std::array<std::uint16_t,8> allowed{10, 13, 16, 43, 44, 50, 51, 0x39};
            return std::ranges::contains(allowed, type);
        }

        auto encode_inner(tls::ClientHello const& inner, std::uint8_t maximum_name_length)
            -> std::expected<crypto::Bytes, Error> {
            auto sni = inner.extension(0);
            if (sni && sni->data.size() < 5) return std::unexpected(Error::malformed);
            tls::ClientHello compressed = inner;
            compressed.session_id.clear();
            auto share = std::ranges::find(compressed.extensions, std::uint16_t{51}, &tls::Extension::type);
            if (share == compressed.extensions.end()) return std::unexpected(Error::malformed);
            *share = {outer_extensions, {2, 0, 51}};
            auto encoded = compressed.encode(hello_limit);
            if (!encoded) return std::unexpected(Error::malformed);

            auto pad_for_name = std::size_t{maximum_name_length};
            if (sni) pad_for_name -= std::min(pad_for_name, sni->data.size() - 5);
            else pad_for_name += 9;
            auto padded = (encoded->size() + pad_for_name + 31) & ~std::size_t{31};
            if (padded + crypto::HpkeSender::overhead > 65535) return std::unexpected(Error::malformed);
            encoded->resize(padded);
            return std::move(*encoded);
        }

        auto same_name(Bytes server_name, std::string_view public_name) noexcept -> bool {
            if (server_name.size() < 5 || server_name.size() - 5 != public_name.size()) return false;
            auto lower = [](unsigned char c) { return c >= 'A' && c <= 'Z' ? c + ('a'-'A') : c; };
            return std::ranges::equal(server_name.subspan(5), public_name,
                [&](auto inner, auto outer) { return lower(inner) == lower(outer); });
        }
    }

    EchClient::EchClient(EchConfig const& config, crypto::HpkeSender sender)
        : public_name_(config.public_name), config_id_(config.id), maximum_name_length_(config.maximum_name_length),
          aead_(config.aead), sender_(std::move(sender)) {}

    auto EchClient::create(EchConfig const& config) -> std::optional<EchClient> {
        crypto::Bytes info{'t', 'l', 's', ' ', 'e', 'c', 'h', 0};
        info.append_range(config.wire);
        auto sender = crypto::HpkeSender::create(static_cast<crypto::HpkeAead>(config.aead), config.public_key, info);
        if (!sender) return {};
        EchClient client(config, std::move(*sender));
        if (!crypto::random_bytes(client.outer_random_)) return {};
        return client;
    }

    auto EchClient::seal(tls::ClientHello const& inner, bool retry) -> std::expected<crypto::Bytes, Error> {
        if (inner.extension(41) || inner.extension(42) || inner.extension(outer_extensions))
            return std::unexpected(Error::malformed);
        if (auto name = inner.extension(0); name && same_name(name->data,public_name_))
            return std::unexpected(Error::rejected);
        auto marker = inner.extension(ech_extension);
        if (!marker || marker->data.size() != 1 || marker->data[0] != 1) return std::unexpected(Error::malformed);
        auto plaintext = encode_inner(inner, maximum_name_length_);
        if (!plaintext) return std::unexpected(plaintext.error());

        tls::ClientHello outer = inner;
        outer.random = outer_random_;
        std::erase_if(outer.extensions, [](auto const& extension) { return !copy_to_outer(extension.type); });
        outer.extensions.insert(outer.extensions.begin(), public_sni(public_name_));
        tls::Extension ech{ech_extension, {0, 0, 1}};
        append16(ech.data, aead_);
        ech.data.push_back(config_id_);
        auto encapsulation = retry ? Bytes{} : Bytes(sender_.encapsulation());
        append16(ech.data, encapsulation.size());
        ech.data.append_range(encapsulation);
        auto payload_length = plaintext->size() + crypto::HpkeSender::overhead;
        append16(ech.data, payload_length);
        auto payload_offset = ech.data.size();
        ech.data.resize(payload_offset + payload_length);
        outer.extensions.push_back(std::move(ech));
        auto aad = outer.encode(hello_limit);
        if (!aad) return std::unexpected(Error::malformed);
        auto payload = std::span(outer.extensions.back().data).subspan(payload_offset);
        if (!sender_.seal(payload, *plaintext, *aad)) return std::unexpected(Error::crypto);
        std::ranges::copy(payload, aad->end() - payload.size());
        auto wire = tls::HandshakeDecoder::encode(1, *aad, hello_limit);
        if (!wire) return std::unexpected(Error::malformed);
        return std::move(*wire);
    }

    auto verify_ech_acceptance(Bytes first_inner, Bytes server_hello, Bytes retry, Bytes second_inner)
        -> std::expected<void, Error> {
        if (first_inner.size() < 38 || server_hello.size() < 4 || retry.empty() != second_inner.empty())
            return std::unexpected(Error::malformed);
        auto parsed = tls::ServerHello::parse(server_hello.subspan(4));
        if (!parsed) return std::unexpected(Error::malformed);
        auto spec = tls::cipher_spec(parsed->cipher_suite);
        if (!spec) return std::unexpected(Error::malformed);
        auto transcript = tls::Transcript::create(spec->hash);
        if (!transcript || !transcript->append(first_inner)) return std::unexpected(Error::crypto);

        constexpr std::size_t confirmation_length = 8;
        std::array<std::uint8_t,confirmation_length> confirmation;
        auto extension = std::ranges::find(parsed->extensions, ech_extension, &tls::Extension::type);
        bool hrr = parsed->is_retry();
        if (hrr) {
            if (!retry.empty()) return std::unexpected(Error::malformed);
            if (extension == parsed->extensions.end()) return std::unexpected(Error::rejected);
            if (extension->data.size() != confirmation.size()) return std::unexpected(Error::malformed);
            std::ranges::copy(extension->data, confirmation.begin());
            std::ranges::fill(extension->data, 0);
            if (!transcript->hello_retry_request()) return std::unexpected(Error::crypto);
        } else {
            if (extension != parsed->extensions.end()) return std::unexpected(Error::malformed);
            auto suffix = std::span(parsed->random).last<confirmation_length>();
            std::ranges::copy(suffix, confirmation.begin());
            std::ranges::fill(suffix, 0);
            if (!retry.empty() && (!transcript->hello_retry_request() || !transcript->append(retry) ||
                                   !transcript->append(second_inner))) return std::unexpected(Error::crypto);
        }
        auto zeroed = parsed->encode();
        if (!zeroed) return std::unexpected(Error::malformed);
        auto framed = tls::HandshakeDecoder::encode(2, *zeroed, hello_limit);
        if (!framed || !transcript->append(*framed)) return std::unexpected(Error::malformed);
        auto hash = transcript->snapshot();
        auto prk = crypto::hkdf_extract(spec->hash, {}, first_inner.subspan(6, 32));
        if (!hash || !prk) return std::unexpected(Error::crypto);
        tls::Secret secret(std::move(*prk));
        auto expected = tls::expand_label(spec->hash, secret.view(),
            hrr ? "hrr ech accept confirmation" : "ech accept confirmation", *hash, confirmation.size());
        if (!expected) return std::unexpected(Error::crypto);
        if (!crypto::constant_time_equal(expected->view(), confirmation)) return std::unexpected(Error::rejected);
        return {};
    }
}
