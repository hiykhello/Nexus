export module tls.tls12_schedule;
import std;
import tls.schedule;

export namespace tls {
    // Full TLS 1.2 ECDHE handshake with the Extended Master Secret extension.
    struct Tls12Keys {
        Secret master;
        Secret key_block;
    };
    [[nodiscard]] auto tls12_keys(crypto::Hash hash,std::span<std::uint8_t const> shared,
        std::span<std::uint8_t const,32> client_random,std::span<std::uint8_t const,32> server_random,
        std::span<std::uint8_t const> session_hash,std::size_t key_size,std::size_t iv_size=4) -> std::expected<Tls12Keys,crypto::Error>;
    [[nodiscard]] auto tls12_finished(crypto::Hash hash,Secret const& master,bool server,
        std::span<std::uint8_t const> transcript_hash) -> std::expected<Secret,crypto::Error>;
}

module :private;

namespace tls {
    namespace {
        auto tls12_prf(crypto::Hash hash,std::span<std::uint8_t const> secret,std::string_view label,
            std::span<std::uint8_t const> seed,std::size_t size) -> std::expected<Secret,crypto::Error> {
            crypto::Bytes input(label.begin(),label.end());
            input.insert(input.end(),seed.begin(),seed.end());
            auto initial=crypto::hmac(hash,secret,input);
            if (!initial) return std::unexpected(initial.error());
            Secret a(std::move(*initial));
            crypto::Bytes output(size);
            struct Clear { crypto::Bytes& bytes; ~Clear(){crypto::cleanse(bytes);} } clear{output};
            auto combined=crypto::Bytes(a.view().size()+input.size());
            Clear clear_combined{combined};
            std::ranges::copy(input,combined.begin()+static_cast<std::ptrdiff_t>(a.view().size()));
            std::size_t offset=0;
            while (offset<size) {
                std::ranges::copy(a.view(),combined.begin());
                auto next_bytes=crypto::hmac(hash,secret,combined);
                if (!next_bytes) return std::unexpected(next_bytes.error());
                Secret block(std::move(*next_bytes));
                auto count=std::min(block.view().size(),size-offset);
                std::ranges::copy(block.view().first(count),output.begin()+static_cast<std::ptrdiff_t>(offset));
                offset+=count;
                if (offset<size) {
                    auto next_a=crypto::hmac(hash,secret,a.view());
                    if (!next_a) return std::unexpected(next_a.error());
                    a=Secret(std::move(*next_a));
                }
            }
            return Secret(std::move(output));
        }
    }

    auto tls12_keys(crypto::Hash hash,std::span<std::uint8_t const> shared,
        std::span<std::uint8_t const,32> client_random,std::span<std::uint8_t const,32> server_random,
        std::span<std::uint8_t const> session_hash,std::size_t key_size,std::size_t iv_size) -> std::expected<Tls12Keys,crypto::Error> {
        auto master=tls12_prf(hash,shared,"extended master secret",session_hash,48);
        if (!master) return std::unexpected(master.error());
        std::array<std::uint8_t,64> randoms;
        std::ranges::copy(server_random,randoms.begin());
        std::ranges::copy(client_random,randoms.begin()+32);
        auto key_block=tls12_prf(hash,master->view(),"key expansion",randoms,2*(key_size+iv_size));
        if (!key_block) return std::unexpected(key_block.error());
        return Tls12Keys{std::move(*master),std::move(*key_block)};
    }

    auto tls12_finished(crypto::Hash hash,Secret const& master,bool server,
        std::span<std::uint8_t const> transcript_hash) -> std::expected<Secret,crypto::Error> {
        return tls12_prf(hash,master.view(),server ? "server finished" : "client finished",transcript_hash,12);
    }
}
