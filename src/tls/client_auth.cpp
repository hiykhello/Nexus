module nexus.tls.client_auth;
import nexus.tls.certificate_verify;
import std;

namespace nexus::tls {
    ClientAuth::ClientAuth(crypto::Hash hash, Transcript&& transcript, Secret&& client, Secret&& server) noexcept
        : hash_(hash), transcript_(std::move(transcript)), client_traffic_(std::move(client)), server_traffic_(std::move(server)) {}
    ClientAuth::ClientAuth(ClientAuth&& o) noexcept
        : state_(o.state_), hash_(o.hash_), transcript_(std::move(o.transcript_)), client_traffic_(std::move(o.client_traffic_)),
          server_traffic_(std::move(o.server_traffic_)), leaf_(std::move(o.leaf_)), finished_(std::move(o.finished_)) { o.state_=State::failed; }
    auto ClientAuth::operator=(ClientAuth&& o) noexcept -> ClientAuth& {
        if (this!=&o) { state_=o.state_; hash_=o.hash_; transcript_=std::move(o.transcript_); client_traffic_=std::move(o.client_traffic_);
            server_traffic_=std::move(o.server_traffic_); leaf_=std::move(o.leaf_); finished_=std::move(o.finished_); o.state_=State::failed; }
        return *this;
    }
    auto ClientAuth::certificate(std::span<std::uint8_t const> m, std::span<std::span<std::uint8_t const> const> anchors,
        PeerNameKind kind, std::span<std::uint8_t const> name, std::int64_t time) -> std::expected<void,ClientAuthError> {
        if (state_!=State::certificate) return std::unexpected(ClientAuthError::invalid_state);
        state_=State::failed;
        if (m.size()<8 || m.size()>4194304 || m[0]!=11 || m[4]!=0) return std::unexpected(ClientAuthError::malformed_certificate);
        auto u24=[&](std::size_t p){ return (std::size_t{m[p]}<<16)|(std::size_t{m[p+1]}<<8)|m[p+2]; };
        if (u24(1)!=m.size()-4 || u24(5)!=m.size()-8) return std::unexpected(ClientAuthError::malformed_certificate);
        std::vector<std::span<std::uint8_t const>> chain;
        for (std::size_t p=8; p<m.size();) {
            if (m.size()-p<5 || chain.size()==16) return std::unexpected(ClientAuthError::malformed_certificate);
            auto len=u24(p); p+=3;
            if (!len || len>m.size()-p || m.size()-p-len<2) return std::unexpected(ClientAuthError::malformed_certificate);
            chain.push_back(m.subspan(p,len)); p+=len;
            if (m[p] || m[p+1]) return std::unexpected(ClientAuthError::malformed_certificate);
            p+=2;
        }
        if (chain.empty()) return std::unexpected(ClientAuthError::malformed_certificate);
        if (!verify_server_certificate_chain(chain,anchors,kind,name,time)) return std::unexpected(ClientAuthError::untrusted_certificate);
        leaf_.assign(chain[0].begin(),chain[0].end());
        if (!transcript_.append(m)) return std::unexpected(ClientAuthError::crypto_error);
        state_=State::signature; return {};
    }
    auto ClientAuth::certificate_verify(std::span<std::uint8_t const> m, std::span<std::uint16_t const> offered) -> std::expected<void,ClientAuthError> {
        if (state_!=State::signature) return std::unexpected(ClientAuthError::invalid_state);
        state_=State::failed;
        auto hash=transcript_.snapshot(); if (!hash) return std::unexpected(ClientAuthError::crypto_error);
        if (!verify_server_certificate_signature(leaf_,hash_,*hash,offered,m)) return std::unexpected(ClientAuthError::invalid_signature);
        if (!transcript_.append(m)) return std::unexpected(ClientAuthError::crypto_error);
        finished_.emplace(hash_,std::move(transcript_),std::move(client_traffic_),std::move(server_traffic_));
        leaf_.clear(); state_=State::finished; return {};
    }
    auto ClientAuth::server_finished(std::span<std::uint8_t const> m) -> std::expected<void,ClientAuthError> {
        if (state_!=State::finished) return std::unexpected(ClientAuthError::invalid_state);
        state_=State::failed;
        if (!finished_->verify_server(m)) return std::unexpected(ClientAuthError::invalid_finished);
        state_=State::client_finished; return {};
    }
    auto ClientAuth::server_finished_hash() const -> std::expected<crypto::Bytes,ClientAuthError> {
        if (state_!=State::client_finished) return std::unexpected(ClientAuthError::invalid_state);
        auto hash=finished_->transcript_hash(); if (!hash) return std::unexpected(ClientAuthError::crypto_error);
        return std::move(*hash);
    }
    auto ClientAuth::client_finished() -> std::expected<crypto::Bytes,ClientAuthError> {
        if (state_!=State::client_finished) return std::unexpected(ClientAuthError::invalid_state);
        state_=State::failed; auto m=finished_->make_client(); if (!m) return std::unexpected(ClientAuthError::crypto_error);
        state_=State::complete; return std::move(*m);
    }
}
