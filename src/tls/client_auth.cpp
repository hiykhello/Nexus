module tls.client_auth;
import tls.certificate_verify;
import std;

namespace tls {
    namespace {
        auto u16(std::span<std::uint8_t const> bytes,std::size_t offset) noexcept -> std::size_t {
            return (std::size_t{bytes[offset]}<<8)|bytes[offset+1];
        }

        auto valid_certificate_extensions(std::span<std::uint8_t const> extensions,bool status,bool sct) noexcept -> bool {
            while (!extensions.empty()) {
                if (extensions.size()<4) return false;
                auto type=u16(extensions,0);
                auto length=u16(extensions,2);
                extensions=extensions.subspan(4);
                if (length>extensions.size()) return false;
                auto data=extensions.first(length);
                switch (type) {
                case 5:
                    if (!status || data.size()<5 || data[0]!=1 ||
                        ((std::size_t{data[1]}<<16)|(std::size_t{data[2]}<<8)|data[3])!=data.size()-4) return false;
                    status=false;
                    break;
                case 18:
                    if (!sct || data.size()<5 || u16(data,0)!=data.size()-2) return false;
                    for (data=data.subspan(2);!data.empty();) {
                        if (data.size()<3) return false;
                        auto entry=u16(data,0);
                        if (!entry || entry>data.size()-2) return false;
                        data=data.subspan(2+entry);
                    }
                    sct=false;
                    break;
                default:
                    return false;
                }
                extensions=extensions.subspan(length);
            }
            return true;
        }
    }
    ClientAuth::ClientAuth(crypto::Hash hash,Transcript&& transcript,Secret&& client,Secret&& server,
        bool status_requested,bool sct_requested) noexcept
        : hash_(hash),transcript_(std::move(transcript)),client_traffic_(std::move(client)),server_traffic_(std::move(server)),
          status_requested_(status_requested),sct_requested_(sct_requested) {}
    auto ClientAuth::resumed(crypto::Hash hash,Transcript&& transcript,Secret&& client,Secret&& server) noexcept -> ClientAuth {
        ClientAuth result(hash,std::move(transcript),std::move(client),std::move(server));
        result.finished_.emplace(hash,std::move(result.transcript_),std::move(result.client_traffic_),std::move(result.server_traffic_));
        result.state_=State::finished;return result;
    }
    ClientAuth::ClientAuth(ClientAuth&& o) noexcept
        : state_(o.state_), hash_(o.hash_), transcript_(std::move(o.transcript_)), client_traffic_(std::move(o.client_traffic_)),
          server_traffic_(std::move(o.server_traffic_)), leaf_(std::move(o.leaf_)),status_requested_(o.status_requested_),sct_requested_(o.sct_requested_),finished_(std::move(o.finished_)) { o.state_=State::failed; }
    auto ClientAuth::operator=(ClientAuth&& o) noexcept -> ClientAuth& {
        if (this!=&o) { state_=o.state_; hash_=o.hash_; transcript_=std::move(o.transcript_); client_traffic_=std::move(o.client_traffic_);
            server_traffic_=std::move(o.server_traffic_); leaf_=std::move(o.leaf_);
            status_requested_=o.status_requested_;sct_requested_=o.sct_requested_; finished_=std::move(o.finished_); o.state_=State::failed; }
        return *this;
    }
    auto ClientAuth::certificate(std::span<std::uint8_t const> m, std::span<std::span<std::uint8_t const> const> anchors,
        PeerNameKind kind, std::span<std::uint8_t const> name, std::int64_t time) -> std::expected<void,ClientAuthError> {
        try {
            return certificate_with(m,[&](std::span<std::span<std::uint8_t const> const> chain) {
                return verify_server_certificate_chain(chain,anchors,kind,name,time);
            });
        } catch (...) { state_=State::failed; throw; }
    }
    auto ClientAuth::certificate(std::span<std::uint8_t const> m,CertificateVerifier const& verifier,
        std::span<std::uint8_t const> transcript_wire) -> std::expected<void,ClientAuthError> {
        auto chain=certificate_chain(m); if (!chain) return std::unexpected(chain.error());
        if (!verifier || !verifier(*chain)) return std::unexpected(ClientAuthError::untrusted_certificate);
        return accept_certificate(transcript_wire.empty() ? m : transcript_wire,*chain);
    }
    auto ClientAuth::certificate_chain(std::span<std::uint8_t const> m) -> std::expected<std::vector<std::span<std::uint8_t const>>,ClientAuthError> {
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
            auto extensions=u16(m,p);
            p+=2;
            if (extensions>m.size()-p || !valid_certificate_extensions(m.subspan(p,extensions),status_requested_,sct_requested_))
                return std::unexpected(ClientAuthError::malformed_certificate);
            p+=extensions;
        }
        if (chain.empty()) return std::unexpected(ClientAuthError::malformed_certificate);
        return chain;
    }
    auto ClientAuth::accept_certificate(std::span<std::uint8_t const> m,std::span<std::span<std::uint8_t const> const> chain) -> std::expected<void,ClientAuthError> {
        leaf_.assign(chain[0].begin(),chain[0].end());
        if (!transcript_.append(m)) return std::unexpected(ClientAuthError::crypto_error);
        state_=State::signature; return {};
    }
    auto ClientAuth::certificate_verify(std::span<std::uint8_t const> m, std::span<std::uint16_t const> offered) -> std::expected<void,ClientAuthError> {
        if (state_!=State::signature) return std::unexpected(ClientAuthError::invalid_state);
        state_=State::failed;
        auto hash=transcript_.snapshot(); if (!hash) return std::unexpected(ClientAuthError::crypto_error);
        auto verified=verify_server_certificate_signature(leaf_,hash_,*hash,offered,m);
        if (!verified) return std::unexpected(verified.error()==CertificateVerifyError::crypto_error ? ClientAuthError::crypto_error : ClientAuthError::invalid_signature);
        if (!transcript_.append(m)) return std::unexpected(ClientAuthError::crypto_error);
        finished_.emplace(hash_,std::move(transcript_),std::move(client_traffic_),std::move(server_traffic_));
        leaf_.clear(); state_=State::finished; return {};
    }
    auto ClientAuth::server_finished(std::span<std::uint8_t const> m) -> std::expected<void,ClientAuthError> {
        if (state_!=State::finished) return std::unexpected(ClientAuthError::invalid_state);
        state_=State::failed;
        auto verified=finished_->verify_server(m);
        if (!verified) return std::unexpected(verified.error()==FinishedError::crypto_error ? ClientAuthError::crypto_error : ClientAuthError::invalid_finished);
        state_=State::client_finished; return {};
    }
    auto ClientAuth::server_finished_hash() const -> std::expected<crypto::Bytes,ClientAuthError> {
        if (state_!=State::client_finished) return std::unexpected(ClientAuthError::invalid_state);
        auto hash=finished_->transcript_hash(); if (!hash) return std::unexpected(ClientAuthError::crypto_error);
        return std::move(*hash);
    }
    auto ClientAuth::client_finished(std::span<std::uint8_t const> preceding) -> std::expected<crypto::Bytes,ClientAuthError> {
        if (state_!=State::client_finished) return std::unexpected(ClientAuthError::invalid_state);
        state_=State::failed; auto m=finished_->make_client(preceding); if (!m) return std::unexpected(ClientAuthError::crypto_error);
        state_=State::complete; return std::move(*m);
    }
    auto ClientAuth::completed_transcript_hash() const -> std::expected<crypto::Bytes,ClientAuthError> {
        if (state_!=State::complete || !finished_) return std::unexpected(ClientAuthError::invalid_state);
        auto hash=finished_->transcript_hash();if (!hash) return std::unexpected(ClientAuthError::crypto_error);return std::move(*hash);
    }
}
