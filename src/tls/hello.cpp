module nexus.tls.hello;
import std;

namespace nexus::tls {
    namespace {
        struct Reader {
            std::span<std::uint8_t const> bytes;
            std::size_t pos = 0;
            auto take(std::size_t n) -> std::expected<std::span<std::uint8_t const>, HelloError> {
                if (n > bytes.size() - pos) return std::unexpected(HelloError::truncated);
                auto result = bytes.subspan(pos,n); pos += n; return result;
            }
            auto u8() -> std::expected<std::uint8_t, HelloError> {
                auto b=take(1); if (!b) return std::unexpected(b.error()); return (*b)[0];
            }
            auto u16() -> std::expected<std::uint16_t, HelloError> {
                auto b=take(2); if (!b) return std::unexpected(b.error()); return static_cast<std::uint16_t>((*b)[0]<<8|(*b)[1]);
            }
            auto vector8() -> std::expected<std::span<std::uint8_t const>, HelloError> {
                auto n=u8(); if (!n) return std::unexpected(n.error()); return take(*n);
            }
            auto vector16() -> std::expected<std::span<std::uint8_t const>, HelloError> {
                auto n=u16(); if (!n) return std::unexpected(n.error()); return take(*n);
            }
        };
        auto append_u16(std::vector<std::uint8_t>& out, std::size_t n) -> bool {
            if (n > 0xffff) return false; out.push_back(static_cast<std::uint8_t>(n>>8)); out.push_back(static_cast<std::uint8_t>(n)); return true;
        }
        auto encoded_size(ClientHello const& hello, std::size_t max_body_size) -> std::expected<std::size_t,HelloError> {
            if (max_body_size == 0 || max_body_size > 0xffffffu) return std::unexpected(HelloError::message_too_large);
            if (hello.legacy_version != 0x0303) return std::unexpected(HelloError::invalid_version);
            if (hello.session_id.size()>32) return std::unexpected(HelloError::invalid_session_id);
            if (hello.cipher_suites.empty() || hello.cipher_suites.size()>0x7fffu) return std::unexpected(HelloError::invalid_cipher_suites);
            if (hello.compression_methods.empty() || !std::ranges::contains(hello.compression_methods,std::uint8_t{0})) return std::unexpected(HelloError::invalid_compression);
            if (hello.extensions.size()>0x7fffu) return std::unexpected(HelloError::invalid_extensions);
            std::size_t ext_size=0; std::bitset<65536> seen;
            for (auto const& item:hello.extensions) {
                if (seen.test(item.type)) return std::unexpected(HelloError::duplicate_extension);
                seen.set(item.type);
                if (item.data.size()>0xffff-4 || ext_size>0xffff-4-item.data.size()) return std::unexpected(HelloError::invalid_extensions);
                ext_size+=4+item.data.size();
            }
            if (hello.compression_methods.size()>255) return std::unexpected(HelloError::invalid_compression);
            auto size=2+32+1+hello.session_id.size()+2+2*hello.cipher_suites.size()+1+hello.compression_methods.size()+2+ext_size;
            if (size>max_body_size) return std::unexpected(HelloError::message_too_large);
            return size;
        }
    }
    auto ClientHello::parse(std::span<std::uint8_t const> body, std::size_t max_body_size)
        -> std::expected<ClientHello, HelloError> {
        if (max_body_size == 0 || max_body_size > 0xffffffu || body.size() > max_body_size) return std::unexpected(HelloError::message_too_large);
        Reader r{body}; ClientHello result;
        auto version=r.u16(); if (!version) return std::unexpected(version.error()); result.legacy_version=*version;
        if (result.legacy_version != 0x0303) return std::unexpected(HelloError::invalid_version);
        auto random=r.take(32); if (!random) return std::unexpected(random.error()); std::ranges::copy(*random,result.random.begin());
        auto sid=r.vector8(); if (!sid) return std::unexpected(sid.error());
        if (sid->size()>32) return std::unexpected(HelloError::invalid_session_id); result.session_id.assign(sid->begin(),sid->end());
        auto suites=r.vector16(); if (!suites) return std::unexpected(suites.error());
        if (suites->empty() || suites->size()%2 != 0) return std::unexpected(HelloError::invalid_cipher_suites);
        result.cipher_suites.reserve(suites->size()/2);
        for (std::size_t i=0;i<suites->size();i+=2) result.cipher_suites.push_back(static_cast<std::uint16_t>((*suites)[i]<<8|(*suites)[i+1]));
        auto compression=r.vector8(); if (!compression) return std::unexpected(compression.error());
        if (compression->empty() || !std::ranges::contains(*compression,std::uint8_t{0})) return std::unexpected(HelloError::invalid_compression);
        result.compression_methods.assign(compression->begin(),compression->end());
        auto ext=r.vector16(); if (!ext) return std::unexpected(ext.error());
        if (ext->size() != 0 && ext->size() < 4) return std::unexpected(HelloError::invalid_extensions);
        // Validate and count before allocating extension objects. This avoids
        // geometric growth and its old/new allocation peak for peer input.
        Reader e{*ext}; std::bitset<65536> seen; std::size_t extension_count=0;
        while (e.pos < e.bytes.size()) {
            auto type=e.u16(); if (!type) return std::unexpected(HelloError::invalid_extensions);
            auto data=e.vector16(); if (!data || e.pos > e.bytes.size()) return std::unexpected(HelloError::invalid_extensions);
            if (seen.test(*type)) return std::unexpected(HelloError::duplicate_extension);
            seen.set(*type);
            ++extension_count;
        }
        result.extensions.reserve(extension_count);
        e.pos=0;
        while (e.pos < e.bytes.size()) {
            auto type=e.u16(); auto data=e.vector16();
            result.extensions.push_back({*type,std::vector<std::uint8_t>(data->begin(),data->end())});
        }
        if (r.pos != body.size()) return std::unexpected(HelloError::invalid_length);
        return result;
    }
    auto ClientHello::encode(std::size_t max_body_size) const -> std::expected<std::vector<std::uint8_t>, HelloError> {
        auto size=encoded_size(*this,max_body_size); if (!size) return std::unexpected(size.error());
        std::size_t ext_size=0;
        for (auto const& item:extensions) ext_size+=4+item.data.size();
        std::vector<std::uint8_t> out; out.reserve(*size);
        out.push_back(static_cast<std::uint8_t>(legacy_version>>8)); out.push_back(static_cast<std::uint8_t>(legacy_version));
        out.insert(out.end(),random.begin(),random.end()); out.push_back(static_cast<std::uint8_t>(session_id.size())); out.insert(out.end(),session_id.begin(),session_id.end());
        if (!append_u16(out,2*cipher_suites.size())) return std::unexpected(HelloError::invalid_cipher_suites);
        for (auto suite : cipher_suites) { out.push_back(static_cast<std::uint8_t>(suite>>8)); out.push_back(static_cast<std::uint8_t>(suite)); }
        if (compression_methods.size()>255) return std::unexpected(HelloError::invalid_compression); out.push_back(static_cast<std::uint8_t>(compression_methods.size())); out.insert(out.end(),compression_methods.begin(),compression_methods.end());
        if (!append_u16(out,ext_size)) return std::unexpected(HelloError::invalid_extensions);
        for (auto const& item:extensions) {
            (void)append_u16(out,item.type); (void)append_u16(out,item.data.size());
            out.insert(out.end(),item.data.begin(),item.data.end());
        }
        return out;
    }
    auto ClientHello::validate_encoding(std::size_t max_body_size) const -> std::expected<void,HelloError> {
        auto size=encoded_size(*this,max_body_size); if (!size) return std::unexpected(size.error()); return {};
    }
    auto ClientHello::validate_tls13() const -> std::expected<void, HelloError> {
        if (legacy_version != 0x0303) return std::unexpected(HelloError::invalid_version);
        if (cipher_suites.empty()) return std::unexpected(HelloError::invalid_cipher_suites);
        if (compression_methods.size()!=1 || compression_methods[0]!=0) return std::unexpected(HelloError::invalid_compression);
        std::bitset<65536> seen;
        for (auto const& item : extensions) { if (seen.test(item.type)) return std::unexpected(HelloError::duplicate_extension); seen.set(item.type); }
        auto versions=extension(43); if (!versions || versions->data.size()<3 || versions->data[0]+1 != versions->data.size() || versions->data[0]%2 != 0) return std::unexpected(HelloError::unsupported);
        bool found=false; for (std::size_t i=1;i<versions->data.size();i+=2) if (versions->data[i]==3 && versions->data[i+1]==4) found=true;
        if (!found) return std::unexpected(HelloError::unsupported); return {};
    }
    auto ClientHello::extension(std::uint16_t type) const noexcept -> Extension const* {
        auto it=std::ranges::find(extensions,type,[](auto const& e) { return e.type; }); return it==extensions.end() ? nullptr : &*it;
    }
}
