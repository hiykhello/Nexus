export module snell.record;
import std;

export namespace snell {
    using Bytes=std::vector<std::uint8_t>;
    using View=std::span<std::uint8_t const>;
    constexpr std::size_t max_payload=0x3fff, tag_size=16, header_size=23;
    enum class Error { invalid_length, bad_version, authentication, terminal, nonce_exhausted, invalid_request, crypto_failure };
    struct Request { std::uint8_t command; Bytes client_id; std::string host; std::uint16_t port; };
    struct ParsedRequest { Request request; std::size_t consumed; };
    [[nodiscard]] auto encode_request(Request const& r) -> std::expected<Bytes,Error> {
        if (r.client_id.size()>255 || (r.command!=0 && r.command!=1 && r.command!=5 && r.command!=6))
            return std::unexpected(Error::invalid_request);
        bool connect=r.command==1 || r.command==5;
        if (connect && (r.host.empty() || r.host.size()>255 || r.port==0)) return std::unexpected(Error::invalid_request);
        Bytes b;b.reserve(3+r.client_id.size()+(connect ? 1+r.host.size()+2 : 0));
        b.push_back(1);b.push_back(r.command);b.push_back(static_cast<std::uint8_t>(r.client_id.size()));
        b.insert(b.end(),r.client_id.begin(),r.client_id.end());
        if (connect) { b.push_back(static_cast<std::uint8_t>(r.host.size())); b.insert(b.end(),r.host.begin(),r.host.end()); b.push_back(r.port>>8); b.push_back(r.port); }
        return b;
    }
    // A complete plaintext record can carry request and early application data.
    [[nodiscard]] auto parse_request(View b) -> std::expected<ParsedRequest,Error> {
        if (b.size()<3 || b[0]!=1 || (b[1]!=0 && b[1]!=1 && b[1]!=5 && b[1]!=6)) return std::unexpected(Error::invalid_request);
        auto n=std::size_t(b[2]); if (b.size()<3+n) return std::unexpected(Error::invalid_request);
        Request r{b[1],{}, {},0}; std::size_t p=3+n;
        if (r.command==1 || r.command==5) {
            if (p==b.size()) return std::unexpected(Error::invalid_request);
            auto h=std::size_t(b[p++]); if (!h || b.size()-p<h+2) return std::unexpected(Error::invalid_request);
            r.host.assign(reinterpret_cast<char const*>(b.data()+p),h); p+=h;
            r.port=std::uint16_t((unsigned(b[p])<<8)|b[p+1]); p+=2;
            if (!r.port) return std::unexpected(Error::invalid_request);
        }
        r.client_id.assign(b.begin()+3,b.begin()+3+n);
        return ParsedRequest{std::move(r),p};
    }
    struct Nonce {
        std::array<std::uint8_t,12> bytes{}; bool exhausted=false;
        auto advance() noexcept -> void { for (auto& b:bytes) if (++b) return; exhausted=true; }
    };
    // Cipher must expose seal/open(nonce, input), returning expected<Bytes,Error>.
    // Each instance owns one direction's AEAD and must not be copied or reused.
    template<class Cipher> class Record {
        Cipher cipher_; Nonce nonce_{}; bool terminal_=false,clean_terminal_=false;
        auto crypt(bool seal, View input) -> std::expected<Bytes,Error> {
            if (nonce_.exhausted) { terminal_=true; return std::unexpected(Error::nonce_exhausted); }
            auto result=seal ? cipher_.seal(nonce_.bytes,input) : cipher_.open(nonce_.bytes,input);
            if (!result) { terminal_=true; return std::unexpected(result.error()); }
            nonce_.advance(); return result;
        }
    public:
        explicit Record(Cipher cipher):cipher_(std::move(cipher)) {}
        Record(Record const&)=delete; auto operator=(Record const&) -> Record& = delete;
        Record(Record&&)=default; auto operator=(Record&&) -> Record& = default;
        // Padding is caller-generated randomness; salt and key initialization precede this layer.
        [[nodiscard]] auto encode(View payload,View padding) -> std::expected<Bytes,Error> {
            if (terminal_) return std::unexpected(Error::terminal);
            if (payload.size()>max_payload || padding.size()>65535 || (payload.empty() && !padding.empty())) return std::unexpected(Error::invalid_length);
            std::array<std::uint8_t,7> h{4,0,0,std::uint8_t(padding.size()>>8),std::uint8_t(padding.size()),std::uint8_t(payload.size()>>8),std::uint8_t(payload.size())};
            auto head=crypt(true,h); if (!head) return std::unexpected(head.error());
            if (head->size()!=header_size) { terminal_=true; return std::unexpected(Error::authentication); }
            Bytes out=std::move(*head); if (payload.empty()) { terminal_=true; clean_terminal_=true; return out; }
            auto body=crypt(true,payload); if (!body) return std::unexpected(body.error());
            if (body->size()!=payload.size()+tag_size) { terminal_=true; return std::unexpected(Error::authentication); }
            Bytes pad(padding.begin(),padding.end());
            for (std::size_t i=0;i<std::min(pad.size(),body->size());i+=2) std::swap(pad[i],(*body)[i]);
            out.insert(out.end(),pad.begin(),pad.end()); out.insert(out.end(),body->begin(),body->end()); return out;
        }
        // Header and body are separate so callers may bound reads after authenticating the header.
        struct Lengths { std::uint16_t padding,payload; };
        [[nodiscard]] auto read_header(View wire) -> std::expected<Lengths,Error> {
            if (terminal_ || pending_) return std::unexpected(Error::terminal);
            if (wire.size()!=header_size) return std::unexpected(Error::invalid_length);
            auto h=crypt(false,wire); if (!h) return std::unexpected(h.error());
            if (h->size()!=7 || (*h)[0]!=4) {terminal_=true;return std::unexpected(Error::bad_version);}
            Lengths n{std::uint16_t((unsigned((*h)[3])<<8)|(*h)[4]),std::uint16_t((unsigned((*h)[5])<<8)|(*h)[6])};
            if (n.payload>max_payload || (!n.payload && n.padding)) {terminal_=true;return std::unexpected(Error::invalid_length);}
            if (!n.payload) { terminal_=true; clean_terminal_=true; } else pending_=n;
            return n;
        }
        [[nodiscard]] auto read_body(View wire) -> std::expected<Bytes,Error> {
            if (terminal_ || !pending_) return std::unexpected(Error::terminal);
            auto n=*pending_; if (wire.size()!=std::size_t(n.padding)+n.payload+tag_size) return std::unexpected(Error::invalid_length);
            Bytes body(wire.begin()+n.padding,wire.end());
            for (std::size_t i=0;i<std::min<std::size_t>(n.padding,body.size());i+=2) body[i]=wire[i];
            auto plaintext=crypt(false,body); if (!plaintext) return std::unexpected(plaintext.error());
            if (plaintext->size()!=n.payload) {terminal_=true;return std::unexpected(Error::authentication);}
            pending_.reset(); return plaintext;
        }
        // Only an authenticated protocol EOF can delimit a reusable logical
        // stream. Authentication and nonce failures remain terminal forever.
        [[nodiscard]] auto resume() noexcept ->bool {if(!terminal_ || !clean_terminal_ || nonce_.exhausted)return false;terminal_=false;clean_terminal_=false;return true;}
    private: std::optional<Lengths> pending_;
    };
}
