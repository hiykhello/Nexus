export module sniff.tcp;
import std;
import http.sniff;
import sniff.tls;
export import sniff.extra;

export namespace sniff {
    enum class TcpProtocol { unknown,http,tls,ssh,bittorrent,rdp,dns };
    enum class TcpStatus { need_more,matched,not_recognized,malformed,too_large,truncated };
    enum class TcpNameKind { unknown,domain,numeric,ambiguous,unsupported,tls_no_sni,tls_outer_ech };
    struct TcpStep { TcpStatus status;std::size_t consumed=0;TcpProtocol protocol=TcpProtocol::unknown;
        std::optional<std::string_view> domain;TcpNameKind name_kind=TcpNameKind::unknown;
        std::optional<std::string_view> client{}; };
    // The two disjoint buffers remain stable until the caller has consumed the
    // result and replayed wire(); feed input does not overlap either buffer.
    // Every accepted input byte is retained, even
    // when a parser finishes in the middle of the most recent input chunk.
    class TcpSniffer {
        std::span<std::uint8_t> wire_,scratch_;
        std::size_t used_=0;
        std::uint32_t allowed_protocols_=~std::uint32_t{0};
        TcpProtocol protocol_=TcpProtocol::unknown;
        TcpStatus status_=TcpStatus::need_more;
        bool selected_=false,candidate_tls_=false;
        std::optional<std::string_view> domain_;
        TcpNameKind name_kind_=TcpNameKind::unknown;
        std::optional<std::string_view> client_;
        http::HttpSniffer http_;
        TlsSniffer tls_;
        auto result(std::size_t consumed) const noexcept -> TcpStep {return {status_,consumed,protocol_,domain_,name_kind_,client_};}
        auto allows(TcpProtocol p) const noexcept -> bool {return (allowed_protocols_&protocol_bit(p))!=0;}
        static auto classify_ssh_client(std::string_view id) noexcept -> std::optional<std::string_view> {
            if (id.contains("OpenSSH")) return "openssh";
            if (id.contains("PuTTY")) return "putty";
            if (id=="Go" || id.starts_with("Go_") || id.starts_with("Go-") || id.contains("golang") || id.contains("Golang"))
                return "golang-ssh";
            if (id.contains("libssh")) return "libssh";
            return {};
        }
        static auto classify_http_client(std::string_view ua) noexcept -> std::optional<std::string_view> {
            if (ua.contains("Chromium/") || ua.contains("Chrome/")) return "chromium";
            if (ua.contains("Firefox/")) return "firefox";
            if (ua.contains("Safari/")) return "safari";
            if (ua.contains("curl/")) return "curl";
            if (ua.contains("Go-http-client")) return "go-http";
            return {};
        }
        // RFC 4253 identification line, including its CRLF and 255-byte limit.
        static auto inspect_ssh(std::string_view wire, std::optional<std::string_view>& client) noexcept -> TcpStatus {
            constexpr std::array prefixes{std::string_view("SSH-2.0-"),std::string_view("SSH-1.99-")};
            auto prefix=std::ranges::find_if(prefixes,[&](auto candidate) {
                return wire.starts_with(candidate) || candidate.starts_with(wire);
            });
            if (prefix==prefixes.end()) return TcpStatus::not_recognized;
            if (wire.size()<=prefix->size()) return TcpStatus::need_more;
            auto limit=wire.substr(0,255);
            auto end=limit.find('\n');
            if (end==limit.npos) return limit.size()==255 ? TcpStatus::too_large : TcpStatus::need_more;
            if (end<=prefix->size()+1 || limit[end-1]!='\r') return TcpStatus::malformed;
            auto identification=limit.substr(prefix->size(),end-prefix->size()-1);
            if (identification.front()==' ' || std::ranges::any_of(identification,[](unsigned char c) {
                return c<' ' || c>126;
            })) return TcpStatus::malformed;
            client=classify_ssh_client(identification);
            return TcpStatus::matched;
        }
    public:
        static constexpr auto protocol_bit(TcpProtocol p) noexcept -> std::uint32_t {
            return p==TcpProtocol::unknown ? 0u : (std::uint32_t{1}<<static_cast<unsigned>(p));
        }
        TcpSniffer(std::span<std::uint8_t> wire,std::span<std::uint8_t> scratch) noexcept:wire_(wire),scratch_(scratch) {}
        TcpSniffer(TcpSniffer const&)=delete;
        auto operator=(TcpSniffer const&) -> TcpSniffer& = delete;
        auto set_allowed_protocols(std::uint32_t mask) noexcept -> void {
            allowed_protocols_=mask;
            if (status_==TcpStatus::matched && !allows(protocol_)) {
                status_=TcpStatus::not_recognized;
                protocol_=TcpProtocol::unknown;
                domain_.reset();
                name_kind_=TcpNameKind::unknown;
                client_.reset();
            } else if (status_==TcpStatus::need_more && selected_ && candidate_tls_ && !allows(TcpProtocol::tls)) {
                status_=TcpStatus::not_recognized;
            }
        }
        [[nodiscard]] auto wire() const noexcept -> std::span<std::uint8_t const> {return wire_.first(used_);}
        [[nodiscard]] auto remaining() const noexcept -> std::size_t {return wire_.size()-used_;}
        [[nodiscard]] auto current() const noexcept -> TcpStep {return result(0);}
        [[nodiscard]] auto limit() noexcept -> TcpStep {
            if(status_==TcpStatus::need_more && !remaining())status_=TcpStatus::too_large;
            return result(0);
        }
        [[nodiscard]] auto feed(std::span<std::uint8_t const> input) noexcept -> TcpStep {
            if(status_!=TcpStatus::need_more || input.empty())return result(0);
            auto size=std::min(input.size(),wire_.size()-used_);
            auto appended=wire_.subspan(used_,size);std::ranges::copy(input.first(size),appended.begin());used_+=size;
            if(!selected_ && used_){selected_=true;candidate_tls_=wire_[0]==22;}
            if(selected_ && candidate_tls_) {
                if (!allows(TcpProtocol::tls)) {
                    status_=TcpStatus::not_recognized;
                } else {
                    auto step=tls_.feed(appended,scratch_);
                    switch(step.status) {
                    case TlsStatus::need_more:break;
                    case TlsStatus::matched:
                        status_=TcpStatus::matched;protocol_=TcpProtocol::tls;domain_=step.server_name;client_=step.client;
                        name_kind_=step.ech_offered ? TcpNameKind::tls_outer_ech : domain_ ? TcpNameKind::domain : TcpNameKind::tls_no_sni;break;
                    case TlsStatus::not_tls:status_=TcpStatus::not_recognized;break;
                    case TlsStatus::malformed:status_=TcpStatus::malformed;break;
                    case TlsStatus::too_large:status_=TcpStatus::too_large;break;
                    case TlsStatus::truncated:status_=TcpStatus::truncated;break;
                    }
                }
            } else if(selected_) {
                auto bytes=wire();
                bool any_need_more=false;
                auto bt=allows(TcpProtocol::bittorrent) ? inspect_bittorrent_tcp(bytes) : ExtraSniffStatus::not_recognized;
                if (bt==ExtraSniffStatus::matched) {
                    status_=TcpStatus::matched;protocol_=TcpProtocol::bittorrent;client_="bittorrent";
                } else {
                    any_need_more |= (bt==ExtraSniffStatus::need_more);
                    std::string_view text{reinterpret_cast<char const*>(bytes.data()),bytes.size()};
                    std::optional<std::string_view> ssh_client;
                    auto ssh=allows(TcpProtocol::ssh) ? inspect_ssh(text,ssh_client) : TcpStatus::not_recognized;
                    if (ssh==TcpStatus::matched) {
                        status_=TcpStatus::matched;protocol_=TcpProtocol::ssh;client_=ssh_client;
                    } else if (ssh==TcpStatus::malformed || ssh==TcpStatus::too_large) {
                        status_=ssh;
                    } else {
                        any_need_more |= (ssh==TcpStatus::need_more);
                        auto rdp=allows(TcpProtocol::rdp) ? inspect_rdp_tcp(bytes) : ExtraSniffStatus::not_recognized;
                        if (rdp==ExtraSniffStatus::matched) {
                            status_=TcpStatus::matched;protocol_=TcpProtocol::rdp;
                        } else {
                            any_need_more |= (rdp==ExtraSniffStatus::need_more);
                            auto dns=allows(TcpProtocol::dns) ? inspect_dns_tcp(bytes,scratch_) : TcpDnsResult{};
                            if (dns.status==ExtraSniffStatus::matched) {
                                status_=TcpStatus::matched;protocol_=TcpProtocol::dns;
                                domain_=dns.domain;
                                name_kind_=domain_ ? TcpNameKind::domain : TcpNameKind::unknown;
                            } else {
                                any_need_more |= (dns.status==ExtraSniffStatus::need_more);
                                if (allows(TcpProtocol::http)) {
                                    inspect_http(text);
                                    if (status_==TcpStatus::not_recognized && any_need_more) status_=TcpStatus::need_more;
                                } else if (!any_need_more) {
                                    status_=TcpStatus::not_recognized;
                                }
                            }
                        }
                    }
                }
            }
            if(status_==TcpStatus::need_more && (size<input.size() || used_==wire_.size()))status_=TcpStatus::too_large;
            return result(size);
        }
        [[nodiscard]] auto finish() noexcept -> TcpStep {
            if(status_==TcpStatus::need_more)status_=TcpStatus::truncated;
            return result(0);
        }
    private:
        auto inspect_http(std::string_view text) noexcept -> void {
            auto step=http_.inspect(text);
            switch(step.status) {
            case http::SniffStatus::need_more:break;
            case http::SniffStatus::matched:
                status_=TcpStatus::matched;protocol_=TcpProtocol::http;domain_=step.domain;
                if (step.user_agent) client_=classify_http_client(*step.user_agent);
                switch(step.name_kind) {
                case http::SniffNameKind::domain:name_kind_=TcpNameKind::domain;break;
                case http::SniffNameKind::numeric:name_kind_=TcpNameKind::numeric;break;
                case http::SniffNameKind::ambiguous:name_kind_=TcpNameKind::ambiguous;break;
                case http::SniffNameKind::unsupported:name_kind_=TcpNameKind::unsupported;break;
                case http::SniffNameKind::unknown:break;
                }
                break;
            case http::SniffStatus::not_http:status_=TcpStatus::not_recognized;break;
            case http::SniffStatus::malformed:status_=TcpStatus::malformed;break;
            case http::SniffStatus::too_large:status_=TcpStatus::too_large;break;
            }
        }
    };
}
