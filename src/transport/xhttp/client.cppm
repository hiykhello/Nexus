export module xhttp.client;
import std;
import xhttp.config;
import xhttp.wire;

export namespace xhttp {
    enum class RequestKind { stream, download, upload, packet };

    struct Request {
        std::string_view method;
        std::string target;
        std::vector<Field> fields;
    };

    // Tracks upload and download stream tickets explicitly so stream-up mode
    // always releases both streams even when distinct HTTP/2 or HTTP/3
    // connections assign colliding numeric stream IDs / tickets.
    template<class Ticket>
    struct StreamTickets {
        std::optional<Ticket> upload;
        std::optional<Ticket> download;
        bool shared_stream = false;

        auto bind_shared(Ticket ticket) noexcept -> void {
            upload = ticket;
            download = ticket;
            shared_stream = true;
        }
        auto bind_download(Ticket ticket) noexcept -> void {
            download = ticket;
            shared_stream = false;
        }
        auto bind_upload(Ticket ticket) noexcept -> void {
            upload = ticket;
            shared_stream = false;
        }
        template<class ReleaseDown, class ReleaseUp>
        auto release_all(ReleaseDown&& release_down, ReleaseUp&& release_up) noexcept -> void {
            auto down = std::exchange(download, std::nullopt);
            auto up = std::exchange(upload, std::nullopt);
            bool const shared = std::exchange(shared_stream, false);
            if (down) release_down(*down);
            if (up && (!shared || !down)) release_up(*up);
        }
    };

    [[nodiscard]] inline auto request(Profile const& profile,Endpoint const& endpoint,RequestKind kind,
        std::string_view id,std::uint64_t sequence,std::uint64_t entropy,bool secure) -> Request {
        Request result{kind==RequestKind::download ? "GET" : "POST",endpoint.path,profile.headers};
        if (kind!=RequestKind::stream) result.target+=id;
        if (kind==RequestKind::packet) { result.target+='/';result.target+=std::to_string(sequence); }
        auto padding=padding_bytes(profile.padding,entropy);
        switch (profile.padding.placement) {
        case Placement::referer:
            result.fields.emplace_back("referer",std::string(secure ? "https://" : "http://")+
                endpoint.authority+result.target+"?x_padding="+padding);
            break;
        case Placement::query:
            result.target+="?x_padding="+padding;
            break;
        case Placement::header:
            result.fields.emplace_back(profile.padding.header,std::move(padding));
            break;
        }
        if (!profile.no_grpc_header && (kind==RequestKind::stream || kind==RequestKind::upload))
            result.fields.emplace_back("content-type","application/grpc");
        return result;
    }
}
