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
