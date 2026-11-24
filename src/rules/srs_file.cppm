module;
#include <zlib.h>
export module rules.srs_file;
import std;
import rules;
import rules.srs_payload;

export namespace rules {
    // Strictly one complete zlib stream and at most max_input_bytes of input/output.
    [[nodiscard]] auto decode_srs_file(std::span<std::uint8_t const> file, bool ip_cidr_match_source=false,
        bool lenient=false) -> std::expected<RuleSet,Error>;
}
namespace rules {
    auto decode_srs_file(std::span<std::uint8_t const> file, bool ip_cidr_match_source, bool lenient) -> std::expected<RuleSet,Error> {
        if(file.size()>max_input_bytes)return std::unexpected(Error{ErrorCode::limit,"SRS file exceeds 32 MiB"});
        if(file.size()<5 || file[0]!='S' || file[1]!='R' || file[2]!='S' || file[3]<1 || file[3]>5)
            return std::unexpected(Error{ErrorCode::schema,"invalid SRS header or version"});
        z_stream stream{};
        if(inflateInit(&stream)!=Z_OK)return std::unexpected(Error{ErrorCode::schema,"cannot initialize SRS decompressor"});
        struct End {z_stream& stream;~End(){inflateEnd(&stream);}} end{stream};
        std::vector<std::uint8_t> payload(std::min<std::size_t>(std::max<std::size_t>(file.size()*4,65536),max_input_bytes+1));
        stream.next_in=const_cast<Bytef*>(file.data()+4);
        stream.avail_in=static_cast<uInt>(file.size()-4);
        int result=Z_OK;
        for (;;) {
            auto space=payload.size()-stream.total_out;
            if (!space) {
                if (payload.size()>max_input_bytes)
                    return std::unexpected(Error{ErrorCode::limit,"SRS decompressed payload exceeds 32 MiB"});
                auto grown=std::min<std::size_t>(payload.size()*2,max_input_bytes+1);
                payload.resize(grown);
                space=payload.size()-stream.total_out;
            }
            stream.next_out=payload.data()+stream.total_out;
            stream.avail_out=static_cast<uInt>(space);
            result=inflate(&stream,Z_NO_FLUSH);
            if (stream.total_out>max_input_bytes)
                return std::unexpected(Error{ErrorCode::limit,"SRS decompressed payload exceeds 32 MiB"});
            if (result==Z_STREAM_END) break;
            if (result!=Z_OK && result!=Z_BUF_ERROR)
                return std::unexpected(Error{ErrorCode::syntax,"invalid, truncated or trailing SRS zlib stream"});
            if (result==Z_BUF_ERROR && stream.avail_out>0)
                return std::unexpected(Error{ErrorCode::syntax,"invalid, truncated or trailing SRS zlib stream"});
        }
        if(stream.avail_in!=0)
            return std::unexpected(Error{ErrorCode::syntax,"invalid, truncated or trailing SRS zlib stream"});
        payload.resize(stream.total_out);
        return decode_srs_payload(payload,ip_cidr_match_source,lenient);
    }
}
