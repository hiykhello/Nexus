#pragma once

namespace proxy::vless_xhttp {
    namespace h3=nex::nghttp3;
    namespace q=nex::ngtcp2;
    inline constexpr std::size_t h3_window=128*1024;

    inline auto h3_field(std::string_view key,std::string_view value) noexcept -> h3::nghttp3_nv {
        return {reinterpret_cast<std::uint8_t const*>(key.data()),reinterpret_cast<std::uint8_t const*>(value.data()),
            key.size(),value.size(),h3::nv_flag_none};
    }

    template<class Registry,bool ServerSide,std::size_t Streams>
    class Http3Streams {
        Registry& registry_;
        quic::SessionHandle owner_;
        nex::capy::async_event& event_;
    public:
        struct Stream {
            http2::detail::InputRing input{h3_window};
            std::vector<http2::Header> headers;
            std::vector<std::uint8_t> output;
            std::size_t header_bytes=0,acked=0;
            bool accepted=false,complete=false,failed=false,closed=false,retired=false,abort=false;
            bool remote_end=false,fin_requested=false,fin_written=false,supplied=false,credited=false;
        };
        std::map<std::int64_t,Stream> streams;
        bool dead=false,goaway=false;

        Http3Streams(Registry& registry,quic::SessionHandle owner,nex::capy::async_event& event)
            :registry_(registry),owner_(owner),event_(event) {}
        static constexpr auto stream_capacity() noexcept -> std::size_t {return Streams;}
        auto changed() noexcept -> void {event_.set();}
        auto add_connection_id(q::ngtcp2_cid const& cid,q::ngtcp2_stateless_reset_token const&) noexcept -> int {
            return registry_.insert(owner_,std::span(cid.data).first(cid.datalen)) ? 0 : q::err_callback_failure;
        }
        auto remove_connection_id(q::ngtcp2_cid const& cid) noexcept -> int {
            (void)registry_.remove(owner_,std::span(cid.data).first(cid.datalen));
            return 0;
        }
        auto find(std::int64_t id) noexcept -> Stream* {
            auto it=streams.find(id);
            return it==streams.end() ? nullptr : &it->second;
        }
        auto open(std::int64_t id) -> Stream* {
            if (dead || goaway || streams.size()>=Streams) return nullptr;
            auto [stream,inserted]=streams.try_emplace(id);
            return inserted ? &stream->second : nullptr;
        }
        auto fail(Stream& stream) noexcept -> void {
            stream.failed=true;
            stream.abort=!stream.closed;
            changed();
        }
        auto take_abort() noexcept -> std::optional<std::pair<std::int64_t,std::uint64_t>> {
            for (auto& [id,stream]:streams)
                if (std::exchange(stream.abort,false)) return std::pair{id,std::uint64_t{h3::h3_request_cancelled}};
            return {};
        }
        auto begin_headers(std::int64_t id,bool trailers) -> int {
            if constexpr (ServerSide) {
                if (!trailers && !open(id)) return h3::err_callback_failure;
            }
            return 0;
        }
        auto header(std::int64_t id,h3::nghttp3_rcbuf* name,h3::nghttp3_rcbuf* value,bool trailers) -> int {
            auto* stream=find(id);
            if (!stream || stream->failed || stream->retired || trailers) return 0;
            auto key=h3::nghttp3_rcbuf_get_buf(name);
            auto field=h3::nghttp3_rcbuf_get_buf(value);
            auto available=http::max_header_bytes-stream->header_bytes;
            if (stream->complete || stream->headers.size()>=100 || key.len>available || field.len>available-key.len) {
                fail(*stream);
                return 0;
            }
            stream->header_bytes+=key.len+field.len;
            stream->headers.emplace_back(std::string(reinterpret_cast<char const*>(key.base),key.len),
                std::string(reinterpret_cast<char const*>(field.base),field.len));
            return 0;
        }
        auto end_headers(std::int64_t id,bool fin,bool trailers) noexcept -> int {
            if (auto* stream=find(id);stream && !stream->retired) {
                if (!trailers) stream->complete=true;
                stream->remote_end|=fin;
                changed();
            }
            return 0;
        }
        auto end_stream(std::int64_t id) noexcept -> int {return end_headers(id,true,true);}
        auto data(std::int64_t id,std::span<std::uint8_t const> bytes) noexcept -> int {
            auto* stream=find(id);
            if (!stream) return 0;
            stream->credited=false;
            if (stream->failed || stream->retired) return 0;
            if (!stream->complete || !stream->input.append(bytes)) {
                fail(*stream);
                return 0;
            }
            stream->credited=true;
            changed();
            return 0;
        }
        auto defer_body_credit(std::int64_t id) noexcept -> bool {
            auto* stream=find(id);
            return stream && stream->credited;
        }
        auto data_acked(std::int64_t id,std::uint64_t count) noexcept -> int {
            auto* stream=find(id);
            if (!stream || count>stream->output.size()-stream->acked) return h3::err_callback_failure;
            stream->acked+=count;
            if (stream->acked==stream->output.size()) {
                stream->output.clear();
                stream->acked=0;
                stream->supplied=false;
                changed();
            }
            return 0;
        }
        auto read_data(std::int64_t id,std::span<h3::nghttp3_vec> vectors,std::uint32_t& flags) noexcept -> h3::nghttp3_ssize {
            auto* stream=find(id);
            if (!stream || stream->failed || stream->retired) return h3::err_wouldblock;
            if (stream->fin_requested) flags=h3::data_flag_eof;
            if (stream->supplied || stream->output.empty() || vectors.empty())
                return stream->fin_requested ? 0 : h3::err_wouldblock;
            vectors[0]={stream->output.data(),stream->output.size()};
            stream->supplied=true;
            return 1;
        }
        auto fin_accepted(std::int64_t id) noexcept -> void {
            if (auto* stream=find(id)) stream->fin_written=true;
            changed();
        }
        auto receive_closed(std::int64_t id,std::uint64_t) noexcept -> void {
            if (auto* stream=find(id);stream && !stream->retired) fail(*stream);
        }
        auto send_closed(std::int64_t id,std::uint64_t code) noexcept -> void {receive_closed(id,code);}
        auto closed(std::int64_t id,std::uint64_t,std::uint64_t) noexcept -> void {
            auto it=streams.find(id);
            if (it==streams.end()) return;
            if (it->second.retired) streams.erase(it);
            else {
                auto& stream=it->second;
                stream.closed=true;
                stream.failed|=!stream.remote_end;
                stream.abort=false;
                stream.output.clear();
            }
            changed();
        }
        auto shutdown(std::int64_t first_unprocessed) noexcept -> int {
            goaway=true;
            if constexpr (!ServerSide)
                for (auto& [id,stream]:streams) if (id>=first_unprocessed && !stream.closed) fail(stream);
            changed();
            return 0;
        }
        auto stopping() noexcept -> void {dead=true;changed();}
        auto h3_closed() noexcept -> void {stopping();}
        auto transport_closed() noexcept -> void {stopping();}
    };
}
