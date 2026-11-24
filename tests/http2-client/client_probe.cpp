module http2.client;
import std;
namespace http2::detail {
    struct ClientTest {
        static auto native(Client<4>& c) -> nghttp2::nghttp2_session* {return c.core_.native();}
        static auto connection_credit(Client<4>& c) -> std::size_t {return c.core_.policy().credited_connection;}
        static auto stream_credit(Client<4>& c) -> std::size_t {return c.core_.policy().credited_stream;}
        static auto generation(Client<4>& c,std::size_t slot,std::uint32_t n) -> void {if(c.core_.policy().streams[slot])std::abort();c.core_.policy().generations[slot]=n;}
        static auto next_id(Client<4>& c,std::int32_t n) -> int {c.core_.policy().last_id=n-2;return nghttp2::nghttp2_session_set_next_stream_id(c.core_.native(),n);}
    };
}
extern "C" auto client_native(http2::Client<4>* c) -> nghttp2::nghttp2_session* {return http2::detail::ClientTest::native(*c);}
extern "C" auto client_connection_credit(http2::Client<4>* c) -> std::size_t {return http2::detail::ClientTest::connection_credit(*c);}
extern "C" auto client_stream_credit(http2::Client<4>* c) -> std::size_t {return http2::detail::ClientTest::stream_credit(*c);}
extern "C" auto client_seed_generation(http2::Client<4>* c,std::size_t slot,std::uint32_t n) -> void {http2::detail::ClientTest::generation(*c,slot,n);}
extern "C" auto client_seed_next_id(http2::Client<4>* c,std::int32_t n) -> int {return http2::detail::ClientTest::next_id(*c,n);}
