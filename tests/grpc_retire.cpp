import std;
import grpc.headers;
import grpc.message;
import grpc.session;
import http2.client;
namespace g=grpc;
namespace h=http2;
struct Test {
    std::unique_ptr<g::Session> server;
    std::unique_ptr<h::Client<2>> client;
    std::optional<h::StreamTicket> first,second;
    std::vector<std::uint8_t> received,wire;
    bool failed=false;
    Test() {
        auto profile=g::RequestProfile::create("nexus.Service","host",false);if (!profile) {failed=true;return;}
        auto s=g::Session::create(g::Role::server,*profile);auto c=h::Client<2>::create();if (!s || !c) {failed=true;return;}
        server=std::move(*s);client=std::move(*c);
    }
    auto fields() const -> std::array<h::FieldView,7> {
        return {{{":method","POST"},{":scheme","http"},{":path","/nexus.Service/Tun"},{":authority","host"},
            {"content-type","application/grpc"},{"te","trailers"},{"grpc-accept-encoding","identity"}}};
    }
    auto submit() -> std::optional<h::StreamTicket> {
        auto request=fields();auto result=client->submit(request,{{},true});if (!result) return {};return *result;
    }
    auto output(bool upstream,std::size_t chunk) -> std::size_t {
        std::array<std::uint8_t,16384> buffer{};
        auto pull=[&](auto& from) -> std::optional<std::size_t> {auto result=from.output(std::span(buffer).first(chunk));return result ? std::optional(*result) : std::nullopt;};
        auto n=upstream ? pull(*client) : pull(*server);
        if (!n) {failed=true;return 0;}
        if (!*n) return 0;
        auto bytes=std::span(buffer).first(*n);
        if (!upstream) wire.insert(wire.end(),bytes.begin(),bytes.end());
        for (std::size_t at=0;at<bytes.size();) {
            auto part=bytes.subspan(at,std::min(std::size_t{3},bytes.size()-at));
            if (upstream) {auto accepted=server->receive(part);if (!accepted || !*accepted) {failed=true;return 0;}at+=*accepted;}
            else {auto accepted=client->receive(part);if (!accepted || !*accepted) {failed=true;return 0;}at+=*accepted;}
        }
        if (first) {
            auto body=client->peek(*first);if (!body) {failed=true;return 0;}
            if (!body->empty()) {received.insert(received.end(),body->begin(),body->end());if (!client->consume(*first,body->size())) failed=true;}
        }
        return *n;
    }
    auto pump(std::size_t chunk) -> void {
        for (unsigned i=0;i<1000000 && !failed;++i) {auto c=output(true,chunk),s=output(false,chunk);if (!c && !s) return;}
        failed=true;
    }
};
auto main() -> int {
    for (auto chunk:{1u,3u,127u,16384u}) for (unsigned race=0;race<3;++race) {
        Test test;if (test.failed || test.server->retire_connection()) return 1;
        test.first=test.submit();if (!test.first) return 2;
        for (unsigned i=0;i<10000 && !test.server->ready();++i) if (!test.output(true,chunk) && !test.server->ready()) return 3;
        if (race==0) {
            test.second=test.submit();if (!test.second) return 4;
            for (unsigned i=0;i<10000;++i) if (!test.output(true,chunk)) break;
        }
        if (!test.server->retire_connection()) return 5;
        if (race==1) {test.second=test.submit();if (!test.second) return 6;}
        test.pump(chunk);if (test.failed || test.server->failure() || test.client->failure()) return 7;
        auto blocked=test.submit();if (blocked) return 8;
        if (test.second) {
            auto second=test.client->response(*test.second);
            if (!second || !second->failure || (second->failure->error!=h::ClientError::unprocessed && second->failure->error!=h::ClientError::reset)) return 9;
        }
        bool goaway=false;
        for (std::size_t at=0;test.wire.size()-at>=9;) {
            auto size=(std::size_t(test.wire[at])<<16)|(std::size_t(test.wire[at+1])<<8)|test.wire[at+2];if (size>test.wire.size()-at-9) return 10;
            if (test.wire[at+3]==7) {
                if (size<8) return 11;
                auto last=(std::uint32_t(test.wire[at+9])<<24)|(std::uint32_t(test.wire[at+10])<<16)|(std::uint32_t(test.wire[at+11])<<8)|test.wire[at+12];
                auto code=(std::uint32_t(test.wire[at+13])<<24)|(std::uint32_t(test.wire[at+14])<<16)|(std::uint32_t(test.wire[at+15])<<8)|test.wire[at+16];
                if (last!=std::uint32_t(test.first->id) || code) return 12;goaway=true;
            }
            at+=9+size;
        }
        if (!goaway) return 13;
        std::vector<std::uint8_t> payload(524288);for (std::size_t i=0;i<payload.size();++i) payload[i]=static_cast<std::uint8_t>(i*17);
        auto queued=test.server->queue(payload);if (!queued || !*queued || !test.server->close_output()) return 14;
        test.pump(chunk);if (test.failed || test.server->failure() || test.client->failure()) return 15;
        auto response=test.client->response(*test.first);auto encoded=g::encode_message(payload);
        if (!response || response->failure || !response->remote_end || !response->closed || !encoded || test.received!=*encoded) return 16;
    }
    std::println("Single-RPC graceful GOAWAY0 actual accepted ID, new request before/after retirement races, old512KiB+trailers+EOF, four fragmentation sizes passed");
}
