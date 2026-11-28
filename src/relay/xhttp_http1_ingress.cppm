module;
#include <boost/capy/ex/run.hpp>

module relay:xhttp_http1_ingress;
import std;
import memory.budget;
import rules;
import xhttp.config;
import xhttp.server;
import xhttp.wire;
import capy;
import corosio;
import :types;
import :session_interface;
import :xhttp_http1;
import :xhttp_inbound_types;

namespace relay::vless_xhttp {
    inline auto process(Session& session, corosio::io_context& context, rules::RouteProgram const& policy,
        InboundProfile& profile, Lower& lower) -> capy::task<> {
        std::string input;
        while (!session.closed) {
            auto deadline = Clock::now() + std::chrono::seconds(10);
            auto request = co_await read_request(lower, input, deadline);
            if (!request) co_return;
            auto const& endpoint = profile.transport.endpoint;
            auto metadata = xhttp::metadata(request->target, endpoint.path);
            auto kind = metadata ? xhttp::classify(request->method, *metadata, profile.transport.mode, endpoint.version) : std::nullopt;
            bool download = kind == xhttp::RequestKind::download;
            if (!kind || (!endpoint.authority.empty() && request->authority != endpoint.authority) ||
                !xhttp::check_padding(profile.transport.padding, request->target, request->fields) ||
                (download ? request->content_length != 0 || input.size() != request->consumed :
                    !request->content_length || request->content_length > profile.transport.limits.post_bytes)) {
                if (auto head = response_head(profile, "400 Bad Request", false, true)) (void)co_await lower.send(bytes(*head), deadline);
                co_return;
            }
            auto id = std::string(metadata->session);
            input.erase(0, request->consumed);
            std::vector<std::uint8_t> body;
            std::optional<memory::Budget::Reservation> body_charge;
            if (!download) {
                body_charge = memory::Budget::reserve(profile.budget, request->content_length + 128);
                if (!body_charge) {
                    if (auto head = response_head(profile, "503 Service Unavailable", false, true))
                        (void)co_await lower.send(bytes(*head), deadline);
                    co_return;
                }
                body.resize(request->content_length);
                auto consumed = std::min(input.size(), body.size());
                std::ranges::copy(bytes(input).first(consumed), body.begin());
                input.erase(0, consumed);
                while (consumed < body.size()) {
                    auto size = co_await lower.read(std::span(body).subspan(consumed), deadline);
                    if (!size || !*size) co_return;
                    consumed += *size;
                }
            }
            auto [split, created] = profile.find(id);
            if (!split) {
                if (auto head = response_head(profile, "503 Service Unavailable", false, true)) (void)co_await lower.send(bytes(*head), deadline);
                co_return;
            }
            SplitOwner retire{profile, id, split, created, created};
            bool accepted = false;
            {
                if (split->sides.attach(*kind, Clock::now())) {
                    if (download) { retire.active = true; retire.orphan = false; accepted = true; }
                    else {
                        accepted = split->input.submit_owned(*metadata->sequence, std::move(body), std::move(*body_charge)).has_value();
                        if (!accepted && split->input.expected_sequence() == 0 && !split->input.pending())
                            split->sides.upload.reset();
                    }
                    if (accepted) {
                        split->change.set();
                        if (split->sides.download) split->paired.set();
                    }
                }
            }
            auto status = accepted ? "200 OK" : "409 Conflict";
            auto close = download || !accepted || request->close;
            auto head = response_head(profile, status, download && accepted, close);
            if (!head || !co_await lower.send(bytes(*head), deadline) || !accepted) co_return;
            session.relaying = true;
            session.touched = Clock::now();
            if (download) {
                DownloadStream stream(lower, *split);
                (void)co_await capy::when_all(watch_download(session, lower), payload(session, context, policy, profile, stream, split->sides.deadline));
                co_return;
            }
            if (created) {
                // The first POST retains the orphan until a GET can own it.
                // A closing upload releases the socket before awaiting pairing.
                if (close) session.client.close();
                auto wait = [&]() -> capy::task<> {
                    auto [error] = co_await corosio::timeout(split->paired.wait(), split->sides.deadline);
                    (void)error;
                };
                co_await boost::capy::run(session.stop.get_token())(wait());
            }
            if (close) co_return;
        }
    }
}
