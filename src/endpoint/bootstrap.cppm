export module endpoint.bootstrap;
import std;
import endpoint.config;
import endpoint.credentials;
import endpoint.process_signals;
export namespace endpoint {
    // Numeric and passive peers return before creating any resolver/context.
    // The same immutable system snapshot and original deadline cover all peers.
    auto bootstrap(Wireguard const&,Prepared&,std::chrono::steady_clock::time_point,process::Signals&,bool use_uring=true) -> std::expected<void,std::string>;
}
