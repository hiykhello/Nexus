// The proxy always imports this DNS boundary. The ordinary provider exposes
// the production cache without depending on experimental cache implementations.
export module relay.dns_backend;
export import dns.cache;
