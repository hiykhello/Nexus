// Request provider for builds that include FakeIP translation.
export module proxy.request_backend;
export import socks5;
export import dns.fakeip_shared;
export import dns.fakeip_registry;
export import dns.fakeip_request;
