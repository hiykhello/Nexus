// Shared cache boundary used by proxy workers and UDP listeners.
export module dns.shared_cache;
import std;
import dns.message;
export import dns.cache;
export import dns.group_cache_binding;
