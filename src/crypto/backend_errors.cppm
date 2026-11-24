export module crypto.backend_errors;
import boringssl;
import std;
export namespace crypto {
    // Own the thread-local crypto error queue for one native operation. Clear
    // stale input errors and drain every failure queue so they never cross
    // otherwise independent TLS owners on this thread.
    class BackendErrors {
    public:
        BackendErrors() noexcept { boringssl::ERR_clear_error(); }
        ~BackendErrors() { boringssl::ERR_clear_error(); }
        BackendErrors(BackendErrors const&)=delete;
        auto operator=(BackendErrors const&) -> BackendErrors& = delete;
        [[nodiscard]] auto allocation_failed() const noexcept -> bool {
            bool failed=false;
            while(auto error=boringssl::ERR_get_error()) failed|=boringssl::error_is_allocation_failure(error);
            return failed;
        }
    };
}
