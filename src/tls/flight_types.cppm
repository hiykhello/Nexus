export module tls.flight_types;
import std;

export namespace tls {
    enum class ClientFlightError { invalid_state, invalid_hello, invalid_extensions, invalid_certificate, invalid_signature, invalid_finished, crypto_error, invalid_record, record_overflow, illegal_parameter, bad_certificate };
    enum class ServerFlightError { invalid_state, invalid_credential, invalid_finished, crypto_error };
    struct RawClientError { ClientFlightError kind; std::uint8_t alert=80; };
    struct RawServerError { ServerFlightError kind; std::uint8_t alert=80; };
}
