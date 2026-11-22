export module quic.receive_windows;
import std;

export namespace quic {
    struct ReceiveWindows {
        static constexpr std::size_t minimum=64*1024,maximum=64*1024*1024;
        std::size_t initial_stream=0,max_stream=0,initial_connection=0,max_connection=0;

        [[nodiscard]] auto configured() const noexcept -> bool {
            return initial_stream || max_stream || initial_connection || max_connection;
        }
        [[nodiscard]] auto valid(std::size_t native_bytes) const noexcept -> bool {
            return !configured() || (initial_stream>=minimum && max_connection<=maximum &&
                max_stream>=initial_stream && initial_connection>=initial_stream &&
                max_connection>=max_stream && max_connection>=initial_connection &&
                native_bytes>=max_connection+minimum);
        }
    };
}
