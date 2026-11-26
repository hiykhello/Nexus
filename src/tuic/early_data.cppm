// TUIC v5 0-RTT early data state & rejection recovery helpers.
export module tuic.early_data;
import std;
import ngtcp2;

export namespace tuic::detail {
    enum class EarlyPhase : std::uint8_t { inactive, available, accepted, rejected };

    struct EarlyDataState {
        static constexpr std::size_t max_replay_datagrams = 64;
        static constexpr std::size_t max_early_uni_packets = 16;
        EarlyPhase phase = EarlyPhase::inactive;
        bool offered = false;
        bool accepted = false;
        bool rejected = false;
        bool server_early_accepted = false;
        std::deque<std::vector<std::uint8_t>> client_sent_datagrams;
        std::deque<std::vector<std::uint8_t>> server_early_uni_packets;

        [[nodiscard]] auto client_can_send() const noexcept -> bool {
            return phase == EarlyPhase::available;
        }
        auto allow_client() noexcept -> void {
            phase = EarlyPhase::available;
            offered = true;
        }
        auto accept_client() noexcept -> void {
            phase = EarlyPhase::accepted;
            accepted = true;
            client_sent_datagrams.clear();
        }
        auto accept_server() noexcept -> void {
            server_early_accepted = true;
        }
        auto record_client_datagram(std::vector<std::uint8_t> dgram) -> void {
            if (phase == EarlyPhase::available && client_sent_datagrams.size() < max_replay_datagrams)
                client_sent_datagrams.push_back(std::move(dgram));
        }
        auto buffer_server_uni_packet(std::span<std::uint8_t const> wire) -> bool {
            if (server_early_uni_packets.size() >= max_early_uni_packets || wire.size() > 4096) return false;
            server_early_uni_packets.emplace_back(wire.begin(), wire.end());
            return true;
        }
        template<class StreamsArray, class DatagramQueue>
        auto reject_client(StreamsArray& streams, DatagramQueue& pending_datagrams) -> void {
            phase = EarlyPhase::rejected;
            rejected = true;
            for (auto& slot : streams) {
                if (!slot || slot->released || !slot->local) continue;
                slot->tx.rewind_unsent();
                slot->fin_queued = false;
                slot->needs_reopen = true;
                slot->id = -1;
            }
            while (!client_sent_datagrams.empty()) {
                if (pending_datagrams.size() < max_replay_datagrams)
                    pending_datagrams.push_front(std::move(client_sent_datagrams.back()));
                client_sent_datagrams.pop_back();
            }
        }
        template<class StreamsArray>
        auto reopen_rejected_streams(ngtcp2::ngtcp2_conn* native, StreamsArray& streams) -> int {
            for (auto& slot : streams) {
                if (!slot || slot->released || !slot->needs_reopen) continue;
                std::int64_t new_id = -1;
                int err = slot->uni
                    ? ngtcp2::ngtcp2_conn_open_uni_stream(native, &new_id, nullptr)
                    : ngtcp2::ngtcp2_conn_open_bidi_stream(native, &new_id, nullptr);
                if (err) return err;
                slot->id = new_id;
                slot->needs_reopen = false;
            }
            return 0;
        }
    };
}
