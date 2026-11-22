export module sniff.quic_datagrams;
import std;
import sniff.quic;

export namespace sniff {
    enum class QuicBufferStatus { waiting,known,unknown,expired,full,invalid_state };
    struct QuicBufferResult {
        QuicBufferStatus status;
        // Only returned for a visible SNI when ECH was not offered. This view
        // belongs to the buffer and remains valid until it is destroyed.
        std::optional<std::string_view> domain;
    };
    // One explicitly identified inbound flow. The caller must demultiplex by
    // authenticated association, source and destination before feeding it;
    // neither QUIC Initial keys nor connection IDs authenticate a client.
    // Original datagrams are retained in arrival order until the caller
    // consumes them after routing. No packet is silently consumed on overflow.
    class QuicDatagramBuffer {
        using Clock=std::chrono::steady_clock;
        QuicSniffer sniffer_;
        std::deque<std::vector<std::uint8_t>> packets_;
        std::size_t bytes_=0,max_packets_,max_bytes_;
        Clock::time_point deadline_;
        QuicBufferStatus state_=QuicBufferStatus::waiting;
        std::optional<std::string> domain_;
        bool closed_=false;
        [[nodiscard]] auto result() const noexcept -> QuicBufferResult {
            return {state_,domain_ ? std::optional<std::string_view>(*domain_) : std::nullopt};
        }
    public:
        QuicDatagramBuffer(std::size_t max_packets,std::size_t max_bytes,Clock::time_point deadline)
            :max_packets_(max_packets),max_bytes_(max_bytes),deadline_(deadline) {}
        QuicDatagramBuffer(QuicDatagramBuffer const&)=delete;
        auto operator=(QuicDatagramBuffer const&) -> QuicDatagramBuffer& = delete;
        [[nodiscard]] auto push(std::span<std::uint8_t const> packet,Clock::time_point now) -> QuicBufferResult {
            if(closed_ || state_!=QuicBufferStatus::waiting)return {QuicBufferStatus::invalid_state,{}};
            if(now>=deadline_){state_=QuicBufferStatus::expired;return result();}
            if(packets_.size()>=max_packets_ || packet.size()>max_bytes_-bytes_)
                return {QuicBufferStatus::full,{}};
            // Allocate before inspecting so allocation failure cannot advance
            // the parser without retaining the packet required for replay.
            packets_.emplace_back(packet.begin(),packet.end());bytes_+=packet.size();
            auto parsed=sniffer_.feed(packets_.back());
            if(parsed.status==QuicSniffStatus::matched) {
                if(parsed.server_name && !parsed.ech_offered) {
                    domain_=std::string(*parsed.server_name);state_=QuicBufferStatus::known;
                } else state_=QuicBufferStatus::unknown;
            } else if(parsed.status!=QuicSniffStatus::need_more)state_=QuicBufferStatus::unknown;
            return result();
        }
        [[nodiscard]] auto poll(Clock::time_point now) noexcept -> QuicBufferResult {
            if(closed_)return {QuicBufferStatus::invalid_state,{}};
            if(state_==QuicBufferStatus::waiting && now>=deadline_)state_=QuicBufferStatus::expired;
            return result();
        }
        // Resource exhaustion or an inbound end-of-input can end sniffing
        // early; retained packets remain available for the caller's fallback.
        [[nodiscard]] auto finish_unknown() noexcept -> QuicBufferResult {
            if(closed_ || state_!=QuicBufferStatus::waiting)return {QuicBufferStatus::invalid_state,{}};
            state_=QuicBufferStatus::unknown;return result();
        }
        // A peek borrows storage until consume() or close(); the caller keeps
        // the packet on a failed or backpressured send and consumes on success.
        [[nodiscard]] auto front() const noexcept -> std::optional<std::span<std::uint8_t const>> {
            if(closed_ || state_==QuicBufferStatus::waiting || packets_.empty())return {};
            return std::span<std::uint8_t const>(packets_.front());
        }
        [[nodiscard]] auto consume() noexcept -> bool {
            if(!front())return false;
            bytes_-=packets_.front().size();packets_.pop_front();return true;
        }
        auto close() noexcept -> void {closed_=true;packets_.clear();bytes_=0;domain_.reset();}
        [[nodiscard]] auto count() const noexcept -> std::size_t {return packets_.size();}
        [[nodiscard]] auto bytes() const noexcept -> std::size_t {return bytes_;}
    };
}
