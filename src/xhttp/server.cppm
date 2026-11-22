export module xhttp.server;
import std;
import memory.budget;
import xhttp.config;
import xhttp.wire;
import xhttp.client;

export namespace xhttp {
    [[nodiscard]] inline auto classify(std::string_view method,Metadata const& metadata,Mode policy,HttpVersion version)
        -> std::optional<RequestKind> {
        auto permits=[&](Mode mode) {return policy==Mode::automatic || policy==mode;};
        if (method=="GET" && !metadata.session.empty() && !metadata.sequence &&
            (permits(Mode::packet_up) || permits(Mode::stream_up))) return RequestKind::download;
        if (method!="POST") return {};
        if (metadata.session.empty()) {
            if (version!=HttpVersion::http1 && permits(Mode::stream_one)) return RequestKind::stream;
        } else if (metadata.sequence) {
            if (permits(Mode::packet_up)) return RequestKind::packet;
        } else if (version!=HttpVersion::http1 && permits(Mode::stream_up)) return RequestKind::upload;
        return {};
    }

    enum class PacketError { closed, stale, duplicate, window, bytes, allocation };
    class Reassembly {
        struct Packet {
            memory::Budget::Reservation charge;
            std::vector<std::uint8_t> data;
            std::size_t read=0;
        };
        Limits limits_;
        std::shared_ptr<memory::Budget> budget_;
        std::map<std::uint64_t,Packet> packets_;
        std::uint64_t next_=0;
        std::size_t bytes_=0;
        bool closed_=false;
    public:
        Reassembly(Limits limits,std::shared_ptr<memory::Budget> budget)
            :limits_(limits),budget_(std::move(budget)) {}
        [[nodiscard]] auto expected_sequence() const noexcept -> std::uint64_t {return next_;}
        [[nodiscard]] auto buffered_bytes() const noexcept -> std::size_t {return bytes_;}
        [[nodiscard]] auto pending() const noexcept -> std::size_t {return packets_.size();}
        [[nodiscard]] auto readable() const noexcept -> bool {return packets_.contains(next_);}
        [[nodiscard]] auto closed() const noexcept -> bool {return closed_;}

    private:
        auto check(std::uint64_t seq,std::size_t size) const noexcept -> std::expected<void,PacketError> {
            if (closed_) return std::unexpected(PacketError::closed);
            if (seq<next_) return std::unexpected(PacketError::stale);
            if (packets_.contains(seq)) return std::unexpected(PacketError::duplicate);
            if (seq==std::numeric_limits<std::uint64_t>::max() || seq-next_>=limits_.buffered_posts)
                return std::unexpected(PacketError::window);
            if (!size || size>limits_.post_bytes || size>limits_.buffer_bytes-bytes_) return std::unexpected(PacketError::bytes);
            return {};
        }
    public:
        auto submit(std::uint64_t seq,std::span<std::uint8_t const> payload) -> std::expected<void,PacketError> {
            if (auto valid=check(seq,payload.size());!valid) return valid;
            // Reserve data and bound the allocator overhead of each map node.
            auto charge=memory::Budget::reserve(budget_,payload.size()+128);
            if (!charge) return std::unexpected(PacketError::bytes);
            try {
                return submit_owned(seq,{payload.begin(),payload.end()},std::move(*charge));
            } catch (std::bad_alloc const&) {return std::unexpected(PacketError::allocation);}
        }
        auto submit_owned(std::uint64_t seq,std::vector<std::uint8_t> payload,memory::Budget::Reservation charge)
            -> std::expected<void,PacketError> {
            auto size=payload.size();
            if (auto valid=check(seq,size);!valid) return valid;
            if (charge.size()<size+128) return std::unexpected(PacketError::bytes);
            try {packets_.emplace(seq,Packet{std::move(charge),std::move(payload)});}
            catch (std::bad_alloc const&) {return std::unexpected(PacketError::allocation);}
            bytes_+=size;
            return {};
        }
        auto read(std::span<std::uint8_t> output) noexcept -> std::size_t {
            std::size_t copied=0;
            while (!output.empty()) {
                auto entry=packets_.find(next_);
                if (entry==packets_.end()) break;
                auto& packet=entry->second;
                auto size=std::min(output.size(),packet.data.size()-packet.read);
                std::ranges::copy(std::span(packet.data).subspan(packet.read,size),output.begin());
                packet.read+=size;
                copied+=size;
                output=output.subspan(size);
                if (packet.read==packet.data.size()) {
                    bytes_-=packet.data.size();
                    packets_.erase(entry);
                    ++next_;
                }
            }
            return copied;
        }
        auto close() noexcept -> void {
            closed_=true;
            packets_.clear();
            bytes_=0;
        }
    };

    // Split sessions can accept their upload before the GET. The host
    // owns I/O and supplies time. A timeout or either terminal side retires it.
    struct Pairing {
        using Clock=std::chrono::steady_clock;
        Clock::time_point deadline;
        std::optional<RequestKind> upload;
        bool download=false,closed=false;

        [[nodiscard]] auto paired() const noexcept -> bool {return download && upload.has_value();}
        auto expired(Clock::time_point now) const noexcept -> bool {return !paired() && now>=deadline;}
        auto attach(RequestKind kind,Clock::time_point now) noexcept -> bool {
            if (closed || expired(now)) return false;
            if (kind==RequestKind::download && !download) {download=true;return true;}
            if ((kind==RequestKind::packet || kind==RequestKind::upload) && !upload) {upload=kind;return true;}
            return kind==RequestKind::packet && upload==kind;
        }
    };
}
