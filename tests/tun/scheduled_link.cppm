export module nexus.tests.scheduled_link;
import std;
import packet;

// Test-only single-owner network with explicit loss and virtual delivery times.
export class ScheduledLink {
    struct Event { std::uint64_t due; ::packet::Side from; ::packet::Bytes bytes; };
    std::vector<Event> events_;
    std::size_t max_packets_, max_bytes_, bytes_ = 0;
    std::uint64_t now_ = 0;
public:
    enum class Error { capacity, time_reversed, device };
    ScheduledLink(std::size_t packets, std::size_t bytes) : max_packets_(packets), max_bytes_(bytes) {}
    // A dropped datagram consumes no queue capacity. Equal deadlines retain insertion order.
    auto send(::packet::Side from, std::span<std::uint8_t const> bytes, std::uint64_t due, bool drop = false)
        -> std::expected<void, Error> {
        if (due < now_) return std::unexpected(Error::time_reversed);
        if (drop) return {};
        if (events_.size() >= max_packets_ || bytes.size() > max_bytes_ - bytes_)
            return std::unexpected(Error::capacity);
        events_.push_back({due, from, {bytes.begin(), bytes.end()}});
        bytes_ += bytes.size();
        return {};
    }
    // A full destination retains the event for a later attempt.
    auto advance(std::uint64_t now, ::packet::MemoryLink& link) -> std::expected<std::size_t, Error> {
        if (now < now_) return std::unexpected(Error::time_reversed);
        now_ = now;
        std::size_t delivered = 0;
        while (!events_.empty()) {
            auto it = std::ranges::min_element(events_, {}, &Event::due);
            if (it->due > now) break;
            auto sent = link.send(it->from, it->bytes);
            if (!sent) {
                if (sent.error() == ::packet::DeviceError::queue_full) break;
                return std::unexpected(Error::device);
            }
            bytes_ -= it->bytes.size();
            events_.erase(it);
            ++delivered;
        }
        return delivered;
    }
    auto size() const noexcept -> std::size_t { return events_.size(); }
};
