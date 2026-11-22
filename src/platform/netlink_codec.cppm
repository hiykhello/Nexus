export module platform.netlink_codec;
import std;
import platform.netlink_abi;

export namespace platform::netlink {
    namespace abi = ::platform::netlink_abi;
    enum class Error { closed, configuration, system, timeout, protocol, limit, sequence_exhausted, uncertain, canceled };
    struct Failure {
        Error code;
        std::error_code system;
        bool may_have_changed = false, rejected = false;
    };
    inline auto fail(Error code, std::error_code system = {}, bool changed = false, bool rejected = false) -> std::unexpected<Failure> {
        return std::unexpected(Failure{code, system, changed, rejected});
    }
    inline auto aligned(std::size_t size) noexcept -> std::size_t { return (size + 3) & ~std::size_t{3}; }
    template <class T> auto native(std::span<std::uint8_t const> bytes, std::size_t offset = 0) noexcept -> std::optional<T> {
        static_assert(std::is_trivially_copyable_v<T>);
        if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) return {};
        T value;
        std::memcpy(&value, bytes.data() + offset, sizeof(T));
        return value;
    }
    struct Attribute {
        std::uint16_t type, flags;
        std::span<std::uint8_t const> bytes;
    };
    template <class Visitor> auto attributes(std::span<std::uint8_t const> bytes, Visitor &&visitor) -> std::expected<void, Failure> {
        std::size_t offset = 0;
        while (offset < bytes.size()) {
            auto header = native<abi::rtattr>(bytes, offset);
            if (!header || header->rta_len < sizeof(*header) || header->rta_len > bytes.size() - offset) return fail(Error::protocol);
            Attribute attribute{static_cast<std::uint16_t>(header->rta_type & abi::NLA_TYPE_MASK), static_cast<std::uint16_t>(header->rta_type & ~abi::NLA_TYPE_MASK),
                                bytes.subspan(offset + sizeof(*header), header->rta_len - sizeof(*header))};
            auto result = visitor(attribute);
            if (!result) return std::unexpected(result.error());
            auto size = aligned(header->rta_len);
            if (size > bytes.size() - offset) {
                if (header->rta_len == bytes.size() - offset) return {};
                return fail(Error::protocol);
            }
            offset += size;
        }
        return {};
    }
    struct Message {
        abi::nlmsghdr header;
        std::span<std::uint8_t const> payload;
    };
    template <class Visitor> auto messages(std::span<std::uint8_t const> bytes, Visitor &&visitor) -> std::expected<void, Failure> {
        std::size_t offset = 0;
        while (offset < bytes.size()) {
            auto header = native<abi::nlmsghdr>(bytes, offset);
            if (!header || header->nlmsg_len < sizeof(*header) || header->nlmsg_len > bytes.size() - offset) return fail(Error::protocol);
            auto result = visitor(Message{*header, bytes.subspan(offset + sizeof(*header), header->nlmsg_len - sizeof(*header))});
            if (!result) return std::unexpected(result.error());
            auto size = aligned(header->nlmsg_len);
            if (size > bytes.size() - offset) {
                if (header->nlmsg_len == bytes.size() - offset) return {};
                return fail(Error::protocol);
            }
            offset += size;
        }
        return {};
    }
    inline auto text(Attribute attribute, std::size_t maximum) noexcept -> std::optional<std::string_view> {
        if (attribute.flags || attribute.bytes.empty() || attribute.bytes.size() > maximum + 1 || attribute.bytes.back()) return {};
        auto result = std::string_view(reinterpret_cast<char const *>(attribute.bytes.data()), attribute.bytes.size() - 1);
        return result.find('\0') == result.npos ? std::optional(result) : std::nullopt;
    }
    template<class T> inline auto scalar(Attribute attribute) -> std::expected<T,Failure> {
        auto value=native<T>(attribute.bytes);
        if(attribute.flags || attribute.bytes.size()!=sizeof(T) || !value)return fail(Error::protocol);
        return *value;
    }
    class Request {
        std::array<std::uint8_t, 1024> bytes_{};
        std::size_t size_ = sizeof(abi::nlmsghdr);
        bool valid_ = true;
        template <class T> auto put(std::size_t offset, T const &value) noexcept -> void { std::memcpy(bytes_.data() + offset, &value, sizeof(value)); }

      public:
        Request(std::uint16_t type, std::uint16_t flags) noexcept { put(0, abi::nlmsghdr{.nlmsg_type = type, .nlmsg_flags = flags}); }
        template <class Payload> Request(std::uint16_t type, std::uint16_t flags, Payload const &payload) noexcept {
            static_assert(std::is_trivially_copyable_v<Payload>);
            put(0, abi::nlmsghdr{.nlmsg_type = type, .nlmsg_flags = flags});
            if (sizeof(payload) > bytes_.size() - size_) {
                valid_ = false;
                return;
            }
            put(size_, payload);
            size_ += sizeof(payload);
        }
        auto append(std::uint16_t type, std::span<std::uint8_t const> payload) noexcept -> bool {
            if (!valid_ || payload.size()>bytes_.size()-sizeof(abi::rtattr)) { valid_=false; return false; }
            auto offset = aligned(size_), length = sizeof(abi::rtattr) + payload.size(), total = aligned(length);
            if (!valid_ || length > 65535 || offset > bytes_.size() || total > bytes_.size() - offset) {
                valid_ = false;
                return false;
            }
            put(offset, abi::rtattr{static_cast<std::uint16_t>(length), type});
            std::ranges::copy(payload, bytes_.begin() + offset + sizeof(abi::rtattr));
            size_ = offset + total;
            return true;
        }
        template <class T> auto scalar(std::uint16_t type, T value) noexcept -> bool {
            static_assert(std::is_trivially_copyable_v<T>);
            auto bytes = std::bit_cast<std::array<std::uint8_t, sizeof(T)>>(value);
            return append(type, bytes);
        }
        auto string(std::uint16_t type, std::string_view value) noexcept -> bool {
            if (value.size() > 255 || value.find('\0') != value.npos) {
                valid_ = false;
                return false;
            }
            std::array<std::uint8_t, 256> bytes{};
            std::ranges::copy(value, bytes.begin());
            return append(type, std::span(bytes).first(value.size() + 1));
        }
        auto stamp(std::uint32_t sequence, std::uint32_t pid) noexcept -> void {
            auto header = *native<abi::nlmsghdr>(bytes_);
            header.nlmsg_len = static_cast<std::uint32_t>(size_);
            header.nlmsg_seq = sequence;
            header.nlmsg_pid = pid;
            put(0, header);
        }
        [[nodiscard]] auto valid() const noexcept -> bool { return valid_; }
        [[nodiscard]] auto bytes() const noexcept -> std::span<std::uint8_t const> { return std::span(bytes_).first(size_); }
        [[nodiscard]] auto header() const noexcept -> abi::nlmsghdr {
            auto header = *native<abi::nlmsghdr>(bytes_);
            header.nlmsg_len = static_cast<std::uint32_t>(size_);
            return header;
        }
    };
    struct ReplyState {
        abi::nlmsghdr request;
        bool dump = false, lookup = false, done = false;
        std::size_t received = 0;
        template <class Visitor> auto receive(Message message, std::uint32_t local, Visitor &&visitor) -> std::expected<void, Failure> {
            auto const &header = message.header;
            if (++received > 4096) return fail(Error::limit);
            if (header.nlmsg_pid != local || !header.nlmsg_seq) return fail(Error::protocol);
            if (header.nlmsg_seq < request.nlmsg_seq) return {}; // Delayed reply from an earlier transaction on this private socket.
            if (done || header.nlmsg_seq != request.nlmsg_seq || (header.nlmsg_flags & abi::NLM_F_DUMP_INTR)) return fail(Error::protocol);
            if (header.nlmsg_type == abi::NLMSG_ERROR) {
                auto value = native<abi::nlmsgerr>(message.payload);
                if (!value || std::memcmp(&value->msg, &request, sizeof(request)) || value->error > 0 || value->error == std::numeric_limits<int>::min())
                    return fail(Error::protocol);
                if (value->error) return fail(Error::system, std::error_code{-value->error, std::generic_category()}, false, true);
                if (lookup) return fail(Error::protocol);
                if (!dump) done = true;
                return {};
            }
            if (header.nlmsg_type == abi::NLMSG_DONE) {
                auto error = native<std::int32_t>(message.payload);
                if (!dump || !error || *error > 0 || *error == std::numeric_limits<std::int32_t>::min()) return fail(Error::protocol);
                if (*error) return fail(Error::system, std::error_code{-*error, std::generic_category()});
                done = true;
                return {};
            }
            if (header.nlmsg_type == abi::NLMSG_NOOP || header.nlmsg_type == abi::NLMSG_OVERRUN) return fail(Error::protocol);
            if (lookup) {
                if (dump || (header.nlmsg_flags&abi::NLM_F_MULTI)) return fail(Error::protocol);
                auto accepted=visitor(message); if (!accepted) return accepted;
                done=true; return {};
            }
            if (!dump || !(header.nlmsg_flags & abi::NLM_F_MULTI)) return fail(Error::protocol);
            return visitor(message);
        }
    };
} // namespace platform::netlink
