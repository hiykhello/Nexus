export module platform.resolved_codec;
import std;
import platform.dbus_wire;
import platform.netlink_abi;
import platform.resolved_bus;
import platform.resolved_types;

export namespace platform::resolved::codec {
    template<std::size_t Size>
    inline auto text(std::string_view source, std::array<char, Size>& destination) noexcept -> bool {
        if (source.size() >= Size || source.find('\0') != source.npos) return false;
        destination.fill(0);
        if (!source.empty()) std::ranges::copy(source, destination.begin());
        return true;
    }

    inline auto servers(dbus::Reader& r, Snapshot& output) noexcept -> std::expected<void, Failure> {
        std::string_view vsig;
        if (!r.read_signature(vsig) || vsig != "a(iayqs)") return fail(Error::protocol);
        std::size_t arr_end = 0;
        if (!r.enter_array(8, arr_end)) return fail(Error::protocol);
        auto const saved_end = r.end;
        r.end = arr_end;
        while (r.pos < arr_end) {
            if (!r.enter_struct() || r.pos >= arr_end) { r.end = saved_end; return fail(Error::protocol); }
            if (output.server_count == output.servers.size()) { r.end = saved_end; return fail(Error::capacity); }
            Server item{};
            std::int32_t family = 0;
            std::span<std::uint8_t const> addr;
            std::string_view name;
            if (!r.read_i32(family) || !r.read_byte_array(addr) ||
                !r.read_u16(item.port) || !r.read_string(name)) {
                r.end = saved_end;
                return fail(Error::protocol);
            }
            item.family = family == netlink_abi::AF_INET ? 4 : family == netlink_abi::AF_INET6 ? 6 : 0;
            if (!item.family || addr.size() != (item.family == 4 ? 4u : 16u) || !text(name, item.name)) {
                r.end = saved_end;
                return fail(Error::protocol);
            }
            std::memcpy(item.address.data(), addr.data(), addr.size());
            output.servers[output.server_count++] = item;
        }
        bool const exact = r.pos == arr_end;
        r.end = saved_end;
        if (!exact) return fail(Error::protocol);
        return {};
    }

    inline auto domains(dbus::Reader& r, Snapshot& output) noexcept -> std::expected<void, Failure> {
        std::string_view vsig;
        if (!r.read_signature(vsig) || vsig != "a(sb)") return fail(Error::protocol);
        std::size_t arr_end = 0;
        if (!r.enter_array(8, arr_end)) return fail(Error::protocol);
        auto const saved_end = r.end;
        r.end = arr_end;
        while (r.pos < arr_end) {
            if (!r.enter_struct() || r.pos >= arr_end) { r.end = saved_end; return fail(Error::protocol); }
            if (output.domain_count == output.domains.size()) { r.end = saved_end; return fail(Error::capacity); }
            Domain item{};
            std::string_view name;
            if (!r.read_string(name) || !r.read_bool(item.route_only) ||
                !text(name, item.name) || !item.name.front()) {
                r.end = saved_end;
                return fail(Error::protocol);
            }
            output.domains[output.domain_count++] = item;
        }
        bool const exact = r.pos == arr_end;
        r.end = saved_end;
        if (!exact) return fail(Error::protocol);
        return {};
    }

    inline auto snapshot(Message const& message) noexcept -> std::expected<Snapshot, Failure> {
        if (message.signature() != "a{sv}") return fail(Error::protocol);
        auto r = message.reader();
        std::size_t arr_end = 0;
        if (!r.enter_array(8, arr_end)) return fail(Error::protocol);
        auto const saved_end = r.end;
        r.end = arr_end;
        Snapshot output;
        bool dns = false;
        bool domain = false;
        while (r.pos < arr_end) {
            if (!r.enter_struct() || r.pos >= arr_end) { r.end = saved_end; return fail(Error::protocol); }
            std::string_view prop;
            if (!r.read_string(prop)) { r.end = saved_end; return fail(Error::protocol); }
            if (prop == "DNSEx") {
                if (dns) { r.end = saved_end; return fail(Error::protocol); }
                dns = true;
                auto res = servers(r, output);
                if (!res) { r.end = saved_end; return std::unexpected(res.error()); }
            } else if (prop == "Domains") {
                if (domain) { r.end = saved_end; return fail(Error::protocol); }
                domain = true;
                auto res = domains(r, output);
                if (!res) { r.end = saved_end; return std::unexpected(res.error()); }
            } else if (!r.skip_variant()) {
                r.end = saved_end;
                return fail(Error::protocol);
            }
        }
        bool const exact = r.pos == arr_end;
        r.end = saved_end;
        if (!exact || !dns || !domain || !r.at_end()) return fail(Error::protocol);
        return output;
    }

    // Check the complete manager domain stream without storing unrelated links.
    // Bound work independently of message size, retaining no borrowed strings.
    inline auto competing_domains(Message const& message, int ours) noexcept -> std::expected<bool, Failure> {
        if (message.signature() != "v") return fail(Error::protocol);
        auto r = message.reader();
        std::string_view vsig;
        if (!r.read_signature(vsig) || vsig != "a(isb)") return fail(Error::protocol);
        std::size_t arr_end = 0;
        if (!r.enter_array(8, arr_end)) return fail(Error::protocol);
        auto const saved_end = r.end;
        r.end = arr_end;
        bool conflict = false;
        unsigned records = 0;
        while (r.pos < arr_end) {
            if (++records > 1024) { r.end = saved_end; return fail(Error::capacity); }
            if (!r.enter_struct() || r.pos >= arr_end) { r.end = saved_end; return fail(Error::protocol); }
            std::int32_t index = 0;
            std::string_view name;
            bool only = false;
            if (!r.read_i32(index) || !r.read_string(name) || !r.read_bool(only) || name.empty()) {
                r.end = saved_end;
                return fail(Error::protocol);
            }
            if (index != ours) conflict = true;
        }
        bool const exact = r.pos == arr_end;
        r.end = saved_end;
        if (!exact || !r.at_end()) return fail(Error::protocol);
        return conflict;
    }

    inline auto append_servers(Request& request, Snapshot const& desired) noexcept -> std::expected<void, Failure> {
        if (desired.server_count > desired.servers.size()) return fail(Error::capacity);
        for (std::size_t i = 0; i < desired.server_count; ++i) {
            auto const& item = desired.servers[i];
            if ((item.family != 4 && item.family != 6) ||
                std::ranges::find(item.name, '\0') == item.name.end() ||
                (item.family == 4 && std::ranges::any_of(std::span(item.address).subspan(4), [](auto b) { return b != 0; }))) {
                return fail(Error::protocol);
            }
        }
        auto w = request.body_writer();
        dbus::BodyWriter::ArrayScope scope{};
        if (!w.begin_array(8, scope)) return fail(Error::capacity);
        for (std::size_t i = 0; i < desired.server_count; ++i) {
            auto const& item = desired.servers[i];
            std::int32_t const family = item.family == 4 ? netlink_abi::AF_INET : netlink_abi::AF_INET6;
            auto const addr = std::span<std::uint8_t const>(item.address.data(), item.family == 4 ? 4u : 16u);
            if (!w.begin_struct() || !w.write_i32(family) || !w.write_byte_array(addr) ||
                !w.write_u16(item.port) || !w.write_string(std::string_view(item.name.data()))) {
                return fail(Error::capacity);
            }
        }
        if (!w.end_array(scope) || !request.commit_body(w, "a(iayqs)")) return fail(Error::capacity);
        return {};
    }

    inline auto append_domains(Request& request, Snapshot const& desired) noexcept -> std::expected<void, Failure> {
        if (desired.domain_count > desired.domains.size()) return fail(Error::capacity);
        for (std::size_t i = 0; i < desired.domain_count; ++i) {
            if (!desired.domains[i].name.front() ||
                std::ranges::find(desired.domains[i].name, '\0') == desired.domains[i].name.end()) {
                return fail(Error::protocol);
            }
        }
        auto w = request.body_writer();
        dbus::BodyWriter::ArrayScope scope{};
        if (!w.begin_array(8, scope)) return fail(Error::capacity);
        for (std::size_t i = 0; i < desired.domain_count; ++i) {
            auto const& item = desired.domains[i];
            if (!w.begin_struct() || !w.write_string(std::string_view(item.name.data())) ||
                !w.write_bool(item.route_only)) {
                return fail(Error::capacity);
            }
        }
        if (!w.end_array(scope) || !request.commit_body(w, "a(sb)")) return fail(Error::capacity);
        return {};
    }
}
