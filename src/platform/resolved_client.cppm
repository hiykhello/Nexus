export module platform.resolved_client;
import std;
import platform.dbus_wire;
import platform.resolved_bus;
import platform.resolved_types;
import platform.resolved_codec;

export namespace platform::resolved {
    template<class Hooks = NoHooks> class Client {
        Bus<Hooks> bus_;
        std::array<char, 64> owner_{};
        std::array<char, 128> path_{};
        int index_ = 0;
        bool revoked_ = false;
        bool dirty_ = false;

        static constexpr char manager[] = "/org/freedesktop/resolve1";
        static constexpr char manager_interface[] = "org.freedesktop.resolve1.Manager";
        static constexpr char link_interface[] = "org.freedesktop.resolve1.Link";

        static auto owner_changed(Message const& message, void* userdata) noexcept -> void {
            auto& self = *static_cast<Client*>(userdata);
            if (message.signature() != "sss") {
                self.revoked_ = true;
                return;
            }
            std::string_view name, before, after;
            auto r = message.reader();
            if (!r.read_string(name) || !r.read_string(before) || !r.read_string(after) || !r.at_end()) {
                self.revoked_ = true;
                return;
            }
            if (name == "org.freedesktop.resolve1" && after != std::string_view(self.owner_.data())) {
                self.revoked_ = true;
            }
        }

        static auto changed(Message const&, void* userdata) noexcept -> void {
            static_cast<Client*>(userdata)->dirty_ = true;
        }

        template<bool ObserveCancellation = true>
        auto invoke(Request const& request, Clock::time_point deadline) -> std::expected<Message, Failure> {
            if (revoked_) return fail(Error::ownership);
            auto reply = bus_.template call<ObserveCancellation>(request, deadline);
            if (!reply) return std::unexpected(reply.error());
            if (revoked_ || reply->sender() != std::string_view(owner_.data())) {
                return fail(Error::ownership, 0, true);
            }
            return *reply;
        }

        auto setting(char const* member) -> std::expected<Request, Failure> {
            if (!index_ || revoked_) return fail(revoked_ ? Error::ownership : Error::state);
            auto request = bus_.message(owner_.data(), manager, manager_interface, member);
            if (!request) return std::unexpected(request.error());
            if (!request->append_i32(index_)) return fail(Error::capacity);
            return *request;
        }

        auto add_match(std::string_view rule, Clock::time_point deadline) -> std::expected<void, Failure> {
            auto request = bus_.message("org.freedesktop.DBus", "/org/freedesktop/DBus",
                "org.freedesktop.DBus", "AddMatch");
            if (!request) return std::unexpected(request.error());
            if (!request->append_string(rule)) return fail(Error::capacity);
            auto reply = bus_.call(*request, deadline);
            if (!reply) return std::unexpected(reply.error());
            if (!reply->signature().empty()) return fail(Error::protocol);
            return {};
        }

      public:
        Client() = default;
        ~Client() { close(); }
        Client(Client const&) = delete;
        auto operator=(Client const&) -> Client& = delete;
        Client(Client&&) = delete;
        auto operator=(Client&&) -> Client& = delete;

        auto close() noexcept -> void {
            bus_.close();
            index_ = 0;
            owner_.fill(0);
            path_.fill(0);
            revoked_ = dirty_ = false;
        }

        [[nodiscard]] auto native_handle() const noexcept -> int { return bus_.native_handle(); }
        [[nodiscard]] auto revoked() const noexcept -> bool { return revoked_; }
        [[nodiscard]] auto dirty() const noexcept -> bool { return dirty_; }
        auto mark_clean() noexcept -> void { dirty_ = false; }

        [[nodiscard]] auto open(int index, Clock::time_point deadline) -> std::expected<void, Failure> {
            if (index_ || index <= 0) return fail(Error::state);
            index_ = index;
            auto abort = [&](Failure error) -> std::expected<void, Failure> {
                close();
                return std::unexpected(error);
            };
            auto connected = bus_.open(deadline);
            if (!connected) return abort(connected.error());
            {
                auto request = bus_.message("org.freedesktop.DBus", "/org/freedesktop/DBus",
                    "org.freedesktop.DBus", "GetNameOwner");
                if (!request) return abort(request.error());
                if (!request->append_string("org.freedesktop.resolve1")) return abort(Failure{Error::capacity});
                auto reply = bus_.call(*request, deadline);
                if (!reply) return abort(reply.error());
                std::string_view owner;
                auto r = reply->reader();
                if (reply->signature() != "s" || !r.read_string(owner) || !r.at_end() ||
                    !codec::text(owner, owner_) || owner_[0] != ':') {
                    return abort(Failure{Error::protocol});
                }
            }
            if constexpr (requires { Hooks::before_owner_watch(); }) {
                static_assert(noexcept(Hooks::before_owner_watch()));
                Hooks::before_owner_watch();
            }
            {
                SignalFilter owner_filter{};
                if (!Request::copy_text("org.freedesktop.DBus", owner_filter.sender) ||
                    !Request::copy_text("/org/freedesktop/DBus", owner_filter.path) ||
                    !Request::copy_text("org.freedesktop.DBus", owner_filter.interface) ||
                    !Request::copy_text("NameOwnerChanged", owner_filter.member) ||
                    !bus_.add_watch(owner_filter, owner_changed, this)) {
                    return abort(Failure{Error::capacity});
                }
                SignalFilter prop_filter{};
                if (!Request::copy_text(owner_.data(), prop_filter.sender) ||
                    !Request::copy_text("/org/freedesktop/resolve1", prop_filter.path) ||
                    !Request::copy_text("org.freedesktop.DBus.Properties", prop_filter.interface) ||
                    !Request::copy_text("PropertiesChanged", prop_filter.member) ||
                    !bus_.add_watch(prop_filter, changed, this)) {
                    return abort(Failure{Error::capacity});
                }
            }
            auto watched = add_match(
                "type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',"
                "member='NameOwnerChanged',arg0='org.freedesktop.resolve1'", deadline);
            if (!watched) return abort(watched.error());
            std::array<char, 320> match{};
            std::size_t used = 0;
            for (auto part : {
                    std::string_view("type='signal',sender='"),
                    std::string_view(owner_.data()),
                    std::string_view("',path='/org/freedesktop/resolve1',"
                        "interface='org.freedesktop.DBus.Properties',member='PropertiesChanged'")}) {
                if (part.size() >= match.size() - used) return abort(Failure{Error::capacity});
                std::ranges::copy(part, match.begin() + used);
                used += part.size();
            }
            watched = add_match(std::string_view(match.data(), used), deadline);
            if (!watched) return abort(watched.error());
            if (revoked_) return abort(Failure{Error::ownership});
            // Close the GetNameOwner -> installed-watch gap before sending
            // anything to the pinned unique name. A daemon can relinquish its
            // well-known name while its old process/unique name still lives.
            {
                auto request = bus_.message("org.freedesktop.DBus", "/org/freedesktop/DBus",
                    "org.freedesktop.DBus", "GetNameOwner");
                if (!request) return abort(request.error());
                if (!request->append_string("org.freedesktop.resolve1")) return abort(Failure{Error::capacity});
                auto reply = bus_.call(*request, deadline);
                if (!reply) return abort(reply.error());
                std::string_view current;
                auto r = reply->reader();
                if (reply->signature() != "s" || !r.read_string(current) || !r.at_end() ||
                    current != std::string_view(owner_.data()) || revoked_) {
                    return abort(Failure{Error::ownership});
                }
            }
            for (;;) {
                auto request = setting("GetLink");
                if (!request) return abort(request.error());
                auto reply = invoke(*request, deadline);
                if (reply) {
                    std::string_view link_path;
                    auto r = reply->reader();
                    if (reply->signature() != "o" || !r.read_object_path(link_path) || !r.at_end() ||
                        !codec::text(link_path, path_) ||
                        !std::string_view(path_.data()).starts_with("/org/freedesktop/resolve1/link/")) {
                        return abort(Failure{Error::protocol});
                    }
                    return {};
                }
                auto error = reply.error();
                if (error.code != Error::remote ||
                    (error.system != std::errc::no_such_device_or_address && error.system != std::errc::no_such_device)) {
                    return abort(error);
                }
                auto until = std::min(deadline, Clock::now() + std::chrono::milliseconds(5));
                auto waited = bus_.until([&]() noexcept { return Clock::now() >= until; }, until);
                if (!waited) return abort(waited.error());
            }
        }

        template<bool ObserveCancellation = true>
        [[nodiscard]] auto snapshot(Clock::time_point deadline) -> std::expected<Snapshot, Failure> {
            if (!index_ || revoked_) return fail(revoked_ ? Error::ownership : Error::state);
            auto request = bus_.message(owner_.data(), path_.data(), "org.freedesktop.DBus.Properties", "GetAll");
            if (!request) return std::unexpected(request.error());
            if (!request->append_string(link_interface)) return fail(Error::capacity);
            auto reply = invoke<ObserveCancellation>(*request, deadline);
            if (!reply) return std::unexpected(reply.error());
            return codec::snapshot(*reply);
        }

        template<bool ObserveCancellation = true>
        [[nodiscard]] auto competing_domains(Clock::time_point deadline) -> std::expected<bool, Failure> {
            if (!index_ || revoked_) return fail(revoked_ ? Error::ownership : Error::state);
            auto request = bus_.message(owner_.data(), manager, "org.freedesktop.DBus.Properties", "Get");
            if (!request) return std::unexpected(request.error());
            if (!request->append_string(manager_interface) || !request->append_string("Domains")) {
                return fail(Error::capacity);
            }
            auto reply = invoke<ObserveCancellation>(*request, deadline);
            if (!reply) return std::unexpected(reply.error());
            return codec::competing_domains(*reply, index_);
        }

        template<bool ObserveCancellation = true>
        [[nodiscard]] auto set_servers(Snapshot const& desired, Clock::time_point deadline)
            -> std::expected<void, Failure> {
            auto request = setting("SetLinkDNSEx");
            if (!request) return std::unexpected(request.error());
            auto appended = codec::append_servers(*request, desired);
            if (!appended) return appended;
            auto reply = invoke<ObserveCancellation>(*request, deadline);
            if (!reply) return std::unexpected(reply.error());
            if (!reply->signature().empty()) return fail(Error::protocol, 0, true);
            return {};
        }

        template<bool ObserveCancellation = true>
        [[nodiscard]] auto set_domains(Snapshot const& desired, Clock::time_point deadline)
            -> std::expected<void, Failure> {
            auto request = setting("SetLinkDomains");
            if (!request) return std::unexpected(request.error());
            auto appended = codec::append_domains(*request, desired);
            if (!appended) return appended;
            auto reply = invoke<ObserveCancellation>(*request, deadline);
            if (!reply) return std::unexpected(reply.error());
            if (!reply->signature().empty()) return fail(Error::protocol, 0, true);
            return {};
        }

        [[nodiscard]] auto process(Clock::time_point deadline) -> std::expected<bool, Failure> {
            return bus_.process(deadline);
        }
    };
}
