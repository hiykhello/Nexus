module cli.control;
import std;
import state.snapshot;

namespace cli {
    namespace {
        constexpr std::string_view version="NXSEL1";
        constexpr std::size_t max_choices=16;
        constexpr std::size_t max_snapshot=version.size()+1+max_choices*512;
        constexpr std::string_view mode_version="NXMOD1";
        constexpr std::size_t max_mode_snapshot=mode_version.size()+2+255;

        const ::state::SnapshotSpec selector_snapshot{
            "selectors.state", ".selectors.next",
            {.max_payload=max_snapshot, .fingerprint={std::byte{'S'}, std::byte{'E'}, std::byte{'L'}}}
        };

        const ::state::SnapshotSpec route_mode_snapshot{
            "route-mode.state", ".route-mode.next",
            {.max_payload=max_mode_snapshot, .fingerprint={std::byte{'R'}, std::byte{'M'}, std::byte{'D'}}}
        };

        auto error(std::string_view stage) -> std::unexpected<std::string> {
            return std::unexpected(std::format("selector state {}",stage));
        }

        auto mode_error(std::string_view stage) -> std::unexpected<std::string> {
            return std::unexpected(std::format("route-mode state {}",stage));
        }

        auto encode_mode_code(std::string_view mode) noexcept -> std::optional<std::uint8_t> {
            if (mode == "rule") return std::uint8_t{0};
            if (mode == "global") return std::uint8_t{1};
            if (mode == "direct") return std::uint8_t{2};
            return std::nullopt;
        }

        auto decode_mode_code(std::uint8_t code) noexcept -> std::optional<std::string_view> {
            switch (code) {
            case 0: return std::string_view{"rule"};
            case 1: return std::string_view{"global"};
            case 2: return std::string_view{"direct"};
            default: return std::nullopt;
            }
        }

        auto decode_route_mode(std::string_view bytes) -> std::expected<PersistedRouteMode,std::string> {
            if (bytes.size() < mode_version.size() + 2 || !bytes.starts_with(mode_version))
                return mode_error("has an unsupported or damaged format");
            bytes.remove_prefix(mode_version.size());
            auto mode_name = decode_mode_code(static_cast<unsigned char>(bytes[0]));
            auto out_len = static_cast<unsigned char>(bytes[1]);
            bytes.remove_prefix(2);
            if (!mode_name || bytes.size() != out_len || bytes.contains('\0'))
                return mode_error("has an unsupported or damaged format");
            return PersistedRouteMode{std::string(*mode_name), std::string(bytes)};
        }

        auto decode(std::string_view bytes) -> std::expected<std::vector<SelectorChoice>,std::string> {
            if (bytes.size()<=version.size() || !bytes.starts_with(version))
                return error("has an unsupported or damaged format");
            bytes.remove_prefix(version.size());
            auto count=static_cast<unsigned char>(bytes.front());
            bytes.remove_prefix(1);
            if (count>max_choices) return error("has too many choices");
            auto name=[&]() -> std::optional<std::string_view> {
                if (bytes.empty()) return {};
                auto size=static_cast<unsigned char>(bytes.front());
                if (!size || bytes.size()<=size) return {};
                auto result=bytes.substr(1,size);
                bytes.remove_prefix(1+size);
                if (result.contains('\0')) return {};
                return result;
            };
            std::vector<SelectorChoice> choices;
            choices.reserve(count);
            for (unsigned index=0;index<count;++index) {
                auto group=name();
                auto member=name();
                if (!group || !member ||
                    std::ranges::find(choices,*group,&SelectorChoice::group)!=choices.end())
                    return error("contains invalid or duplicate choices");
                choices.push_back({std::string(*group),std::string(*member)});
            }
            if (!bytes.empty()) return error("contains trailing data");
            return choices;
        }

        auto io_error(::state::StateError const& failure) -> std::unexpected<std::string> {
            using ::state::Stage;
            switch (failure.stage) {
            case Stage::directory: return error("directory must be owned by the process user and private");
            case Stage::lock: return error("directory cannot be locked");
            case Stage::lock_file: return error("instance lock must be a private regular file");
            case Stage::open: return error("must be a private regular file");
            case Stage::format:
            case Stage::version:
            case Stage::checksum: return error("has an unsupported or damaged format");
            case Stage::remove_stage:
                return error(std::format("cannot clear staging file: {}", failure.os.message()));
            default: return error(std::format("cannot commit snapshot ({})", ::state::describe(failure.stage)));
            }
        }
    }

    SelectorState::~SelectorState() = default;

    auto SelectorState::open(this SelectorState& self,std::string const& path) -> std::expected<void,std::string> {
        auto instance=::state::InstanceLock::open(path);
        if (!instance) return io_error(instance.error());
        auto snapshot=::state::load_snapshot(*instance,selector_snapshot);
        if (!snapshot) return io_error(snapshot.error());
        if (*snapshot) {
            auto const& payload=(**snapshot).payload;
            auto choices=decode({reinterpret_cast<char const*>(payload.data()),payload.size()});
            if (!choices) return std::unexpected(std::move(choices.error()));
            self.choices_=std::move(*choices);
            self.revision_=(**snapshot).header.revision;
        }
        auto mode_snap=::state::load_snapshot(*instance,route_mode_snapshot);
        if (!mode_snap) return io_error(mode_snap.error());
        if (*mode_snap) {
            auto const& payload=(**mode_snap).payload;
            auto decoded=decode_route_mode({reinterpret_cast<char const*>(payload.data()),payload.size()});
            if (!decoded) return std::unexpected(std::move(decoded.error()));
            self.route_mode_=std::move(*decoded);
            self.route_mode_revision_=(**mode_snap).header.revision;
        }
        self.instance_.emplace(std::move(*instance));
        return {};
    }

    auto SelectorState::open_route_mode_only(this SelectorState& self,std::string const& path) -> std::expected<void,std::string> {
        auto instance=::state::InstanceLock::open(path);
        if (!instance) return io_error(instance.error());
        auto mode_snap=::state::load_snapshot(*instance,route_mode_snapshot);
        if (!mode_snap) return io_error(mode_snap.error());
        if (*mode_snap) {
            auto const& payload=(**mode_snap).payload;
            auto decoded=decode_route_mode({reinterpret_cast<char const*>(payload.data()),payload.size()});
            if (!decoded) return std::unexpected(std::move(decoded.error()));
            self.route_mode_=std::move(*decoded);
            self.route_mode_revision_=(**mode_snap).header.revision;
        }
        self.instance_.emplace(std::move(*instance));
        return {};
    }

    auto SelectorState::save_route_mode(this SelectorState& self,std::string_view mode,std::string_view global_outbound)
        -> std::expected<bool,std::string> {
        auto code = encode_mode_code(mode);
        if (!code || global_outbound.size() > 255 || global_outbound.contains('\0'))
            return mode_error("contains invalid values");
        if (!self.instance_) return true;
        if (self.route_mode_revision_ == std::numeric_limits<std::uint64_t>::max())
            return mode_error("revision exhausted");
        std::string payload(mode_version);
        payload.push_back(static_cast<char>(*code));
        payload.push_back(static_cast<char>(static_cast<unsigned char>(global_outbound.size())));
        payload.append(global_outbound);
        auto revision = self.route_mode_revision_ + 1;
        auto persisted = ::state::commit_snapshot(*self.instance_, route_mode_snapshot, revision, 0,
            std::as_bytes(std::span(payload)));
        if (!persisted) return io_error(persisted.error());
        self.route_mode_revision_ = revision;
        self.route_mode_ = PersistedRouteMode{std::string(mode), std::string(global_outbound)};
        return persisted->state == ::state::CommitState::committed;
    }

    auto SelectorState::select(this SelectorState& self,std::string_view group,std::string_view member)
        -> std::expected<bool,std::string> {
        if (!self.instance_) return true;
        auto valid=[](std::string_view name) {return !name.empty() && name.size()<=255 && !name.contains('\0');};
        if (!valid(group) || !valid(member)) return error("contains invalid or duplicate choices");
        if (self.revision_==std::numeric_limits<std::uint64_t>::max()) return error("revision exhausted");
        auto choices=self.choices_;
        auto found=std::ranges::find(choices,group,&SelectorChoice::group);
        if (found==choices.end()) {
            if (choices.size()==max_choices) return error("has too many choices");
            choices.push_back({std::string(group),std::string(member)});
        } else found->member=member;

        std::string payload(version);
        payload.push_back(static_cast<char>(choices.size()));
        auto append=[&](std::string_view name) {
            payload.push_back(static_cast<char>(static_cast<unsigned char>(name.size())));
            payload.append(name);
        };
        for (auto const& choice:choices) {
            append(choice.group);
            append(choice.member);
        }

        auto revision=self.revision_+1;
        auto persisted=::state::commit_snapshot(*self.instance_,selector_snapshot,revision,0,
            std::as_bytes(std::span(payload)));
        if (!persisted) return io_error(persisted.error());
        self.revision_=revision;
        self.choices_.swap(choices);
        return persisted->state==::state::CommitState::committed;
    }
}
