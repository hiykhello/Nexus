module cli.control;
import std;
import state.snapshot;

namespace cli {
    namespace {
        constexpr std::string_view version="NXSEL1";
        constexpr std::size_t max_choices=16;
        constexpr std::size_t max_snapshot=version.size()+1+max_choices*512;

        const ::state::SnapshotSpec selector_snapshot{
            "selectors.state", ".selectors.next",
            {.max_payload=max_snapshot, .fingerprint={std::byte{'S'}, std::byte{'E'}, std::byte{'L'}}},
            ::state::Magic{'N','X','S','E','L','1'}
        };

        auto error(std::string_view stage) -> std::unexpected<std::string> {
            return std::unexpected(std::format("selector state {}",stage));
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
        self.instance_.emplace(std::move(*instance));
        return {};
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
