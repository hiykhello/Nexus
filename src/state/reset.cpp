module state.maintenance;
import std;
import state.file;
import state.lock;

namespace state {
    namespace {
        auto backup(NativeHandle directory, std::string_view name) -> std::expected<std::string, StateError> {
            auto stamp = std::chrono::system_clock::now().time_since_epoch().count();
            auto destination = std::format("{}.backup.{}", name, stamp);
            if (auto moved = rename_dir_file(directory, name, destination, true, Stage::replace); !moved)
                return std::unexpected(moved.error());
            if (auto synced = sync_handle(directory, Stage::sync_directory, true); !synced)
                return std::unexpected(synced.error());
            return destination;
        }
    }

    auto reset_selectors(std::filesystem::path const& directory) -> std::expected<std::string, StateError> {
        auto locked = InstanceLock::open(directory);
        if (!locked) return std::unexpected(locked.error());
        auto removed = unlink_dir_file(locked->directory(), ".selectors.next", Stage::remove_blob);
        if (!removed) return std::unexpected(removed.error());
        return backup(locked->directory(), "selectors.state");
    }

    auto reset_fakeip(std::filesystem::path const& root) -> std::expected<std::string, StateError> {
        auto parent = open_private_directory(root);
        if (!parent) return std::unexpected(parent.error());
        auto directory = open_private_directory(root / "fakeip");
        if (!directory) return std::unexpected(directory.error());
        auto locked = InstanceLock::open(root / "fakeip");
        if (!locked) return std::unexpected(locked.error());
        auto same = same_directory_entry(locked->directory(), parent->get(), "fakeip");
        if (!same) return std::unexpected(same.error());
        if (!*same) return std::unexpected(StateError{Stage::directory, std::make_error_code(std::errc::io_error)});
        return backup(parent->get(), "fakeip");
    }
}
