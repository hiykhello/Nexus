module;
#include <cerrno>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
module state.maintenance;
import std;
import state.file;
import state.lock;

namespace state {
    namespace {
        auto backup(int directory,std::string_view name) -> std::expected<std::string,StateError> {
            auto source=std::string(name);
            auto stamp=std::chrono::system_clock::now().time_since_epoch().count();
            auto destination=std::format("{}.backup.{}",name,stamp);
            // Rename preserves the complete data, metadata and permissions in a
            // single atomic operation. Never replace an existing backup.
            if (::renameat2(directory,source.c_str(),directory,destination.c_str(),RENAME_NOREPLACE)<0)
                return failure(Stage::replace,errno);
            if (sync_file(directory)<0) return failure(Stage::sync_directory,errno,true);
            return destination;
        }

        auto remove_file(int directory,char const* name) -> std::expected<void,StateError> {
            if (::unlinkat(directory,name,0)<0 && errno!=ENOENT) return failure(Stage::remove_blob,errno);
            return {};
        }
    }

    auto reset_selectors(std::filesystem::path const& directory) -> std::expected<std::string,StateError> {
        auto locked=InstanceLock::open(directory);
        if (!locked) return std::unexpected(locked.error());
        auto removed=remove_file(locked->directory(),".selectors.next");
        if (!removed) return std::unexpected(removed.error());
        return backup(locked->directory(),"selectors.state");
    }

    auto reset_fakeip(std::filesystem::path const& root) -> std::expected<std::string,StateError> {
        auto parent=open_private_directory(root);
        if (!parent) return std::unexpected(parent.error());
        auto directory=open_private_directory(root/"fakeip");
        if (!directory) return std::unexpected(directory.error());
        auto locked=InstanceLock::open(root/"fakeip");
        if (!locked) return std::unexpected(locked.error());
        struct stat held{}, named{};
        if (::fstat(locked->directory(),&held)<0 ||
            ::fstatat(parent->get(),"fakeip",&named,AT_SYMLINK_NOFOLLOW)<0)
            return failure(Stage::directory,errno);
        if (held.st_dev!=named.st_dev || held.st_ino!=named.st_ino) return failure(Stage::directory,ESTALE);
        return backup(parent->get(),"fakeip");
    }

    auto clear_legacy_dns(std::filesystem::path const& directory) -> std::expected<void,StateError> {
        auto locked=InstanceLock::open(directory);
        if (!locked) {
            if (locked.error().os==std::errc::no_such_file_or_directory) return {};
            return std::unexpected(locked.error());
        }
        for (auto name:{"messages.cache",".messages.next"}) {
            auto removed=remove_file(locked->directory(),name);
            if (!removed) return removed;
        }
        if (sync_file(locked->directory())<0) return failure(Stage::sync_directory,errno);
        return {};
    }
}
