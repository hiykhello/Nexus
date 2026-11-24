module state.ruleset_storage;
import std;
import state.file;
import crypto;
import blake3;

namespace state {
    namespace {
        constexpr std::string_view staging = ".blob.next";

        auto blob_name(Fingerprint const& hash) -> std::string {
            std::string name;
            name.reserve(69);
            constexpr std::string_view hex = "0123456789abcdef";
            for (auto byte : hash) {
                auto value = std::to_integer<unsigned>(byte);
                name += hex[value >> 4];
                name += hex[value & 0xf];
            }
            name += ".blob";
            return name;
        }

        auto blob_filename(std::string_view name) noexcept -> bool {
            return name.size() == 69 && name.ends_with(".blob") &&
                std::ranges::all_of(name.substr(0, 64), [](char ch) {
                    return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
                });
        }
    }

    auto rule_blake3(std::string_view body) noexcept -> Fingerprint {
        blake3::blake3_hasher state;
        blake3::blake3_hasher_init(&state);
        blake3::blake3_hasher_update(&state, body.data(), body.size());
        Fingerprint hash;
        blake3::blake3_hasher_finalize(&state, reinterpret_cast<std::uint8_t*>(hash.data()), hash.size());
        return hash;
    }

    auto rule_sha256(std::string_view body) -> std::expected<Fingerprint, StateError> {
        auto bytes = std::span(reinterpret_cast<std::uint8_t const*>(body.data()), body.size());
        auto hash = ::crypto::digest(::crypto::Hash::sha256, bytes);
        Fingerprint result{};
        if (!hash || hash->size() != result.size()) return std::unexpected(StateError{Stage::digest});
        std::ranges::copy(std::as_bytes(std::span(*hash)), result.begin());
        return result;
    }

    auto read_rule_blob(NativeHandle directory, RulesetMetadata const& metadata)
        -> std::expected<std::string, StateError> {
        auto name = blob_name(metadata.content_blake3);
        auto fd = open_dir_read(directory, name, true, Stage::open);
        if (!fd) return std::unexpected(fd.error());
        auto sz = handle_size(fd->get(), Stage::read);
        if (!sz) return std::unexpected(sz.error());
        if (*sz != metadata.size_bytes) return std::unexpected(StateError{Stage::format});
        std::string body(metadata.size_bytes, '\0');
        auto got = read_handle(fd->get(), std::as_writable_bytes(std::span(body)), Stage::read);
        if (!got) return std::unexpected(got.error());
        if (*got != body.size()) return std::unexpected(StateError{Stage::format});
        std::byte extra{};
        auto probe = read_handle(fd->get(), std::span(&extra, 1), Stage::read);
        if (!probe) return std::unexpected(probe.error());
        if (*probe != 0 || rule_blake3(body) != metadata.content_blake3)
            return std::unexpected(StateError{Stage::checksum});
        auto sha = rule_sha256(body);
        if (!sha) return std::unexpected(sha.error());
        if (*sha != metadata.content_sha256) return std::unexpected(StateError{Stage::checksum});
        return body;
    }

    auto remove_rule_blob(NativeHandle directory, Fingerprint const& hash) -> std::expected<void, StateError> {
        return unlink_dir_file(directory, blob_name(hash), Stage::remove_blob);
    }

    auto write_rule_blob(NativeHandle directory, Fingerprint const& hash, std::string_view body)
        -> std::expected<void, StateError> {
        auto name = blob_name(hash);
        auto cleared = unlink_dir_file(directory, staging, Stage::remove_stage);
        if (!cleared) return cleared;
        auto file = open_dir_stage(directory, staging, Stage::create_stage);
        if (!file) return std::unexpected(file.error());
        auto abort = [&](StateError error) -> std::unexpected<StateError> {
            auto deleted = unlink_dir_file(directory, staging, Stage::remove_stage);
            if (deleted) return std::unexpected(error);
            auto fail = deleted.error();
            fail.preceding = error.stage;
            fail.preceding_os = error.os;
            return std::unexpected(fail);
        };
        auto written = write_handle_all(file->get(), std::as_bytes(std::span(body)), Stage::write);
        if (written) written = sync_handle(file->get(), Stage::sync_stage);
        auto closed = close_file(*file, Stage::close_stage);
        if (!written) return abort(written.error());
        if (!closed) return abort(closed.error());
        if (auto moved = rename_dir_file(directory, staging, name, false, Stage::replace); !moved)
            return abort(moved.error());
        return sync_handle(directory, Stage::sync_directory, true);
    }

    auto sweep_rule_blobs(NativeHandle directory, std::span<RulesetRow const> rows) -> std::expected<void, StateError> {
        std::vector<std::string> retained;
        retained.reserve(rows.size());
        for (auto const& row : rows) retained.push_back(blob_name(row.metadata.content_blake3));
        auto candidates = directory_entries(directory, [&](std::string_view name) {
            return name == staging || (blob_filename(name) && std::ranges::find(retained, name) == retained.end());
        });
        if (!candidates) return std::unexpected(candidates.error());
        bool changed = false;
        for (auto const& item : *candidates) {
            auto deleted = unlink_dir_file(directory, item.name, Stage::remove_blob);
            if (!deleted) return deleted;
            changed = true;
        }
        if (changed) return sync_handle(directory, Stage::sync_directory, true);
        return {};
    }
}
