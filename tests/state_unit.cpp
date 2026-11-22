#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
import std;
import state;

using namespace std::chrono_literals;

namespace {
    namespace fs = std::filesystem;
    using state::CommitState;
    using state::Stage;
    const state::SnapshotSpec spec{"value.state", ".value.next"};

    auto check(bool condition, std::string_view what) -> void {
        if (!condition) {
            std::cerr << "FAIL " << what << '\n';
            std::exit(1);
        }
    }

    class Temporary {
        fs::path path_;
    public:
        Temporary() {
            char path[] = "/tmp/nexus-state-unit.XXXXXX";
            auto created = ::mkdtemp(path);
            check(created != nullptr, "create temporary state directory");
            path_ = created;
        }
        ~Temporary() {
            std::error_code ignored;
            fs::remove_all(path_, ignored);
        }
        auto path(this Temporary const& self) -> fs::path const& { return self.path_; }
    };

    auto bytes(std::string_view text) -> state::Bytes {
        auto view = std::as_bytes(std::span(text));
        return {view.begin(), view.end()};
    }

    auto instance(fs::path const& path) -> state::InstanceLock {
        auto opened = state::InstanceLock::open(path);
        check(opened.has_value(), "open instance");
        return std::move(*opened);
    }

    auto revision(std::string_view value) -> std::uint64_t {
        std::uint64_t number;
        auto result = std::from_chars(value.data(), value.data() + value.size(), number);
        check(result.ec == std::errc{} && result.ptr == value.end(), "revision is numeric");
        return number;
    }

    auto envelope() -> void {
        auto payload = bytes("payload");
        state::EnvelopeHeader header{.payload_bytes=7, .revision=0x0123456789abcdef, .clear_epoch=99};
        state::Fingerprint fingerprint{std::byte{0x42}};
        auto encoded = state::encode_header(header, payload, fingerprint);
        check(encoded && encoded->size() == 64 && (*encoded)[6] == std::byte{1} &&
              (*encoded)[8] == std::byte{1} && (*encoded)[12] == std::byte{7} &&
              (*encoded)[16] == std::byte{0xef} && (*encoded)[23] == std::byte{1} &&
              (*encoded)[24] == std::byte{99}, "fixed 64-byte little endian header");
        auto decoded = state::decode_header(*encoded, {});
        check(decoded && decoded->revision == header.revision && decoded->clear_epoch == 99 &&
              state::verify_payload(*encoded, *decoded, payload, fingerprint), "verify BLAKE3 envelope");
        auto corrupted = *encoded;
        corrupted[20] ^= std::byte{1};
        auto changed = state::decode_header(corrupted, {});
        check(changed && !state::verify_payload(corrupted, *changed, payload, fingerprint),
              "metadata covered by BLAKE3");
        check(!state::verify_payload(*encoded, *decoded, payload), "semantic fingerprint participates in hash");
        payload.back() ^= std::byte{1};
        auto mismatch = state::verify_payload(*encoded, *decoded, payload, fingerprint);
        check(!mismatch && mismatch.error().stage == Stage::checksum, "payload tampering detected");
        (*encoded)[6] = std::byte{2};
        auto unknown = state::decode_header(*encoded, {});
        check(!unknown && unknown.error().stage == Stage::version, "unknown version reported explicitly");
        (*encoded)[6] = std::byte{1};
        (*encoded)[10] = std::byte{1};
        check(!state::decode_header(*encoded, {}), "nonzero reserved header byte rejected");
    }

    auto locks() -> void {
        Temporary root;
        auto path = root.path() / "instance";
        fs::create_directory(path);
        fs::permissions(path, fs::perms::owner_all);
        {
            auto first = instance(path);
            auto second = state::InstanceLock::open(path);
            check(!second && second.error().stage == Stage::lock, "second owner cannot lock");
        }
        auto lock = path / "instance.lock";
        check(fs::exists(lock) && fs::status(lock).permissions() ==
              (fs::perms::owner_read | fs::perms::owner_write), "stable lock remains private");
        auto link = root.path() / "alias";
        fs::create_directory_symlink(path, link);
        check(!state::InstanceLock::open(link / "."), "reject symlink in directory path");
        fs::permissions(path, fs::perms::owner_all | fs::perms::group_read);
        check(!state::InstanceLock::open(path), "reject directory mode other than 0700");
        fs::permissions(path, fs::perms::owner_all);
        auto alias = root.path() / "lock-link";
        fs::create_hard_link(lock, alias);
        check(!state::InstanceLock::open(path), "reject lock with more than one link");
        fs::remove(alias);
        fs::rename(lock, alias);
        fs::create_symlink(alias, lock);
        check(!state::InstanceLock::open(path), "reject symlink at lock filename");
    }

    auto snapshot() -> void {
        Temporary root;
        auto locked = instance(root.path());
        auto empty = state::load_snapshot(locked, spec);
        check(empty && !*empty, "missing snapshot is optional");
        auto committed = state::commit_snapshot(locked, spec, 1, 3, bytes("initial"));
        check(committed && committed->state == CommitState::committed && !committed->error, "initial durable commit");
        auto loaded = state::load_snapshot(locked, spec);
        check(loaded && *loaded && (**loaded).header.revision == 1 && (**loaded).header.clear_epoch == 3 &&
              (**loaded).payload == bytes("initial"), "load envelope round trip");
        auto repeated = state::commit_snapshot(locked, spec, 1, 3, bytes("duplicate revision"));
        check(!repeated && repeated.error().stage == Stage::revision, "reject nonincreasing revision");
        auto stale = state::commit_snapshot(locked, spec, 2, 2, bytes("lower epoch"));
        check(!stale && stale.error().stage == Stage::stale_epoch, "on-disk epoch cannot regress");
        auto alias = root.path() / "alias";
        fs::create_hard_link(root.path() / spec.name, alias);
        auto linked = state::load_snapshot(locked, spec);
        check(!linked && linked.error().stage == Stage::open, "snapshot rejects multiple hardlinks");
        fs::remove(alias);
        fs::create_directory(root.path() / spec.staging_name);
        auto cleanup = state::commit_snapshot(locked, spec, 2, 3, bytes("next"));
        check(!cleanup && cleanup.error().stage == Stage::remove_stage && cleanup.error().os.value() != 0 &&
              !cleanup.error().replaced, "report actual unlink failure before replacing current file");
        fs::remove(root.path() / spec.staging_name);

        auto current = root.path() / spec.name;
        {
            std::fstream corrupt(current, std::ios::binary | std::ios::in | std::ios::out);
            corrupt.seekp(state::header_bytes);
            corrupt.put('X');
        }
        auto preserved = state::load_snapshot(locked, spec);
        check(!preserved && preserved.error().stage == Stage::checksum && fs::exists(current),
              "preserve damaged authority file by default");
        check(!state::commit_snapshot(locked, spec, 2, 4, bytes("new")), "damaged authority cannot be overwritten");
        auto isolated = state::load_snapshot(locked, spec, state::DamagePolicy::isolate);
        check(!isolated && isolated.error().stage == Stage::checksum && isolated.error().replaced &&
              !fs::exists(current), "explicitly isolate damaged file but keep failure visible");
        check(std::ranges::any_of(fs::directory_iterator(root.path()), [&](auto const& entry) {
            return entry.path().filename().string().starts_with(spec.name + ".corrupt.");
        }), "retain quarantined bytes");
        auto newer = spec;
        newer.envelope.schema_version = 2;
        check(state::commit_snapshot(locked, newer, 3, 4, bytes("v2")).has_value(), "write new schema fixture");
        auto old = state::load_snapshot(locked, spec, state::DamagePolicy::isolate);
        check(!old && old.error().stage == Stage::version && !old.error().replaced && fs::exists(current),
              "preserve unknown authority schema even with isolation requested");
        auto cache = spec;
        cache.name = "cache";
        cache.envelope.tier = state::Tier::cache;
        newer = cache;
        newer.envelope.schema_version = 2;
        check(state::commit_snapshot(locked, newer, 1, 0, bytes("cache-v2")).has_value(), "write cache schema fixture");
        auto old_cache = state::load_snapshot(locked, cache, state::DamagePolicy::isolate);
        check(!old_cache && old_cache.error().stage == Stage::version && old_cache.error().replaced &&
              !fs::exists(root.path() / cache.name), "isolate unknown cache schema for cold start");
    }

    auto owner(fs::path const& path, bool publication_phase) -> void {
        if (publication_phase) {
            auto locked = instance(path);
            check(state::commit_snapshot(locked, spec, 1, 4, bytes("seed")).has_value(), "seed persisted epoch");
        }
        int ready[2], release[2];
        check(::pipe2(ready, O_CLOEXEC) == 0 && ::pipe2(release, O_CLOEXEC) == 0, "open test gates");
        check(::setenv("NEXUS_STATE_READY_FD", std::to_string(ready[1]).c_str(), 1) == 0 &&
              ::setenv("NEXUS_STATE_RELEASE_FD", std::to_string(release[0]).c_str(), 1) == 0, "set fault gates");
        auto created = state::StateOwner::start(instance(path), spec, {.requests=2, .bytes=8});
        check(created.has_value(), "start bounded owner");
        auto& writer = **created;
        auto epoch = writer.current_epoch();
        check(epoch == (publication_phase ? 4 : 0), "owner restores epoch on reopen");
        auto moved = writer.submit(publication_phase ? 2 : 1, epoch, bytes("old!"));
        check(moved && moved->state == CommitState::accepted, "accept first owning request");
        pollfd input{ready[0], POLLIN, 0};
        char token;
        check(::poll(&input, 1, 3000) == 1 && ::read(ready[0], &token, 1) == 1, "writer reached fsync gate");
        if (publication_phase) {
            check(moved->publication.wait_for(0ms) == std::future_status::ready &&
                  moved->publication.get() == CommitState::visible &&
                  moved->result.wait_for(0ms) == std::future_status::timeout,
                  "rename publishes a visible receipt while directory fsync is pending");
            auto pending = writer.drain(state::Clock::now() + 10ms);
            check(!pending.completed && pending.pending == 1, "visible still counts as pending");
            check(::write(release[1], "x", 1) == 1, "release directory fsync");
            auto committed = moved->result.get();
            check(committed && committed->state == CommitState::committed &&
                  writer.drain(state::Clock::now() + 2s).completed, "durable receipt follows directory sync");
            for (auto fd : {ready[0], ready[1], release[0], release[1]}) ::close(fd);
            std::println("PASS accepted, visible and durable receipts with persisted epoch restore");
            return;
        }
        auto over = writer.submit(2, 0, bytes("five!"));
        check(!over && over.error().stage == Stage::capacity, "in-flight bytes count against quota");
        auto old = writer.submit(2, 0, bytes("next"));
        auto full = writer.submit(3, 0, {});
        check(old && !full && full.error().stage == Stage::capacity, "queue item quota includes active work");
        auto next = writer.advance_epoch();
        check(next && *next == 1, "advance clear epoch while old batch is prepared");
        auto timed_out = writer.drain(state::Clock::now() + 10ms);
        check(!timed_out.completed && timed_out.pending == 2 && timed_out.bytes == 8 &&
              moved->result.wait_for(0ms) == std::future_status::timeout, "timed-out drain reports true pending work");
        check(::write(release[1], "x", 1) == 1, "release blocked fsync");
        check(!moved->publication.get() && !old->publication.get(), "rejected requests never report visible");
        auto rejected = moved->result.get();
        auto queued = old->result.get();
        check(!rejected && rejected.error().stage == Stage::stale_epoch && !rejected.error().replaced &&
              !queued && queued.error().stage == Stage::stale_epoch, "reject both in-flight and queued old epochs");
        auto drained = writer.drain(state::Clock::now() + 2s);
        auto after = writer.submit(3, *next, bytes("done"));
        check(drained.completed && drained.pending == 0 && drained.bytes == 0 && !after &&
              after.error().stage == Stage::stopped && !fs::exists(path / spec.name), "drained owner cannot publish old data");
        for (auto fd : {ready[0], ready[1], release[0], release[1]}) ::close(fd);
        std::println("PASS owner capacity, in-flight epoch barrier, deadlines and actual receipts");
    }
}

auto main(int argc, char** argv) -> int {
    if (argc == 1) {
        envelope();
        locks();
        snapshot();
        std::println("PASS envelope, instance locks, durable snapshots, isolation and unlink errors");
        return 0;
    }
    check(argc >= 3, "expected mode and directory");
    auto mode = std::string_view(argv[1]);
    auto path = fs::path(argv[2]);
    if (mode == "owner" || mode == "owner-visible") {
        owner(path, mode == "owner-visible");
        return 0;
    }
    auto locked = instance(path);
    if (mode == "write") {
        check(argc == 5, "write requires revision and value");
        auto result = state::commit_snapshot(locked, spec, revision(argv[3]), 0, bytes(argv[4]));
        if (!result) {
            auto const& error = result.error();
            std::println("{} os={} preceding={} prior-os={} replaced={}", state::describe(error.stage), error.os.value(),
                error.preceding ? state::describe(*error.preceding) : "-", error.preceding_os.value(), error.replaced);
            return 3;
        }
        auto durable = result->state == CommitState::committed;
        if (!durable)
            check(result->error && result->error->replaced && result->error->stage == Stage::sync_directory,
                  "uncertain receipt describes visible replacement");
        std::println("{}", durable ? "committed" : "uncertain");
        return 0;
    }
    auto result = state::load_snapshot(locked, spec,
        mode == "isolate" ? state::DamagePolicy::isolate : state::DamagePolicy::preserve);
    if (!result) {
        auto const& error = result.error();
        std::println("{} os={} preceding={} replaced={}", state::describe(error.stage), error.os.value(),
            error.preceding ? state::describe(*error.preceding) : "-", error.replaced);
        return 3;
    }
    check(result->has_value(), "snapshot exists");
    auto const& snapshot = **result;
    auto text = std::string_view(reinterpret_cast<char const*>(snapshot.payload.data()), snapshot.payload.size());
    std::println("{} {}", snapshot.header.revision, text);
    return 0;
}
