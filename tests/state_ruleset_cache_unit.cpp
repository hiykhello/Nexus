#include <stdlib.h>
#include <unistd.h>
import std;
import state;

namespace {
    namespace fs = std::filesystem;
    using state::RuleFormat;
    using state::RulesetCache;
    using state::RulesetKey;

    auto require(bool condition, std::string_view message) -> void {
        if (!condition) {
            std::cerr << "FAIL " << message << '\n';
            std::exit(1);
        }
    }

    struct Temp {
        fs::path path;
        Temp() {
            char temp[] = "/tmp/nexus-ruleset-cache.XXXXXX";
            auto result = ::mkdtemp(temp);
            require(result!=nullptr, "create cache fixture");
            path=result;
        }
        ~Temp() {
            std::error_code ignored;
            fs::remove_all(path, ignored);
        }
    };

    auto metadata() -> state::RulesetMetadata {
        return {.etag="\"one\"", .last_modified="Sat, 07 Mar 2026 00:00:00 GMT",
                .response_target="/rules", .fetched_at=1, .expires_at=100};
    }

    auto put(RulesetCache const& cache, RulesetKey const& key, std::string_view body) -> void {
        auto hit=cache.lookup(key);
        require(hit.has_value(), "obtain epoch before write");
        auto stored=cache.store(key,hit->clear_epoch,metadata(),body);
        if (!stored) std::cerr << state::describe(stored.error().stage) << " " << stored.error().os.message() << '\n';
        require(stored.has_value(), "store with current epoch");
    }

    auto body(RulesetCache const& cache, RulesetKey const& key) -> std::optional<std::string> {
        auto result=cache.lookup(key);
        if (!result) std::cerr << state::describe(result.error().stage) << " " << result.error().os.message() << '\n';
        require(result.has_value(), "lookup succeeds");
        if (!result->hit) return {};
        require(result->hit->metadata.size_bytes==result->hit->body.size(), "size metadata matches");
        require(result->hit->metadata.etag=="\"one\"" && result->hit->metadata.last_modified==metadata().last_modified,
                "read validators");
        return std::move(result->hit->body);
    }

    auto blobs(fs::path const& path) -> std::vector<fs::path> {
        std::vector<fs::path> result;
        for (auto const& entry : fs::directory_iterator(path))
            if (entry.path().extension()==".blob") result.push_back(entry.path());
        return result;
    }

    auto formats_and_budget() -> void {
        Temp directory;
        RulesetCache cache(directory.path, {.max_bytes=8,.max_entries=3});
        auto kdl=RulesetKey{"https://test/rules",RuleFormat::kdl,1};
        auto beve=kdl;
        beve.format=RuleFormat::beve;
        auto srs=kdl;
        srs.format=RuleFormat::srs;
        auto future=kdl;
        future.parser_version=2;
        put(cache,kdl,"abcd");
        require(body(cache,kdl)=="abcd" && !body(cache,beve) && !body(cache,srs) && !body(cache,future),
                "same URL never crosses format or parser versions");
        put(cache,beve,"abcd");
        auto path=directory.path/"rulesets";
        require(blobs(path).size()==1, "identical bytes share blob");
        put(cache,srs,"efgh");
        require(blobs(path).size()==2, "two digests within byte budget");
        put(cache,future,"ijkl");
        require(!body(cache,kdl) && !body(cache,beve) && body(cache,srs)=="efgh" &&
                body(cache,future)=="ijkl" && blobs(path).size()==2, "eviction removes unreferenced blobs");
        for (auto const& blob : blobs(path))
            require(fs::status(blob).permissions()==(fs::perms::owner_read|fs::perms::owner_write) &&
                    blob.filename().string().size()==69, "private content-addressed blob");
        auto another=RulesetKey{"https://test/other",RuleFormat::kdl,1};
        auto fourth=RulesetKey{"https://test/fourth",RuleFormat::kdl,1};
        put(cache,another,"ijkl");
        put(cache,fourth,"ijkl");
        require(!body(cache,srs) && blobs(path).size()==1, "entry count is bounded independently of blob bytes");
        auto old=cache.lookup(future);
        require(old && old->hit, "capture epoch for in-flight request");
        std::ofstream(directory.path/"selectors.state").put('a');
        require(cache.clear().has_value() && fs::exists(directory.path/"selectors.state") && blobs(path).empty(),
                "clear only ruleset tier");
        auto stale=cache.store(future,old->clear_epoch,metadata(),"later");
        require(!stale && stale.error().stage==state::Stage::stale_epoch && !body(cache,future),
                "in-flight pre-clear downloads cannot resurrect cache");
    }

    auto recovery() -> void {
        Temp directory;
        RulesetCache cache(directory.path);
        auto key=RulesetKey{"https://test/rules",RuleFormat::kdl,1};
        put(cache,key,"valid");
        auto path=directory.path/"rulesets";
        auto before=cache.lookup(key);
        require(before && before->hit, "prime cached body");
        auto blob=blobs(path).front();
        std::ofstream(blob).write("wrong",5);
        fs::permissions(path, fs::perms::owner_read|fs::perms::owner_exec);
        auto denied=cache.lookup(key);
        fs::permissions(path, fs::perms::owner_all);
        require(!denied && denied.error().stage==state::Stage::remove_blob &&
                denied.error().os==std::errc::permission_denied &&
                denied.error().preceding==state::Stage::checksum, "preserve actual EACCES on corrupt blob deletion");
        require(!body(cache,key) && !fs::exists(blob), "repair corrupt blob as cold miss");
        put(cache,key,"valid");
        auto index=path/"index.state";
        {
            std::fstream file(index,std::ios::binary|std::ios::in|std::ios::out);
            file.seekp(32);
            file.put(static_cast<char>(before->hit->body.size()));
            // Truncation guarantees damage even if the overwritten byte matched.
        }
        fs::resize_file(index,32);
        fs::permissions(path, fs::perms::owner_read|fs::perms::owner_exec);
        auto bad_index=cache.lookup(key);
        fs::permissions(path, fs::perms::owner_all);
        require(!bad_index && bad_index.error().stage==state::Stage::remove_index &&
                bad_index.error().os==std::errc::permission_denied, "report EACCES deleting damaged index");
        auto repaired=cache.lookup(key);
        require(repaired && !repaired->hit && repaired->clear_epoch!=before->clear_epoch &&
                blobs(path).empty(), "damaged index restarts with a new epoch, sweeps orphaned blobs");
        auto orphan=path/(std::string(64,'e')+".blob");
        std::ofstream(orphan).put('o');
        require(!body(cache,key) && !fs::exists(orphan),"unindexed files from interrupted writes are reclaimed");
    }
}

auto main() -> int {
    require(::geteuid()!=0, "permission fixture requires a non-root UID");
    formats_and_budget();
    std::println("PASS format/version isolation, dedup, byte/count eviction, orphan cleanup and clear epoch");
    recovery();
    std::println("PASS corruption recovery, real EACCES on blob/index unlink, authority isolation");
}
