#include <pthread.h>
#include <sched.h>

#include "bounded_table.hpp"
import std;
import dns.cache;
import dns.message;
#include "snapshot_cache.hpp"

namespace d = dns;
using Clock = std::chrono::steady_clock;
using Nanoseconds = std::chrono::nanoseconds;

struct Measurements {
    std::size_t completed = 0;
    std::size_t hits = 0;
    std::uint64_t checksum = 0;
    std::vector<long long> service;
    std::vector<long long> lag;
};

auto parse_positive(std::string_view text, int maximum) -> int {
    int value = 0;
    auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size() || value <= 0 || value > maximum)
        throw std::invalid_argument("invalid numeric argument");
    return value;
}

auto parse_cpus(std::string_view text, std::size_t count) -> std::vector<int> {
    cpu_set_t available;
    if (sched_getaffinity(0, sizeof(available), &available) != 0)
        throw std::runtime_error("cannot read CPU affinity");
    std::vector<int> cpus;
    while (!text.empty()) {
        auto comma = text.find(',');
        auto part = text.substr(0, comma);
        int cpu = -1;
        auto [end, error] = std::from_chars(part.data(), part.data() + part.size(), cpu);
        if (error != std::errc{} || end != part.data() + part.size() || cpu < 0 || cpu >= CPU_SETSIZE ||
            !CPU_ISSET(cpu, &available) || std::ranges::find(cpus, cpu) != cpus.end())
            throw std::invalid_argument("invalid, unavailable or repeated CPU");
        cpus.push_back(cpu);
        if (comma == std::string_view::npos) break;
        text.remove_prefix(comma + 1);
        if (text.empty()) throw std::invalid_argument("empty CPU");
    }
    if (cpus.size() != count) throw std::invalid_argument("need one CPU per reader and one for the writer");
    return cpus;
}

void pin(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (pthread_setaffinity_np(pthread_self(), sizeof(set), &set) != 0) {
        std::cerr << "cannot pin thread to CPU " << cpu << '\n';
        std::abort();
    }
}

auto answer(d::CacheKey const& key, std::uint64_t revision) -> d::AddressAnswer {
    d::Address address{};
    address.size = 4;
    address.bytes[0] = static_cast<std::uint8_t>(revision);
    address.bytes[1] = static_cast<std::uint8_t>(~address.bytes[0]);
    return {key.name, {key.name}, {address}, 3600};
}

template<class F>
void generate(Clock::time_point start, std::size_t offered, Nanoseconds interval,
              std::size_t sample_every, Measurements& measurements, F&& operation) {
    measurements.service.reserve(offered / sample_every + 1);
    measurements.lag.reserve(offered / sample_every + 1);
    std::size_t slot = 0;
    while (slot < offered) {
        auto scheduled = start + interval * slot;
        auto now = Clock::now();
        while (now < scheduled) {
            std::this_thread::yield();
            now = Clock::now();
        }
        // Skip requests whose slot has already passed; never hide backlog by
        // silently issuing catch-up bursts. The output counts all skipped slots.
        auto late_slots = static_cast<std::size_t>((now - scheduled) / interval);
        slot += std::min(late_slots, offered - slot);
        if (slot == offered) break;
        scheduled = start + interval * slot;
        bool sample = slot % sample_every == 0;
        auto operation_start = Clock::now();
        measurements.checksum += operation(slot);
        auto finished = Clock::now();
        if (sample) {
            measurements.service.push_back(std::chrono::duration_cast<Nanoseconds>(finished - operation_start).count());
            measurements.lag.push_back(std::chrono::duration_cast<Nanoseconds>(operation_start - scheduled).count());
        }
        ++measurements.completed;
        ++slot;
    }
}

auto quantile(std::vector<long long>& values, double p) -> long long {
    if (values.empty()) return 0;
    std::sort(values.begin(), values.end());
    return values[static_cast<std::size_t>(p * (values.size() - 1))];
}

auto main(int argc, char** argv) -> int {
    if (argc != 8) {
        std::cerr << "usage: cache_offered_bench per-worker|shared|snapshot|ordered|module readers hot|uniform|churn "
                     "reads-per-reader-second writes-per-second seconds cpu-list\n";
        return 2;
    }
    try {
        std::string mode = argv[1], distribution = argv[3];
        int threads = parse_positive(argv[2], 16);
        int read_rate = parse_positive(argv[4], 1000000);
        int write_rate = parse_positive(argv[5], 1000000);
        int seconds = parse_positive(argv[6], 60);
        if ((mode != "per-worker" && mode != "shared" && mode != "snapshot" && mode != "ordered" && mode != "module") ||
            (distribution != "hot" && distribution != "uniform" && distribution != "churn")) throw std::invalid_argument("invalid mode or distribution");
        auto cpus = parse_cpus(argv[7], threads + 1);
        auto read_interval = Nanoseconds(1000000000LL / read_rate);
        auto write_interval = Nanoseconds(1000000000LL / write_rate);
        std::size_t offered_reads = static_cast<std::size_t>(seconds) * 1000000000LL / read_interval.count();
        std::size_t offered_writes = static_cast<std::size_t>(seconds) * 1000000000LL / write_interval.count();
        std::vector<d::CacheKey> keys;
        for (unsigned i = 0; i < (distribution == "churn" ? 512u : 256u); ++i)
            keys.push_back({1, "host-" + std::to_string(i) + ".example.test", 1});
        std::vector<std::unique_ptr<d::AddressCache>> local;
        std::unique_ptr<d::AddressCache> shared;
        std::unique_ptr<dns_hp_experiment::SnapshotCache> snapshot;
        std::unique_ptr<dns_hp_experiment::OrderedSnapshotCache> ordered;
        std::unique_ptr<d::AddressCache> module;
        if (mode == "per-worker") {
            for (int i = 0; i < threads; ++i) local.push_back(std::make_unique<d::AddressCache>(256));
        } else if (mode == "shared") shared = std::make_unique<d::AddressCache>(256, 0, true);
        else if (mode == "snapshot") snapshot = std::make_unique<dns_hp_experiment::SnapshotCache>(256, 0, threads);
        else if (mode=="ordered") ordered = std::make_unique<dns_hp_experiment::OrderedSnapshotCache>(256, 0, threads);
        else module = std::make_unique<d::AddressCache>(256,0,true,threads);

        auto publish_one = [&](auto& cache, d::CacheKey const& key, std::uint64_t revision) {
            auto token = cache.begin_query(key);
            return token && cache.publish(key, answer(key, revision), 1000, *token).has_value();
        };
        auto publish = [&](d::CacheKey const& key, std::uint64_t revision) {
            if (shared) return publish_one(*shared, key, revision);
            if (snapshot) return publish_one(*snapshot, key, revision);
            if (ordered) return publish_one(*ordered, key, revision);
            if (module) return publish_one(*module, key, revision);
            for (auto& cache : local) if (!publish_one(*cache, key, revision)) return false;
            return true;
        };
        for (std::size_t i = 0; i < 256; ++i) if (!publish(keys[i], 1)) std::abort();

        Clock::time_point start;
        std::barrier gate(threads + 2, [&]() noexcept { start = Clock::now() + std::chrono::milliseconds(100); });
        std::vector<Measurements> reads(threads);
        Measurements writes;
        std::vector<std::thread> readers;
        for (int t = 0; t < threads; ++t) readers.emplace_back([&, t] {
            pin(cpus[t]);
            std::optional<dns_hp_experiment::SnapshotCache::Reader> reader;
            std::optional<dns_hp_experiment::OrderedSnapshotCache::Reader> ordered_reader;
            std::optional<d::AddressCache::Reader> module_reader;
            if (snapshot) reader.emplace(snapshot->reader(t));
            if (ordered) ordered_reader.emplace(ordered->reader(t));
            if (module) module_reader.emplace(module->reader(t));
            std::uint64_t rng = 0x9e3779b97f4a7c15ULL + t;
            gate.arrive_and_wait();
            generate(start, offered_reads, read_interval, 100, reads[t], [&](std::size_t) {
                rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
                auto const& key = keys[distribution == "hot" ? 0 : rng % keys.size()];
                auto result = shared ? shared->lookup(key, 1000) : snapshot ? snapshot->lookup(key, 1000, *reader) :
                    ordered ? ordered->lookup(key, 1000, *ordered_reader) : module ? module->lookup(key,1000,*module_reader) : local[t]->lookup(key, 1000);
                if (!result) std::abort();
                if (!*result) {
                    if (distribution != "churn") std::abort();
                    return std::size_t{0};
                }
                if ((**result).canonical_name != key.name || (**result).addresses.size() != 1 ||
                    (**result).addresses[0].bytes[1] != static_cast<std::uint8_t>(~(**result).addresses[0].bytes[0])) std::abort();
                ++reads[t].hits;
                return (**result).canonical_name.size();
            });
        });
        std::thread writer([&] {
            pin(cpus[threads]);
            gate.arrive_and_wait();
            generate(start, offered_writes, write_interval, 1, writes, [&](std::size_t slot) {
                auto const& key = keys[distribution == "hot" ? 0 : slot % keys.size()];
                if (!publish(key, slot + 2)) std::abort();
                return std::uint64_t{1};
            });
        });
        gate.arrive_and_wait();
        for (auto& thread : readers) thread.join();
        writer.join();

        Measurements total;
        for (auto& item : reads) {
            total.completed += item.completed; total.hits += item.hits; total.checksum += item.checksum;
            total.service.insert(total.service.end(), item.service.begin(), item.service.end());
            total.lag.insert(total.lag.end(), item.lag.begin(), item.lag.end());
        }
        auto read_offered = offered_reads * threads;
        std::cout << mode << ',' << threads << ',' << distribution << ',' << read_rate << ',' << write_rate << ',' << seconds << ','
                  << read_offered << ',' << total.completed << ',' << read_offered - total.completed << ','
                  << quantile(total.service, .5) << ',' << quantile(total.service, .99) << ',' << quantile(total.service, .999) << ','
                  << quantile(total.lag, .99) << ',' << quantile(total.lag, .999) << ','
                  << offered_writes << ',' << writes.completed << ',' << offered_writes - writes.completed << ','
                  << quantile(writes.service, .5) << ',' << quantile(writes.service, .99) << ',' << quantile(writes.service, .999) << ','
                  << quantile(writes.lag, .99) << ',' << quantile(writes.lag, .999) << ',' << total.checksum << ','
                  << total.hits << ',' << total.completed-total.hits << '\n';
    } catch (std::exception const& error) {
        std::cerr << error.what() << '\n';
        return 2;
    }
}
