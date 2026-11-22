module;
#include <cerrno>
#include <unistd.h>
#include <sys/stat.h>
module state.fakeip_disk;
import std;
import state.serde;
import state.snapshot;
import state.fakeip;
import state.file;

namespace state {
    namespace {
        constexpr Magic magic{'N','X','F','P','0','1'};
        constexpr std::size_t max_record=4+8+2+253;
        constexpr std::size_t max_rows=65536;

        auto identity(FakeIpMeta const& meta) noexcept -> Fingerprint {
            return fingerprint(meta.owner);
        }

        auto encode_row(Bytes& bytes, FakeIpRow const& row) -> void {
            append_le(bytes,row.address,4);
            append_le(bytes,row.view,8);
            append_le(bytes,row.domain.size(),2);
            bytes.append_range(std::as_bytes(std::span(row.domain)));
        }

        auto decode_row(Reader& input) -> std::optional<FakeIpRow> {
            auto addr=static_cast<std::uint32_t>(input.number(4));
            auto view=input.number(8);
            auto text=input.take(input.number(2));
            if (text.empty() || input.invalid) return {};
            auto domain=std::string_view(reinterpret_cast<char const*>(text.data()),text.size());
            if (!valid_fakeip_name(domain)) return {};
            return FakeIpRow{addr,view,std::string(domain)};
        }

        auto checkpoint(FakeIpMeta const& meta) -> SnapshotSpec {
            return {"fakeip.ckpt",".ckpt.next",
                {.magic=magic,.tier=Tier::lease,.max_payload=max_rows*max_record+4,.fingerprint=identity(meta)}};
        }

        auto read_wal(int wal) -> std::expected<Bytes,StateError> {
            struct stat info{};
            if (::fstat(wal,&info)<0) return failure(Stage::read,errno);
            if (info.st_size>static_cast<off_t>(fakeip_wal_limit+128*(max_record+header_bytes)))
                return std::unexpected(StateError{Stage::capacity});
            Bytes bytes(static_cast<std::size_t>(info.st_size));
            auto rest=std::span(bytes);
            while (!rest.empty()) {
                auto count=::read(wal,rest.data(),rest.size());
                if (count<0 && errno==EINTR) continue;
                if (count<=0) return failure(Stage::read,count<0 ? errno : EIO);
                rest=rest.subspan(static_cast<std::size_t>(count));
            }
            return bytes;
        }
    }

    auto replay_fakeip(InstanceLock const& directory, FakeIpScope const& scope, FakeIpMeta const& meta, int wal)
        -> std::expected<FakeIpReplay,StateError> {
        auto saved=load_snapshot(directory,checkpoint(meta));
        if (!saved) return std::unexpected(saved.error());
        FakeIpReplay result;
        std::set<std::pair<std::uint64_t,std::string_view>> keys;
        // Reserve at most the pool's capacity so recorded string views stay valid.
        result.rows.reserve(std::uint64_t(scope.alloc_last)-scope.alloc_first+1);
        auto add=[&](FakeIpRow row) {
            if (row.address<scope.alloc_first || row.address>scope.alloc_last ||
                (!result.rows.empty() && row.address<=result.rows.back().address) ||
                std::ranges::any_of(scope.exclude_cidrs,[&](auto range) {
                    return row.address>=range.first && row.address<=range.second;
                })) return false;
            result.rows.push_back(std::move(row));
            auto const& added=result.rows.back();
            return keys.emplace(added.view,added.domain).second;
        };
        auto invalid=std::unexpected(StateError{Stage::format});
        if (*saved) {
            Reader input{(**saved).payload};
            auto count=input.number(4);
            if (!count || count>result.rows.capacity() || count!=(**saved).header.revision) return invalid;
            for (std::uint64_t i=0;i<count;++i) {
                auto row=decode_row(input);
                if (!row || !add(std::move(*row))) return invalid;
            }
            if (!input.complete()) return invalid;
        }
        auto bytes=read_wal(wal);
        if (!bytes) return std::unexpected(bytes.error());
        auto rest=std::span<std::byte const>(*bytes);
        auto spec=EnvelopeSpec{.magic=magic,.tier=Tier::lease,.max_payload=max_record,.fingerprint=identity(meta)};
        std::optional<std::uint64_t> previous;
        while (rest.size()>=header_bytes) {
            auto prefix=rest.first(header_bytes);
            auto header=decode_header(prefix,spec);
            if (!header) return std::unexpected(header.error());
            if (header->payload_bytes>rest.size()-header_bytes) break;
            auto payload=rest.subspan(header_bytes,header->payload_bytes);
            auto verified=verify_payload(prefix,*header,payload,spec.fingerprint);
            if (!verified) return std::unexpected(verified.error());
            Reader input{payload};
            auto row=decode_row(input);
            auto sequence=header->revision;
            if (!row || !input.complete() || header->clear_epoch || !sequence ||
                (previous && sequence!=*previous+1)) return invalid;
            if (sequence<=result.rows.size()) {
                auto const& old=result.rows[sequence-1];
                if (old.address!=row->address || old.view!=row->view || old.domain!=row->domain) return invalid;
            } else if (sequence!=result.rows.size()+1 || !add(std::move(*row))) return invalid;
            previous=sequence;
            auto consumed=header_bytes+payload.size();
            result.wal_bytes+=consumed;
            rest=rest.subspan(consumed);
        }
        if (!rest.empty() && (::ftruncate(wal,static_cast<off_t>(result.wal_bytes))<0 || sync_file(wal)<0))
            return failure(Stage::sync_stage,errno);
        return result;
    }

    auto append_fakeip(int wal, FakeIpMeta const& meta, std::uint64_t sequence, FakeIpRow const& row)
        -> std::expected<std::size_t,StateError> {
        Bytes payload;
        encode_row(payload,row);
        auto prefix=encode_header({magic,1,Tier::lease,0,static_cast<std::uint32_t>(payload.size()),sequence,0},
                                  payload,identity(meta));
        if (!prefix) return std::unexpected(prefix.error());
        for (auto bytes:{std::span<std::byte const>(*prefix),std::span<std::byte const>(payload)}) {
            while (!bytes.empty()) {
                auto count=::write(wal,bytes.data(),bytes.size());
                if (count<0 && errno==EINTR) continue;
                if (count<=0) return failure(Stage::write,count<0 ? errno : EIO);
                bytes=bytes.subspan(static_cast<std::size_t>(count));
            }
        }
        return header_bytes+payload.size();
    }

    auto compact_fakeip(InstanceLock const& directory, FakeIpMeta const& meta, int wal,
                        std::span<FakeIpRow const> rows) -> std::expected<void,StateError> {
        Bytes payload;
        append_le(payload,rows.size(),4);
        for (auto const& row:rows) encode_row(payload,row);
        auto result=commit_snapshot(directory,checkpoint(meta),rows.size(),0,payload);
        if (!result) {
            // A crash can leave the complete WAL after a durable checkpoint.
            if (result.error().stage!=Stage::revision) return std::unexpected(result.error());
        } else if (result->error) return std::unexpected(*result->error);
        if (::ftruncate(wal,0)<0 || sync_file(wal)<0) return failure(Stage::sync_stage,errno);
        return {};
    }
}
