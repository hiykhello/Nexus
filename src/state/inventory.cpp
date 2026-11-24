module state.maintenance;
import std;
import functional;
import state.dns_cache;
import state.file;
import state.ruleset_storage;
import state.serde;
import state.snapshot;

namespace state {
    namespace {
        constexpr Magic fake_magic{'N','X','F','P','0','1'};

        auto begin(std::filesystem::path const& path,std::string_view version)
            -> std::pair<Inventory,std::optional<File>> {
            Inventory result{.version=version};
            if (path.empty()) return {Inventory{.version="-",.health="disabled"},std::optional<File>{}};
            auto directory=open_private_directory(path);
            if (!directory) {
                if (directory.error().os!=std::errc::no_such_file_or_directory) result.health="unreadable";
                return {result,std::optional<File>{}};
            }
            return {result,std::optional<File>(std::move(*directory))};
        }

        auto stat_files(NativeHandle directory,Inventory& info,functional::function_ref<bool(std::string_view)> match) -> bool {
            auto files=directory_entries(directory,match);
            if (!files) {info.health="unreadable";return false;}
            if (files->empty()) return false;
            info.health="ok";
            for (auto const& file:*files) {
                info.bytes+=file.size;
                if (!file.private_file) info.health="damaged";
            }
            return info.health=="ok";
        }

        auto read_number(NativeHandle directory,std::string_view name,std::uint64_t offset,std::size_t width,bool big=false)
            -> std::optional<std::uint64_t> {
            auto fd=open_dir_read(directory,name,true,Stage::open);
            if (!fd) return {};
            std::array<std::byte,8> bytes{};
            auto got=read_handle_at(fd->get(),offset,std::span(bytes).first(width),Stage::read);
            if (!got || *got!=width) return {};
            std::uint64_t result=0;
            for (std::size_t i=0;i<width;++i)
                result=(result<<8)|std::to_integer<unsigned>(bytes[big ? i : width-i-1]);
            return result;
        }

        auto dns_legacy(std::filesystem::path const& path,std::size_t servers) -> Inventory {
            auto [info,folder]=begin(path,"NXDNS2");
            if (!folder || !stat_files(folder->get(),info,[](auto name){return name=="messages.cache";})) return info;
            auto dir=folder->get();
            constexpr auto signature=[](std::string_view value) {
                std::uint64_t number=0;
                for (unsigned char ch:value) number=(number<<8)|ch;
                return number;
            };
            auto magic=read_number(dir,"messages.cache",0,6,true);
            if (magic==signature("NXDNS2")) {
                info.version="NXDNS2";
                auto policy=read_number(dir,"messages.cache",6,4,true);
                if (!policy || *policy>1024*1024 || servers>256) info.health="damaged";
                else {
                    auto count=read_number(dir,"messages.cache",18+*policy+servers*4,2,true);
                    if (!count || *count>256) info.health="damaged";
                    else {info.entries=*count;info.health="legacy";}
                }
            } else info.health="damaged";
            return info;
        }
    }

    auto inspect_selectors(std::filesystem::path const& path) -> Inventory {
        auto [info,folder]=begin(path,"NXST01");
        if (!folder || !stat_files(folder->get(),info,[](auto name){return name=="selectors.state";})) return info;
        auto snapshot=inspect_snapshot(folder->get(),{"selectors.state",".selectors.next",
            {.max_payload=8199,.fingerprint={std::byte{'S'},std::byte{'E'},std::byte{'L'}}},
            Magic{'N','X','S','E','L','1'}});
        if (!snapshot || !*snapshot || (**snapshot).payload.size()<7) {info.health="damaged";return info;}
        if ((**snapshot).legacy) info.version="NXSEL1";
        info.entries=std::to_integer<unsigned>((**snapshot).payload[6]);
        if (info.entries>16) info.health="damaged";
        return info;
    }

    auto inspect_fakeip(std::filesystem::path const& path,bool unified) -> Inventory {
        auto [info,folder]=begin(path,unified ? "NXFP01" : "legacy");
        if (!folder) return info;
        auto dir=folder->get();
        if (!unified) {
            stat_files(dir,info,[](auto name){return name=="history" || name=="highwater";});
            if (info.health=="ok") {
                auto magic=read_number(dir,"history",0,4,true);
                auto entries=read_number(dir,"history",20,4,true);
                if (magic==0x4e464801 && entries && *entries && *entries<=256) {
                    info.version="NFH1";
                    info.entries=*entries;
                    info.health="legacy";
                } else info.health="damaged";
            }
            return info;
        }
        if (!stat_files(dir,info,[](auto name) {
            return name=="fakeip.meta" || name=="fakeip.wal" || name=="fakeip.ckpt";
        })) return info;
        auto meta=inspect_snapshot(dir,{"fakeip.meta",".meta.next",
            {.magic=fake_magic,.tier=Tier::lease,.max_payload=4096}});
        if (!meta || !*meta || (**meta).payload.size()<74) {info.health="damaged";return info;}
        auto owner=std::span((**meta).payload).last(24).first(16);
        auto checkpoint=inspect_snapshot(dir,{"fakeip.ckpt",".ckpt.next",{.magic=fake_magic,
            .tier=Tier::lease,.max_payload=65536*267+4,.fingerprint=fingerprint(owner)}});
        if (!checkpoint) {info.health="damaged";return info;}
        if (*checkpoint) info.entries=(**checkpoint).header.revision;

        auto wal=open_dir_read(dir,"fakeip.wal",true,Stage::open);
        if (!wal) {if (wal.error().os!=std::errc::no_such_file_or_directory) info.health=wal.error().os==std::errc::permission_denied ? "damaged" : "unreadable";return info;}
        auto wal_sz=handle_size(wal->get(),Stage::read);
        if (!wal_sz) {info.health="unreadable";return info;}
        auto spec=EnvelopeSpec{.magic=fake_magic,.tier=Tier::lease,.max_payload=267,.fingerprint=fingerprint(owner)};
        for (std::uint64_t offset=0;offset+header_bytes<=*wal_sz;) {
            EncodedHeader header;
            auto got_h=read_handle_at(wal->get(),offset,header,Stage::read);
            if (!got_h || *got_h!=header.size()) {
                info.health="unreadable";break;
            }
            auto decoded=decode_header(header,spec);
            if (!decoded) {info.health="damaged";break;}
            offset+=header.size();
            if (offset+decoded->payload_bytes>*wal_sz) break;
            std::array<std::byte,267> bytes;
            auto payload=std::span(bytes).first(decoded->payload_bytes);
            auto got_p=read_handle_at(wal->get(),offset,payload,Stage::read);
            if (!got_p || *got_p!=payload.size() ||
                !verify_payload(header,*decoded,payload,spec.fingerprint)) {info.health="damaged";break;}
            info.entries=std::max(info.entries,decoded->revision);
            offset+=decoded->payload_bytes;
        }
        return info;
    }

    auto inspect_dns(std::filesystem::path const& root,std::filesystem::path const& legacy,std::size_t servers) -> Inventory {
        if (root.empty()) return dns_legacy(legacy,servers);
        auto [info,folder]=begin(root/"dns","NXDN03");
        if (!folder) return info;
        auto dir=folder->get();
        auto entries=directory_entries(dir,[](auto name){return dns_shard_fingerprint(name).has_value();});
        if (!entries) {info.health="unreadable";return info;}
        for (auto const& item:*entries) {
            info.bytes+=item.size;
            auto view=*dns_shard_fingerprint(item.name);
            auto data=inspect_snapshot(dir,{item.name,".inspect.next",{.magic=dns_cache_magic,.tier=Tier::cache,
                .max_payload=dns_shard_payload,.fingerprint=view}});
            if (!data || !*data || (**data).payload.size()<2) {info.health="damaged";continue;}
            Reader reader{(**data).payload};
            auto count=reader.number(2);
            if (count>256) {info.health="damaged";continue;}
            info.entries+=count;
            if (info.health=="missing") info.health="ok";
        }
        return info;
    }

    auto inspect_rules(std::filesystem::path const& root) -> Inventory {
        auto [info,folder]=begin(root.empty() ? root : root/"rulesets","NXRS01");
        if (!folder) return info;
        auto dir=folder->get();
        if (!stat_files(dir,info,[](auto name){return name=="index.state" || (name.size()==69 && name.ends_with(".blob"));}))
            return info;
        auto count=inspect_rulesets(dir);
        if (!count || !*count) info.health="damaged";
        else info.entries=**count;
        return info;
    }
}
