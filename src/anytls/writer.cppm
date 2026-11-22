export module anytls.writer;
import std;
import anytls;
import anytls.auth;
import anytls.settings;
import anytls.padding;
import crypto;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

export namespace anytls {
    using IoClock=std::chrono::steady_clock;
    using Deadline=std::optional<IoClock::time_point>;
    // One writer serializes control and data, preserving the first session
    // record's settings+SYN+address grouping. After Upgrade/TLS composition,
    // Stream still supplies only complete send and cancellation.
    template<class Stream>
    class Writer {
        Stream& stream_;
        PaddingScheme& scheme_;
        nex::capy::async_mutex mutex_;
        std::vector<std::uint8_t> settings_;
        std::uint32_t packet_=0;
        bool client_,failed_=false,authenticated_=false,pending_settings_=false,padding_=true;
        struct Guard { Writer& owner; bool done=false; ~Guard() { if (!done) owner.cancel(); } };
        auto expired(Deadline deadline) const noexcept -> bool { return deadline && IoClock::now()>=*deadline; }
        auto fail() noexcept -> bool { cancel(); return false; }
        auto write(std::span<std::uint8_t const> bytes,Deadline deadline) -> nex::capy::task<bool> {
            if (failed_ || expired(deadline)) co_return fail();
            if (!client_ || !padding_) {
                if (!co_await stream_.send(bytes,deadline) || expired(deadline)) co_return fail();
                co_return true;
            }
            ++packet_;
            if (packet_>=scheme_.stop()) {
                padding_=false;
                if (!co_await stream_.send(bytes,deadline) || expired(deadline)) co_return fail();
                co_return true;
            }
            // A padding update can arrive while a send is suspended. Retain
            // this write's bounded plan, never a span into mutable settings.
            std::inplace_vector<PaddingStep,256> plan;
            for (auto step:scheme_.steps(packet_)) plan.push_back(step);
            for (auto step:plan) {
                if (step.check) { if (bytes.empty()) co_return true; continue; }
                auto size=random_padding(step);
                if (!size) co_return fail();
                if (bytes.size()>*size) {
                    if (!co_await stream_.send(bytes.first(*size),deadline)) co_return fail();
                    bytes=bytes.subspan(*size);
                } else {
                    auto packet=pad_packet(bytes,*size);
                    if (!packet || !co_await stream_.send(*packet,deadline)) co_return fail();
                    bytes={};
                }
                if (failed_ || expired(deadline)) co_return fail();
            }
            if (!bytes.empty() && (!co_await stream_.send(bytes,deadline) || expired(deadline))) co_return fail();
            co_return !failed_;
        }
    public:
        Writer(Stream& stream,PaddingScheme& scheme,bool client) : stream_(stream),scheme_(scheme),client_(client) {}
        Writer(Writer const&)=delete;
        auto operator=(Writer const&) -> Writer& = delete;
        auto cancel() noexcept -> void { failed_=true; stream_.cancel(); }
        auto start(std::span<std::uint8_t const> key,std::string_view metadata,IoClock::time_point deadline) -> nex::capy::task<bool> {
            Guard operation_guard{*this};
            if (!client_ || authenticated_ || failed_) co_return false;
            auto [error,guard]=co_await nex::corosio::timeout(mutex_.scoped_lock(),deadline);
            if (error || failed_ || IoClock::now()>=deadline) co_return fail();
            std::size_t padding=0;
            auto steps=scheme_.steps(0);
            if (!steps.empty() && !steps.front().check) {
                auto size=random_padding(steps.front());
                if (!size || *size>65535) co_return fail();
                padding=*size;
            }
            auto request=encode_authentication(key,padding);
            if (!request) co_return fail();
            struct Erase { std::vector<std::uint8_t>& bytes; ~Erase() { crypto::cleanse(bytes); } } erase{*request};
            auto fingerprint=padding_fingerprint(scheme_);
            if (!fingerprint) co_return fail();
            auto settings=encode_client_settings(*fingerprint,metadata);
            if (!settings) co_return fail();
            auto frame=encode_frame(Command::settings,0,*settings);
            if (!frame || !co_await stream_.send(*request,deadline) || failed_ || IoClock::now()>=deadline) co_return fail();
            settings_=std::move(*frame); pending_settings_=true; authenticated_=true; operation_guard.done=true; co_return true;
        }
        auto open(std::uint32_t id,Address const& address,IoClock::time_point deadline) -> nex::capy::task<bool> {
            Guard operation_guard{*this};
            if (!client_ || !authenticated_ || !id || !net::valid_proxy_address(address)) co_return false;
            auto [error,guard]=co_await nex::corosio::timeout(mutex_.scoped_lock(),deadline);
            if (error || failed_ || IoClock::now()>=deadline) co_return fail();
            std::vector<std::uint8_t> destination;
            if (!net::append_proxy_address(destination,address,net::AddressWire::socks)) co_return fail();
            auto address_frame=encode_frame(Command::push,id,destination);
            if (!address_frame) co_return fail();
            auto syn=encode_frame(Command::syn,id);
            if (!syn) co_return fail();
            if (pending_settings_) {
                settings_.insert(settings_.end(),syn->begin(),syn->end());
                settings_.insert(settings_.end(),address_frame->begin(),address_frame->end());
                if (!co_await write(settings_,deadline)) co_return false;
                settings_.clear(); pending_settings_=false;
            } else if (!co_await write(*syn,deadline) || !co_await write(*address_frame,deadline)) co_return false;
            operation_guard.done=true; co_return true;
        }
        auto frame(Command command,std::uint32_t id,std::span<std::uint8_t const> payload={},Deadline deadline={}) -> nex::capy::task<bool> {
            Guard operation_guard{*this};
            if (client_ && (!authenticated_ || pending_settings_)) co_return false;
            auto operation=mutex_.scoped_lock();
            auto [error,guard]=deadline ? co_await nex::corosio::timeout(std::move(operation),*deadline) : co_await std::move(operation);
            if (error || failed_ || expired(deadline)) co_return fail();
            auto encoded=encode_frame(command,id,payload);
            if (!encoded) co_return false;
            auto sent=co_await write(*encoded,deadline);
            operation_guard.done=sent; co_return sent;
        }
        auto data(std::uint32_t id,std::span<std::uint8_t const> input,Deadline deadline={}) -> nex::capy::task<bool> {
            Guard operation_guard{*this};
            if (!id || (client_ && (!authenticated_ || pending_settings_))) co_return false;
            auto operation=mutex_.scoped_lock();
            auto [error,guard]=deadline ? co_await nex::corosio::timeout(std::move(operation),*deadline) : co_await std::move(operation);
            if (error || failed_ || expired(deadline)) co_return fail();
            while (!input.empty()) {
                auto amount=std::min(input.size(),max_payload);
                auto encoded=encode_frame(Command::push,id,input.first(amount));
                if (!encoded || !co_await write(*encoded,deadline)) co_return false;
                input=input.subspan(amount);
            }
            operation_guard.done=true; co_return true;
        }
    };
}
