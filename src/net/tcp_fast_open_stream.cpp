module net.tcp_fast_open_stream;
import std;
import net.tcp_fast_open;
import net.socket_stream;
import platform.socket_options;
import capy;
import corosio;

namespace net {
auto FastOpenStream::fail(std::error_code error) noexcept -> void {
    if(state_!=State::failed) {error_=error ? error : std::make_error_code(std::errc::io_error);state_=State::failed;}
    socket_.cancel();connected_.set();
}

auto FastOpenStream::connect(std::span<std::uint8_t const> first,StreamDeadline deadline)
    -> capy::task<std::expected<std::size_t,std::error_code>> {
    auto until=deadline ? std::min(*deadline,connect_deadline_) : connect_deadline_;
    auto stop=co_await capy::this_coro::stop_token;
    if(stop.stop_requested()) {fail(std::make_error_code(std::errc::operation_canceled));co_return std::unexpected(error_);}
    if(deadline && Clock::now()>=*deadline) {fail(std::make_error_code(std::errc::timed_out));co_return std::unexpected(error_);}
    if(state_==State::ready)co_return std::size_t{};
    if(state_==State::failed)co_return std::unexpected(error_);
    if(Clock::now()>=until) {fail(std::make_error_code(std::errc::timed_out));co_return std::unexpected(error_);}
    if(state_==State::connecting) {
        auto [error]=co_await corosio::timeout(connected_.wait(),until);
        if(error || Clock::now()>=until) {
            fail(capy::is_timeout(error) || Clock::now()>=until ? std::make_error_code(std::errc::timed_out) : error);
            co_return std::unexpected(error_);
        }
        if(state_!=State::ready)co_return std::unexpected(error_);
        co_return std::size_t{};
    }
    state_=State::connecting;
    struct Guard {FastOpenStream& owner;bool done=false;~Guard(){if(!done)owner.fail(std::make_error_code(std::errc::operation_canceled));}} guard{*this};
    auto result=co_await tcp_fast_open_candidates(socket_,std::span(endpoints_),
        [](auto const&,auto const& endpoint){
            auto address=endpoint.address();if(!endpoint.port() || address.is_unspecified())return false;
            if(!address.is_v6())return true;
            auto bytes=address.to_v6().to_bytes();
            bool mapped=std::ranges::all_of(std::span(bytes).first(10),[](auto byte){return byte==0;}) && bytes[10]==255 && bytes[11]==255;
            return !mapped || std::ranges::any_of(std::span(bytes).last(4),[](auto byte){return byte!=0;});
        },first,until,options_);
    if(state_==State::failed) {guard.done=true;co_return std::unexpected(error_);}
    if(result.result.error) {fail(result.result.error);guard.done=true;co_return std::unexpected(error_);}
    // A native Fast Open send can bypass Corosio's connect bookkeeping.
    // Retain the selected destination in the now-unused candidate list.
    endpoints_.resize(1);
    endpoints_.front()=result.endpoint;
    interface_index_=result.interface_index;
    state_=State::ready;connected_.set();guard.done=true;co_return result.result.accepted;
}

FastOpenStream::FastOpenStream(corosio::io_context& context,std::vector<corosio::endpoint> endpoints,
    Clock::time_point deadline,platform::TcpSocketOptions options)
    :socket_(context),endpoints_(std::move(endpoints)),options_(std::move(options)),connect_deadline_(deadline) {}

auto FastOpenStream::cancel() noexcept -> void {fail(std::make_error_code(std::errc::operation_canceled));}

auto FastOpenStream::read(std::span<std::uint8_t> output,StreamDeadline deadline)
    -> capy::task<std::expected<std::size_t,std::error_code>> {
    if(reading_)co_return std::unexpected(std::make_error_code(std::errc::operation_in_progress));
    if(state_==State::failed)co_return std::unexpected(error_);
    if(output.empty())co_return std::size_t{};
    reading_=true;
    struct Guard {FastOpenStream& owner;bool done=false;~Guard(){owner.reading_=false;if(!done)owner.fail(std::make_error_code(std::errc::operation_canceled));}} guard{*this};
    auto ready=co_await connect({},deadline);if(!ready)co_return std::unexpected(ready.error());
    auto operation=socket_.read_some(capy::mutable_buffer(output.data(),output.size()));
    auto [error,size]=deadline ? co_await corosio::timeout(std::move(operation),*deadline) : co_await std::move(operation);
    if(state_==State::failed)co_return std::unexpected(error_);
    if(capy::is_eof(error) && (!deadline || Clock::now()<*deadline)){guard.done=true;co_return std::size_t{};}
    if(error || (deadline && Clock::now()>=*deadline) || size>output.size()) {
        fail(deadline && Clock::now()>=*deadline ? std::make_error_code(std::errc::timed_out) : error ? error : std::make_error_code(std::errc::protocol_error));
        co_return std::unexpected(error_);
    }
    guard.done=true;co_return size;
}

auto FastOpenStream::send(std::span<std::uint8_t const> input,StreamDeadline deadline) -> capy::task<bool> {
    if(writing_ || output_closed_ || state_==State::failed)co_return false;
    writing_=true;
    struct Guard {FastOpenStream& owner;bool done=false;~Guard(){owner.writing_=false;if(!done)owner.fail(std::make_error_code(std::errc::operation_canceled));}} guard{*this};
    auto ready=co_await connect(input,deadline);if(!ready)co_return false;
    if(*ready>input.size()){fail(std::make_error_code(std::errc::protocol_error));co_return false;}
    input=input.subspan(*ready);
    while(!input.empty()) {
        if(deadline && Clock::now()>=*deadline){fail(std::make_error_code(std::errc::timed_out));co_return false;}
        auto operation=socket_.write_some(capy::const_buffer(input.data(),input.size()));
        auto [error,size]=deadline ? co_await corosio::timeout(std::move(operation),*deadline) : co_await std::move(operation);
        if(state_==State::failed)co_return false;
        if(error || !size || size>input.size() || (deadline && Clock::now()>=*deadline)) {
            fail(deadline && Clock::now()>=*deadline ? std::make_error_code(std::errc::timed_out) : error ? error : std::make_error_code(std::errc::io_error));co_return false;
        }
        input=input.subspan(size);
    }
    guard.done=true;co_return true;
}

auto FastOpenStream::close_output(StreamDeadline deadline) -> capy::task<bool> {
    if(writing_ || state_==State::failed)co_return false;
    if(output_closed_)co_return true;
    writing_=true;
    struct Guard {FastOpenStream& owner;bool done=false;~Guard(){owner.writing_=false;if(!done)owner.fail(std::make_error_code(std::errc::operation_canceled));}} guard{*this};
    auto ready=co_await connect({},deadline);if(!ready)co_return false;
    if(auto error=socket_.shutdown(corosio::shutdown_send)) {fail(error);co_return false;}
    output_closed_=true;guard.done=true;co_return true;
}
}
