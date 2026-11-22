module vision;
import std;
namespace vision {
    auto complete_application_records(std::span<std::uint8_t const> bytes) noexcept -> bool {
        std::size_t pos=0;
        while (pos<bytes.size()) {
            if (bytes.size()-pos<5 || bytes[pos]!=0x17 || bytes[pos+1]!=3 || bytes[pos+2]!=3) return false;
            auto length=(std::size_t{bytes[pos+3]}<<8)|bytes[pos+4]; pos+=5;
            if (!length || length>bytes.size()-pos) return false;
            pos+=length;
        }
        return true;
    }
    auto TrafficFilter::observe(std::span<std::uint8_t const> bytes) noexcept -> void {
        if (remaining_<=0) return;
        --remaining_;
        if (bytes.size()>=6) {
            if (bytes[0]==0x16 && bytes[1]==3 && bytes[2]==3 && bytes[5]==2) {
                server_remaining_=(std::int32_t{bytes[3]}<<8)+bytes[4]+5;
                tls_=tls12_=true;
                if (bytes.size()>=79 && server_remaining_>=79) {
                    auto offset=std::size_t{44}+bytes[43];
                    if (offset+2<=bytes.size() && offset+2<=static_cast<std::size_t>(server_remaining_))
                        cipher_=(std::uint16_t{bytes[offset]}<<8)|bytes[offset+1];
                }
            } else if (bytes[0]==0x16 && bytes[1]==3 && bytes[5]==1) tls_=true;
        }
        if (server_remaining_>0) {
            constexpr std::array<std::uint8_t,6> version{0,0x2b,0,2,3,4};
            auto length=std::min(bytes.size(),static_cast<std::size_t>(server_remaining_));
            server_remaining_-=static_cast<std::int32_t>(length);
            if (std::ranges::search(bytes.first(length),version).begin()!=bytes.first(length).end()) {
                direct_=cipher_>=0x1301 && cipher_<=0x1304; remaining_=0;
            } else if (server_remaining_==0) remaining_=0;
        }
    }
    auto Sender::random_bound(TrafficFilter const& filter,std::size_t size,bool initial) const noexcept -> std::size_t {
        if (state_!=SendStatus::padding || size>8171 || (initial && (!first_ || size))) return 0;
        return (initial || filter.is_tls()) && size<900 ? 500 : 256;
    }
    auto Sender::plan_large(TrafficFilter const& filter,std::span<std::uint8_t const> bytes) const noexcept -> std::expected<LargePlan,SendError> {
        if (state_==SendStatus::pending || state_==SendStatus::failed) return std::unexpected(SendError::invalid_state);
        if (bytes.size()<8171 || bytes.size()>8192) return std::unexpected(SendError::invalid_size);
        std::size_t split=0;
        for (std::size_t i=0;i+3<=bytes.size();++i)
            if (bytes[i]==0x17 && bytes[i+1]==3 && bytes[i+2]==3) split=i;
        if (split<21 || split>8171) split=4096;
        LargePlan plan{split,{0,0}};
        if (state_!=SendStatus::padding) return plan;
        auto switching=filter.is_tls() && bytes.size()>=6 && complete_application_records(bytes);
        auto ending=!switching && !filter.tls12_or_later() && filter.remaining()<=1;
        plan.random_bounds[0]=filter.is_tls() && split<900 ? 500 : 256;
        auto second=bytes.subspan(split);
        auto second_record=switching && second.size()>=6 && second[0]==0x17 && second[1]==3 && second[2]==3;
        if (!ending) plan.random_bounds[1]=filter.is_tls() && (!switching || second_record) && second.size()<900 ? 500 : 256;
        return plan;
    }
    auto Sender::prepare_large(TrafficFilter const& filter,std::span<std::uint8_t const> bytes,std::array<std::size_t,2> random)
        -> std::expected<SendBlock,SendError> {
        auto plan=plan_large(filter,bytes); if (!plan) return std::unexpected(plan.error());
        for (std::size_t i=0;i<2;++i)
            if ((plan->random_bounds[i] && random[i]>=plan->random_bounds[i]) || (!plan->random_bounds[i] && random[i])) return std::unexpected(SendError::invalid_random);
        if (state_!=SendStatus::padding) {
            SendBlock result; result.wire.assign(bytes.begin(),bytes.end()); next_=state_; state_=SendStatus::pending; return result;
        }
        auto switching=filter.is_tls() && complete_application_records(bytes);
        auto ending=!switching && !filter.tls12_or_later() && filter.remaining()<=1;
        auto first_command=ending ? Command::end : Command::more;
        auto final_command=switching ? (filter.direct_eligible() ? Command::direct : Command::end) : first_command;
        auto make_block=[&](std::span<std::uint8_t const> part,std::size_t r,std::size_t bound,Command command,bool first) {
            auto padding=bound==500 ? r+900-part.size() : r;
            padding=std::min(padding,std::size_t{8171}-part.size());
            std::vector<std::uint8_t> filler(padding,0);
            return encode_block(first && first_ ? std::optional<UserId>{user_} : std::nullopt,command,part,filler);
        };
        auto first=make_block(bytes.first(plan->split),random[0],plan->random_bounds[0],first_command,true);
        if (!first) return std::unexpected(SendError::invalid_size);
        if (ending) first->insert(first->end(),bytes.begin()+plan->split,bytes.end());
        else {
            auto second=make_block(bytes.subspan(plan->split),random[1],plan->random_bounds[1],final_command,false);
            if (!second) return std::unexpected(SendError::invalid_size);
            first->insert(first->end(),second->begin(),second->end());
        }
        next_=switching ? (filter.direct_eligible() ? SendStatus::direct : SendStatus::plain) : ending ? SendStatus::plain : SendStatus::padding;
        state_=SendStatus::pending; return SendBlock{std::move(*first),final_command,true};
    }
    auto Sender::prepare(TrafficFilter const& filter,std::span<std::uint8_t const> bytes,std::size_t random_value,bool initial)
        -> std::expected<SendBlock,SendError> {
        if (state_==SendStatus::pending || state_==SendStatus::failed) return std::unexpected(SendError::invalid_state);
        if (bytes.size()>8171 || (initial && (!first_ || !bytes.empty())) || (!initial && bytes.empty())) return std::unexpected(SendError::invalid_size);
        if (state_!=SendStatus::padding) {
            if (initial || random_value) return std::unexpected(SendError::invalid_random);
            SendBlock block; block.wire.assign(bytes.begin(),bytes.end()); next_=state_; state_=SendStatus::pending; return block;
        }
        auto bound=random_bound(filter,bytes.size(),initial);
        if (random_value>=bound) return std::unexpected(SendError::invalid_random);
        auto long_padding=(initial || filter.is_tls()) && bytes.size()<900;
        auto padding=long_padding ? random_value+900-bytes.size() : random_value;
        padding=std::min(padding,std::size_t{8171}-bytes.size());
        Command command=Command::more; next_=SendStatus::padding;
        if (!initial && filter.is_tls() && bytes.size()>=6 && complete_application_records(bytes)) {
            command=filter.direct_eligible() ? Command::direct : Command::end;
            next_=filter.direct_eligible() ? SendStatus::direct : SendStatus::plain;
        } else if (!initial && !filter.tls12_or_later() && filter.remaining()<=1) {
            command=Command::end; next_=SendStatus::plain;
        }
        std::vector<std::uint8_t> filler(padding,0);
        auto encoded=encode_block(first_ ? std::optional<UserId>{user_} : std::nullopt,command,bytes,filler);
        if (!encoded) return std::unexpected(SendError::invalid_size);
        state_=SendStatus::pending;
        return SendBlock{std::move(*encoded),command,true};
    }
    auto Sender::commit(bool written) noexcept -> bool {
        if (state_!=SendStatus::pending) return false;
        if (!written) { state_=SendStatus::failed; return true; }
        first_=false; state_=next_; return true;
    }
    auto PrefixDetector::feed(std::span<std::uint8_t const> input) noexcept -> PrefixStep {
        PrefixStep result{0,status_};
        if (status_!=PrefixStatus::detecting) return result;
        while (result.consumed<input.size()) {
            auto byte=input[result.consumed++]; bytes_[size_]=byte;
            if (byte!=user_[size_++]) { status_=PrefixStatus::plain; break; }
            if (size_==bytes_.size()) { status_=PrefixStatus::padded; break; }
        }
        result.status=status_; return result;
    }
    auto PrefixDetector::finish() noexcept -> PrefixStatus {
        if (status_==PrefixStatus::detecting) status_=PrefixStatus::plain;
        return status_;
    }
    auto PrefixDetector::consume(std::size_t count) noexcept -> bool {
        if (status_==PrefixStatus::detecting || count>size_-offset_) return false;
        offset_+=count; return true;
    }
    auto encode_block(std::optional<UserId> const& user,Command command,std::span<std::uint8_t const> content,std::span<std::uint8_t const> padding)
        -> std::expected<std::vector<std::uint8_t>,Status> {
        if (static_cast<unsigned>(command)>2 || content.size()>65535 || padding.size()>65535) return std::unexpected(Status::invalid);
        std::vector<std::uint8_t> out; out.reserve((user ? 16 : 0)+5+content.size()+padding.size());
        if (user) out.insert(out.end(),user->begin(),user->end());
        out.push_back(static_cast<std::uint8_t>(command));
        out.push_back(static_cast<std::uint8_t>(content.size()>>8)); out.push_back(static_cast<std::uint8_t>(content.size()));
        out.push_back(static_cast<std::uint8_t>(padding.size()>>8)); out.push_back(static_cast<std::uint8_t>(padding.size()));
        out.insert(out.end(),content.begin(),content.end()); out.insert(out.end(),padding.begin(),padding.end());
        return out;
    }
    auto Decoder::feed(std::span<std::uint8_t const> input,std::span<std::uint8_t> output) noexcept -> Step {
        Step step; step.status=status_;
        if (status_!=Status::reading) return step;
        while (true) {
            while (prefix_<user_.size() && step.consumed<input.size()) {
                if (input[step.consumed++]!=user_[prefix_++]) { status_=Status::invalid; step.status=status_; return step; }
            }
            if (prefix_<user_.size()) break;
            while (header_size_<header_.size() && step.consumed<input.size()) header_[header_size_++]=input[step.consumed++];
            if (header_size_<header_.size()) break;
            if (header_size_==5) {
                if (header_[0]>2) { status_=Status::invalid; break; }
                command_=static_cast<Command>(header_[0]);
                content_=(std::size_t{header_[1]}<<8)|header_[2]; padding_=(std::size_t{header_[3]}<<8)|header_[4];
                ++header_size_;
            }
            auto count=std::min({content_,input.size()-step.consumed,output.size()-step.written});
            std::copy_n(input.begin()+step.consumed,count,output.begin()+step.written);
            step.consumed+=count; step.written+=count; content_-=count;
            if (content_) break;
            count=std::min(padding_,input.size()-step.consumed); step.consumed+=count; padding_-=count;
            if (padding_) break;
            if (command_!=Command::more) { status_=command_==Command::end ? Status::end : Status::direct; break; }
            completed_=true; header_size_=0;
            if (step.consumed==input.size()) break;
        }
        step.status=status_; return step;
    }
    auto Decoder::finish() noexcept -> Status {
        if (status_==Status::reading) status_=completed_ && header_size_==0 ? Status::end : Status::truncated;
        return status_;
    }
    auto Receiver::feed(std::span<std::uint8_t const> input,std::span<std::uint8_t> output) noexcept -> ReceiveStep {
        ReceiveStep result{0,0,status_};
        if (status_==ReceiveStatus::closed || status_==ReceiveStatus::direct || status_==ReceiveStatus::invalid || status_==ReceiveStatus::truncated || (eof_ && !input.empty())) return result;
        if (status_==ReceiveStatus::detecting) {
            auto detected=prefix_.feed(input); result.consumed=detected.consumed;
            if (detected.status==PrefixStatus::detecting) return result;
            status_=detected.status==PrefixStatus::padded ? ReceiveStatus::padded : ReceiveStatus::plain;
        }
        if (status_==ReceiveStatus::padded) {
            if (!prefix_.buffered().empty()) {
                auto step=decoder_.feed(prefix_.buffered(),output);
                (void)prefix_.consume(step.consumed); result.written+=step.written;
                if (!prefix_.buffered().empty()) { result.status=status_; return result; }
            }
            auto step=decoder_.feed(input.subspan(result.consumed),output.subspan(result.written));
            result.consumed+=step.consumed; result.written+=step.written;
            if (step.status==Status::invalid) status_=ReceiveStatus::invalid;
            else if (step.status==Status::direct) status_=ReceiveStatus::direct;
            else if (step.status==Status::end) status_=ReceiveStatus::plain;
        }
        if (status_==ReceiveStatus::plain) {
            auto buffered=prefix_.buffered();
            auto count=std::min(buffered.size(),output.size()-result.written);
            std::copy_n(buffered.begin(),count,output.begin()+result.written);
            (void)prefix_.consume(count); result.written+=count;
            if (prefix_.buffered().empty()) {
                count=std::min(input.size()-result.consumed,output.size()-result.written);
                std::copy_n(input.begin()+result.consumed,count,output.begin()+result.written);
                result.consumed+=count; result.written+=count;
                if (eof_) status_=ReceiveStatus::closed;
            }
        }
        result.status=status_; return result;
    }
    auto Receiver::finish() noexcept -> ReceiveStatus {
        if (status_==ReceiveStatus::detecting) { (void)prefix_.finish(); status_=ReceiveStatus::plain; }
        if (status_==ReceiveStatus::padded) status_=decoder_.finish()==Status::end ? ReceiveStatus::closed : ReceiveStatus::truncated;
        if (status_==ReceiveStatus::plain) { eof_=true; if (prefix_.buffered().empty()) status_=ReceiveStatus::closed; }
        return status_;
    }
}
