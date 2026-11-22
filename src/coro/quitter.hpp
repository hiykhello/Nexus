// Copyright (c) 2026 Michael Vandeberg
// Distributed under the Boost Software License, Version 1.0.
// See https://www.boost.org/LICENSE_1_0.txt.
// Adapted from cppalliance/capy quitter.hpp at 24c54af2cf967ccbf8d3809af4bcd9c8f61f553b.
// Nexus owns this cancellation policy; current Capy supplies the public
// coroutine protocol, frame allocation, execution environment and chain owner.
#ifndef NEXUS_CORO_QUITTER_HPP
#define NEXUS_CORO_QUITTER_HPP

#include <boost/capy/concept/context_awaitable.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/ex/context_awaitable_promise_base.hpp>
#include <boost/capy/ex/frame_allocator.hpp>

#include <concepts>
#include <coroutine>
#include <exception>
#include <optional>
#include <system_error>
#include <tuple>
#include <type_traits>
#include <utility>

namespace coro {
    // Catch only at a boundary that has canceled and drained its child work.
    // Capy's default launch handler treats every exception as unhandled; a
    // directly launched quitter therefore needs an explicit error handler.
    struct stop_requested {};

    namespace detail {
        template<class T> struct result_storage {
            std::optional<T> value;
            auto return_value(this result_storage& self,T result) -> void {self.value.emplace(std::move(result));}
            auto result(this result_storage& self) noexcept -> T&& {return std::move(*self.value);}
        };
        template<> struct result_storage<void> {
            auto return_void() noexcept -> void {}
        };
        template<class T> inline constexpr bool is_results=false;
        template<class... T> inline constexpr bool is_results<std::tuple<std::error_code,T...>> = true;
    }

    // A lazy task that unwinds its body on cancellation, before its parent
    // continues. Its ordinary value may be bool or a protocol-specific type;
    // cancellation never manufactures a value of that type.
    template<class T=void> class [[nodiscard]] quitter {
    public:
        struct promise_type : boost::capy::context_awaitable_promise_base<promise_type>,detail::result_storage<T> {
            std::exception_ptr error;
            auto exception(this promise_type const& self) noexcept -> std::exception_ptr {return self.error;}
            auto get_return_object(this promise_type& self) noexcept -> quitter {
                return quitter{std::coroutine_handle<promise_type>::from_promise(self)};
            }
            auto unhandled_exception(this promise_type& self) noexcept -> void {self.error=std::current_exception();}
            auto initial_suspend(this promise_type& self) noexcept {
                struct awaiter {
                    promise_type* promise;
                    auto await_ready() const noexcept -> bool {return false;}
                    auto await_suspend(std::coroutine_handle<>) const noexcept -> void {}
                    auto await_resume() const -> void {
                        boost::capy::set_current_frame_allocator(promise->environment()->frame_allocator);
                        if(promise->environment()->stop_token.stop_requested())throw stop_requested{};
                    }
                };
                return awaiter{&self};
            }
            auto final_suspend(this promise_type& self) noexcept {
                struct awaiter {
                    promise_type* promise;
                    auto await_ready() const noexcept -> bool {return false;}
                    auto await_suspend(std::coroutine_handle<>) const noexcept -> std::coroutine_handle<> {
                        return promise->continuation();
                    }
                    auto await_resume() const noexcept -> void {}
                };
                return awaiter{&self};
            }
            template<class A> struct awaiter {
                A operation;
                promise_type* promise;
                bool skipped=false,synchronous=false;

                auto await_ready(this awaiter& self) -> bool {
                    if(self.promise->environment()->stop_token.stop_requested()) {
                        self.skipped=true;return true;
                    }
                    self.synchronous=self.operation.await_ready();
                    return self.synchronous;
                }
                template<class P> auto await_suspend(this awaiter& self,std::coroutine_handle<P> current) {
                    auto* environment=self.promise->environment();
                    using Result=decltype(self.operation.await_suspend(current,environment));
                    if constexpr(std::same_as<Result,void>) {
                        self.operation.await_suspend(current,environment);
                    } else if constexpr(std::same_as<Result,bool>) {
                        if(!self.operation.await_suspend(current,environment)) {
                            self.synchronous=true;return false;
                        }
                        return true;
                    } else {
                        auto next=self.operation.await_suspend(current,environment);
                        // No other thread can resume current when it is the
                        // returned handle. Do not touch self on an async path.
                        if(next==current)self.synchronous=true;
                        return next;
                    }
                }
                auto await_resume(this awaiter& self) -> decltype(auto) {
                    auto* environment=self.promise->environment();
                    boost::capy::set_current_frame_allocator(environment->frame_allocator);
                    if(self.skipped || (!self.synchronous && environment->stop_token.stop_requested()))
                        throw stop_requested{};
                    using Result=decltype(self.operation.await_resume());
                    if constexpr(detail::is_results<Result>) {
                        auto result=self.operation.await_resume();
                        if(std::get<0>(result)==boost::capy::cond::canceled && environment->stop_token.stop_requested())
                            throw stop_requested{};
                        return result;
                    } else {
                        // A synchronous await_ready/await_suspend may already
                        // have acquired a resource. Always hand it over even
                        // if stop raced that acquisition; stop at the next await.
                        return self.operation.await_resume();
                    }
                }
            };
            template<class A> requires boost::capy::ContextAwaitable<std::decay_t<A>>
            auto transform_awaitable(this promise_type& self,A&& operation) {
                return awaiter<std::decay_t<A>>{std::forward<A>(operation),&self};
            }
        };
    private:
        std::coroutine_handle<promise_type> frame_;
        bool lent_=false;
        explicit quitter(std::coroutine_handle<promise_type> frame) noexcept : frame_(frame) {}
        auto destroy(this quitter& self) noexcept -> void {
            if(!self.frame_)return;
            if(self.lent_ && !self.frame_.done()) {
                auto* owner=self.frame_.promise().environment()->owner;
                if(!owner || !owner->abandoned())std::terminate();
            }
            std::exchange(self.frame_,nullptr).destroy();self.lent_=false;
        }
    public:
        ~quitter() {destroy();}
        quitter(quitter const&)=delete;
        auto operator=(quitter const&) -> quitter& = delete;
        quitter(quitter&& other) noexcept
            :frame_(std::exchange(other.frame_,nullptr)),lent_(std::exchange(other.lent_,false)) {}
        auto operator=(this quitter& self,quitter&& other) noexcept -> quitter& {
            if(&self!=&other) {
                self.destroy();self.frame_=std::exchange(other.frame_,nullptr);self.lent_=std::exchange(other.lent_,false);
            }
            return self;
        }
        auto await_ready() const noexcept -> bool {return false;}
        auto await_suspend(this quitter& self,std::coroutine_handle<> continuation,boost::capy::await_context const* environment)
            noexcept -> std::coroutine_handle<> {
            self.frame_.promise().set_continuation(continuation);
            self.frame_.promise().set_environment(environment);self.lent_=true;return self.frame_;
        }
        auto await_resume(this quitter& self) -> T {
            self.lent_=false;
            if(self.frame_.promise().error)std::rethrow_exception(self.frame_.promise().error);
            if constexpr(!std::is_void_v<T>)return std::move(*self.frame_.promise().value);
        }
        auto handle(this quitter const& self) noexcept -> std::coroutine_handle<promise_type> {return self.frame_;}
        auto release(this quitter& self) noexcept -> void {self.frame_=nullptr;self.lent_=false;}
    };
}
#endif
