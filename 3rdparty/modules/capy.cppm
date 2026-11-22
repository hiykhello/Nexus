module;
#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/task.hpp>
#include "../../src/coro/quitter.hpp"
#include <boost/capy/when_all.hpp>
#include <boost/capy/when_any.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/ex/execution_context.hpp>
#include <boost/capy/ex/async_waker.hpp>
#include <boost/capy/ex/async_event.hpp>
#include <boost/capy/ex/this_coro.hpp>
#include <boost/capy/ex/async_mutex.hpp>

export module nexus.thirdparty.capy;
export using std::is_error_condition_enum;
export namespace boost::capy { using ::boost::capy::make_error_condition; }
export namespace nex::capy {
    namespace this_coro { using ::boost::capy::this_coro::stop_token; }
    using ::boost::capy::await_context;
    using ::boost::capy::execution_context;
    using ::boost::capy::const_buffer;
    using ::boost::capy::mutable_buffer;
    using ::boost::capy::task;
    using ::coro::quitter;
    using ::boost::capy::when_all;
    using ::boost::capy::when_any;
    using ::boost::capy::results;
    using ::boost::capy::cond;
    using ::boost::capy::make_error_condition;
    using ::boost::capy::run_async;
    using ::boost::capy::async_waker;
    using ::boost::capy::async_event;
    using ::boost::capy::async_mutex;
    using ::boost::capy::get_current_frame_allocator;
    using ::boost::capy::set_current_frame_allocator;
    inline auto is_timeout(std::error_code const& error) -> bool {
        return error == ::boost::capy::make_error_condition(::boost::capy::cond::timeout);
    }
    inline auto is_eof(std::error_code const& error) -> bool {
        return error == ::boost::capy::make_error_condition(::boost::capy::cond::eof);
    }
}
