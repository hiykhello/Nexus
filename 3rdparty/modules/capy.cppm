module;
#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/ex/async_event.hpp>
#include <boost/capy/ex/async_mutex.hpp>

export module nexus.thirdparty.capy;
export namespace nex::capy {
    using ::boost::capy::const_buffer;
    using ::boost::capy::mutable_buffer;
    using ::boost::capy::task;
    using ::boost::capy::run_async;
    using ::boost::capy::async_event;
    using ::boost::capy::async_mutex;
    inline auto is_timeout(std::error_code const& error) -> bool {
        return error == ::boost::capy::make_error_condition(::boost::capy::cond::timeout);
    }
    inline auto is_eof(std::error_code const& error) -> bool {
        return error == ::boost::capy::make_error_condition(::boost::capy::cond::eof);
    }
}
