module;
#include <glaze/kdl.hpp>
#include <glaze/beve.hpp>

export module glaze;

export namespace glaze {
    using ::glz::raw_json_view;
    using ::glz::read;
    using ::glz::read_json;
    using ::glz::format_error;
    using ::glz::opts;
    using ::glz::read_beve_at;
    using ::glz::read_kdl;
    using ::glz::write_beve;
    using ::glz::write_kdl;
    using Context = ::glz::context;
    using KdlDocument = ::glz::kdl::document;
    using KdlNode = ::glz::kdl::node;
    using KdlValue = ::glz::kdl::value;
}
