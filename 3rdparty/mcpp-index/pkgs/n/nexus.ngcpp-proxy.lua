-- Fixed upstream commit and archive; the interface below is byte-identical to
-- include/proxy/v4/proxy.ixx (SHA-256 91d957186597e0ae20178230789305c7f51de46c5bd0b499c538176479115538).
-- Form B in mcpp 2026.10.30.1 cannot declare module_extensions, and GCC
-- rejects module declarations from #include, so materialize the original
-- interface as .cppm. Update it together with the pinned source archive.
package = {
    spec = "1", namespace = "nexus", name = "ngcpp-proxy",
    description = "Nexus pinned ngcpp proxy", licenses = { "MIT" },
    repo = "https://github.com/ngcpp/proxy", type = "package",
    xpm = { linux = { ["0.1.0"] = {
        url = "https://github.com/ngcpp/proxy/archive/9d9749d63766cdd9affb5ea7953237e38ce5ab63.tar.gz",
        sha256 = "21eecb3fef4d36055e030600c939465c4239516f8629051e7ea9ee68dd42dd3b",
    } } },
    mcpp = {
        language = "c++23", import_std = false,
        include_dirs = { "*/include" },
        -- Exact copy of upstream proxy.ixx at the pinned source commit.
        generated_files = { ["mcpp_generated/proxy.cppm"] = [=[module;

#include <proxy/v4/proxy.h>

export module proxy.v4;

export namespace pro::inline v4 {

#if __STDC_HOSTED__
using v4::allocate_proxy;
using v4::allocate_proxy_shared;
using v4::make_proxy;
using v4::make_proxy_shared;
#endif // __STDC_HOSTED__

#if __cpp_rtti >= 199711L
using v4::bad_proxy_cast;
#endif // __cpp_rtti >= 199711L

using v4::basic_facade_builder;
using v4::constraint_level;
using v4::conversion_dispatch;
using v4::explicit_conversion_dispatch;
using v4::facade;
using v4::facade_aware_overload_t;
using v4::facade_builder;
using v4::implicit_conversion_dispatch;
using v4::inplace_proxiable_target;
using v4::is_bitwise_trivially_relocatable;
using v4::is_bitwise_trivially_relocatable_v;
using v4::make_proxy_inplace;
using v4::make_proxy_view;
using v4::not_implemented;
using v4::observer_facade;
using v4::operator_dispatch;
using v4::proxiable;
using v4::proxiable_target;
using v4::proxy;
using v4::proxy_indirect_accessor;
using v4::proxy_invoke;
using v4::proxy_reflect;
using v4::proxy_view;
using v4::substitution_dispatch;
using v4::weak_dispatch;
using v4::weak_facade;
using v4::weak_proxy;

namespace skills {

#ifdef PRO4D_HAS_FORMAT
using skills::format;
using skills::wformat;
#endif // PRO4D_HAS_FORMAT

#if __cpp_rtti >= 199711L
using skills::direct_rtti;
using skills::indirect_rtti;
using skills::rtti;
#endif // __cpp_rtti >= 199711L

using skills::as_view;
using skills::as_weak;
using skills::slim;

} // namespace skills

} // namespace pro::inline v4

#ifdef PRO4D_HAS_FORMAT
export namespace std {

using std::formatter;

} // namespace std
#endif // PRO4D_HAS_FORMAT
]=] },
        sources = { "mcpp_generated/proxy.cppm" },
        modules = { "proxy.v4" },
        targets = { ["proxy"] = { kind = "lib" } }, deps = {},
    },
}
