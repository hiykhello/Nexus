if is_plat("linux") then
    target("nexus-udp-deferred-allocation-test")
        set_kind("binary")
        set_default(false)
        add_files("$(projectdir)/tests/udp_deferred_allocation.cpp")
        add_ldflags("-Wl,--wrap=recvfrom")
        add_deps("nexus-udp-engine", "nexus-rules")

    target("nexus-udp-output-allocation-test")
        set_kind("binary")
        set_default(false)
        add_files("$(projectdir)/tests/udp_output_allocation.cpp")
        add_ldflags("-Wl,--wrap=recvfrom")
        add_deps("nexus-udp-engine", "nexus-rules")

    target("nexus-udp-direct-many-test")
        set_kind("binary")
        set_default(false)
        add_files("$(projectdir)/tests/udp_direct_many.cpp")
        add_deps("nexus-udp-direct", "nexus-rules")

    target("nexus-udp-send-fault-test")
        set_kind("binary")
        set_default(false)
        add_files("$(projectdir)/tests/udp_send_fault.cpp")
        add_ldflags("-Wl,--wrap=sendto")
        add_deps("nexus-udp-engine", "nexus-rules")

    target("nexus-udp-reply-allocation-test")
        set_kind("binary")
        set_default(false)
        add_files("$(projectdir)/tests/udp_reply_allocation.cpp")
        add_ldflags("-Wl,--wrap=recvfrom")
        add_deps("nexus-udp-direct", "nexus-rules")

    target("nexus-udp-input-allocation-test")
        set_kind("binary")
        set_default(false)
        add_files("$(projectdir)/tests/udp_input_allocation.cpp")
        add_deps("nexus-udp-engine", "nexus-rules")

    target("nexus-packet-switch-allocation-test")
        set_kind("binary")
        set_default(false)
        add_files("$(projectdir)/tests/packet_switch_allocation.cpp")
        add_deps("nexus-packet-switch")

    target("nexus-udp-direct-fault-test")
        set_kind("binary")
        set_default(false)
        add_files("$(projectdir)/tests/udp_direct_fault.cpp")
        add_ldflags("-Wl,--wrap=recvfrom")
        add_deps("nexus-udp-direct", "nexus-rules")
end

if is_plat("linux") then
    target("nexus-udp-engine-fault-test")
        set_kind("binary")
        set_default(false)
        add_files("$(projectdir)/tests/udp_engine_fault.cpp")
        add_ldflags("-Wl,--wrap=recvfrom")
        add_deps("nexus-udp-engine", "nexus-rules")
end

