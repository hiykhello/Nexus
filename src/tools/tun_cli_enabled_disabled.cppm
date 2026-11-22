export module cli.tun_enabled;
import cli.tun_disabled;
export namespace cli::tun_enabled {
    using Runtime = tun_disabled::Runtime;
    inline auto run_strict_tun_owner() -> int {return 2;}
}
