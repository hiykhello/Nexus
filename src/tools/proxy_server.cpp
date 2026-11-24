import cli.proxy_run;
import cli.hy2_enabled;
import cli.hy2_disabled;
import cli.masque_enabled;
import cli.masque_disabled;
import cli.tuic_enabled;
import cli.tuic_disabled;
import cli.tun_enabled;
import cli.tun_disabled;
namespace cli {
#ifdef NEXUS_ENABLE_MASQUE
using SelectedMasqueRuntime=masque_enabled::Runtime;
#else
using SelectedMasqueRuntime=masque_disabled::Runtime;
#endif
#ifdef NEXUS_ENABLE_HY2
using SelectedHy2Runtime=hy2_enabled::Runtime;
#else
using SelectedHy2Runtime=hy2_disabled::Runtime;
#endif
#ifdef NEXUS_ENABLE_TUIC
using SelectedTuicRuntime=tuic_enabled::Runtime;
#else
using SelectedTuicRuntime=tuic_disabled::Runtime;
#endif
#ifdef NEXUS_ENABLE_TUN
using SelectedTunRuntime=tun_enabled::Runtime;
#else
using SelectedTunRuntime=tun_disabled::Runtime;
#endif
}
import cli.udp;

#ifndef MCPP_FEATURE_SS2022
auto nexus_run(int argc, char** argv) -> int {
    return nexus_run_proxy<cli::UdpRuntime,cli::SelectedHy2Runtime,cli::SelectedMasqueRuntime,cli::SelectedTuicRuntime,cli::SelectedTunRuntime>(argc,argv,true);
}
auto nexus_run_embedded(int argc, char** argv) -> int {
    return nexus_run_proxy<cli::UdpRuntime,cli::SelectedHy2Runtime,cli::SelectedMasqueRuntime,cli::SelectedTuicRuntime,cli::SelectedTunRuntime>(argc,argv,false);
}
#endif
