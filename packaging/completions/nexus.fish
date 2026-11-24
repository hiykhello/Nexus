# Fish shell completions for nexus CLI

set -l nexus_top run check rule endpoint control state convert-config provider system-proxy service

complete -c nexus -f
complete -c nexus -n "not __fish_seen_subcommand_from $nexus_top" -a run -d "Run proxy server from KDL configuration"
complete -c nexus -n "not __fish_seen_subcommand_from $nexus_top" -a check -d "Validate KDL configuration"
complete -c nexus -n "not __fish_seen_subcommand_from $nexus_top" -a rule -d "Convert, explain, fetch, or watch rule sets"
complete -c nexus -n "not __fish_seen_subcommand_from $nexus_top" -a endpoint -d "Check or run standalone protocol endpoints"
complete -c nexus -n "not __fish_seen_subcommand_from $nexus_top" -a control -d "Send NEXUS/1 commands over control socket"
complete -c nexus -n "not __fish_seen_subcommand_from $nexus_top" -a state -d "Inspect, clear caches, or reset state"
complete -c nexus -n "not __fish_seen_subcommand_from $nexus_top" -a convert-config -d "Convert external proxy/URI configs to Nexus KDL"
complete -c nexus -n "not __fish_seen_subcommand_from $nexus_top" -a provider -d "Inspect or sync proxy providers"
complete -c nexus -n "not __fish_seen_subcommand_from $nexus_top" -a system-proxy -d "Manage OS system proxy settings"
complete -c nexus -n "not __fish_seen_subcommand_from $nexus_top" -a service -d "Manage systemd, launchd, or Windows service"

# run & check
complete -c nexus -n "__fish_seen_subcommand_from run check" -l config -r -F -d "KDL configuration file"
complete -c nexus -n "__fish_seen_subcommand_from run" -l traffic-stats -d "Enable traffic counters"
complete -c nexus -n "__fish_seen_subcommand_from run check" -l help -d "Show help"

# rule
complete -c nexus -n "__fish_seen_subcommand_from rule; and not __fish_seen_subcommand_from convert explain fetch watch" -a convert -d "Convert rule format (kdl/beve/srs)"
complete -c nexus -n "__fish_seen_subcommand_from rule; and not __fish_seen_subcommand_from convert explain fetch watch" -a explain -d "Explain routing decision"
complete -c nexus -n "__fish_seen_subcommand_from rule; and not __fish_seen_subcommand_from convert explain fetch watch" -a fetch -d "Fetch remote ruleset"
complete -c nexus -n "__fish_seen_subcommand_from rule; and not __fish_seen_subcommand_from convert explain fetch watch" -a watch -d "Watch and refresh remote ruleset"
complete -c nexus -n "__fish_seen_subcommand_from rule" -l sha256 -r -d "Expected SHA-256 digest"
complete -c nexus -n "__fish_seen_subcommand_from rule" -l cache-dir -r -d "Cache directory"
complete -c nexus -n "__fish_seen_subcommand_from rule" -l ruleset-cache-max-bytes -r -d "Max cache bytes"
complete -c nexus -n "__fish_seen_subcommand_from rule" -l offline-cache -d "Allow offline cache"

# control
complete -c nexus -n "__fish_seen_subcommand_from control" -l server-uid -r -d "Expected server UID"
for cmd in status connections close close-any close-all select probe group-health user-usage reload clear-cache network-change operation events diagnostics log-level
    complete -c nexus -n "__fish_seen_subcommand_from control" -a $cmd
end

# state
complete -c nexus -n "__fish_seen_subcommand_from state; and not __fish_seen_subcommand_from inspect clear-cache reset" -a inspect -d "Inspect durable state"
complete -c nexus -n "__fish_seen_subcommand_from state; and not __fish_seen_subcommand_from inspect clear-cache reset" -a clear-cache -d "Clear DNS or ruleset cache"
complete -c nexus -n "__fish_seen_subcommand_from state; and not __fish_seen_subcommand_from inspect clear-cache reset" -a reset -d "Reset fakeip or selectors state"
complete -c nexus -n "__fish_seen_subcommand_from state" -l config -r -F -d "KDL configuration file"
complete -c nexus -n "__fish_seen_subcommand_from state" -l dns -d "Clear DNS cache"
complete -c nexus -n "__fish_seen_subcommand_from state" -l rulesets -d "Clear ruleset cache"
complete -c nexus -n "__fish_seen_subcommand_from state" -l target -r -a "fakeip selectors" -d "Reset target"
complete -c nexus -n "__fish_seen_subcommand_from state" -l confirm -d "Confirm destructive reset"

# endpoint
complete -c nexus -n "__fish_seen_subcommand_from endpoint; and not __fish_seen_subcommand_from check run" -a check -d "Validate endpoint config"
complete -c nexus -n "__fish_seen_subcommand_from endpoint; and not __fish_seen_subcommand_from check run" -a run -d "Run endpoint"
complete -c nexus -n "__fish_seen_subcommand_from endpoint" -l config -r -F -d "KDL configuration file"
complete -c nexus -n "__fish_seen_subcommand_from endpoint" -l resolve -d "Resolve endpoint addresses"

# convert-config, provider, system-proxy, service
complete -c nexus -n "__fish_seen_subcommand_from convert-config" -l from -r -a "auto uri base64 sip008" -d "Source format"
complete -c nexus -n "__fish_seen_subcommand_from convert-config" -s o -l output -r -F -d "Output KDL path"
complete -c nexus -n "__fish_seen_subcommand_from provider; and not __fish_seen_subcommand_from inspect sync" -a "inspect sync"
complete -c nexus -n "__fish_seen_subcommand_from system-proxy; and not __fish_seen_subcommand_from status on off" -a "status on off"
complete -c nexus -n "__fish_seen_subcommand_from system-proxy" -l host -r -d "Proxy host"
complete -c nexus -n "__fish_seen_subcommand_from system-proxy" -l port -r -d "HTTP proxy port"
complete -c nexus -n "__fish_seen_subcommand_from system-proxy" -l socks-port -r -d "SOCKS proxy port"
complete -c nexus -n "__fish_seen_subcommand_from system-proxy" -l dry-run -d "Preview changes"
complete -c nexus -n "__fish_seen_subcommand_from system-proxy" -l shell-env -d "Emit shell export/unset lines"
complete -c nexus -n "__fish_seen_subcommand_from service; and not __fish_seen_subcommand_from install uninstall start stop restart status" -a "install uninstall start stop restart status"
complete -c nexus -n "__fish_seen_subcommand_from service" -l config -r -F -d "KDL configuration file"
complete -c nexus -n "__fish_seen_subcommand_from service" -l render-target -r -a "systemd launchd windows native" -d "Preview target"
