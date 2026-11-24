# Bash completion for nexus CLI

_nexus_completions() {
    local cur prev words cword
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    local top_cmds="run check rule endpoint control state generate tools convert-config provider system-proxy service --help"
    local rule_cmds="convert merge explain fetch watch --help"
    local control_cmds="status connections close close-any close-all select probe group-health user-usage reload clear-cache network-change operation events diagnostics log-level"
    local state_cmds="inspect clear-cache reset --help"
    local endpoint_cmds="check run --help"
    local provider_cmds="inspect sync --help"
    local sysproxy_cmds="status on off --help"
    local service_cmds="install uninstall start stop restart status --help"

    if [[ $COMP_CWORD -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "$top_cmds" -- "$cur") )
        return 0
    fi

    case "${COMP_WORDS[1]}" in
        run)
            if [[ "$prev" == "--config" ]]; then
                COMPREPLY=( $(compgen -f -X '!*.kdl' -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "--config --traffic-stats --help" -- "$cur") )
            fi
            ;;
        check)
            if [[ "$prev" == "--config" ]]; then
                COMPREPLY=( $(compgen -f -X '!*.kdl' -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "--config --help" -- "$cur") $(compgen -f -X '!*.kdl' -- "$cur") )
            fi
            ;;
        rule)
            if [[ $COMP_CWORD -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "$rule_cmds" -- "$cur") )
            elif [[ "$prev" == "--cache-dir" ]]; then
                COMPREPLY=( $(compgen -d -- "$cur") )
            else
                case "${COMP_WORDS[2]}" in
                    fetch|watch)
                        COMPREPLY=( $(compgen -W "--sha256 --cache-dir --ruleset-cache-max-bytes --offline-cache --help" -- "$cur") )
                        ;;
                    convert)
                        COMPREPLY=( $(compgen -W "kdl beve srs --help" -- "$cur") )
                        ;;
                    *)
                        COMPREPLY=( $(compgen -f -- "$cur") )
                        ;;
                esac
            fi
            ;;
        control)
            if [[ $COMP_CWORD -eq 2 ]]; then
                COMPREPLY=( $(compgen -f -- "$cur") )
            elif [[ $COMP_CWORD -eq 3 ]]; then
                COMPREPLY=( $(compgen -W "--server-uid $control_cmds" -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "$control_cmds --auto" -- "$cur") )
            fi
            ;;
        state)
            if [[ $COMP_CWORD -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "$state_cmds" -- "$cur") )
            elif [[ "$prev" == "--config" ]]; then
                COMPREPLY=( $(compgen -f -X '!*.kdl' -- "$cur") )
            elif [[ "$prev" == "--target" ]]; then
                COMPREPLY=( $(compgen -W "fakeip selectors" -- "$cur") )
            else
                case "${COMP_WORDS[2]}" in
                    inspect)
                        COMPREPLY=( $(compgen -W "--config --help" -- "$cur") )
                        ;;
                    clear-cache)
                        COMPREPLY=( $(compgen -W "--config --dns --rulesets --help" -- "$cur") )
                        ;;
                    reset)
                        COMPREPLY=( $(compgen -W "--config --target --confirm --help" -- "$cur") )
                        ;;
                esac
            fi
            ;;
        endpoint)
            if [[ $COMP_CWORD -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "$endpoint_cmds" -- "$cur") )
            elif [[ "$prev" == "--config" ]]; then
                COMPREPLY=( $(compgen -f -X '!*.kdl' -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "--config --resolve --help" -- "$cur") )
            fi
            ;;
        convert-config)
            COMPREPLY=( $(compgen -W "--from --output -o --inbound-listen --inbound-type --default-group --include --exclude --tag-prefix --help" -- "$cur") $(compgen -f -- "$cur") )
            ;;
        provider)
            if [[ $COMP_CWORD -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "$provider_cmds" -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "--config --name --json --force --help" -- "$cur") )
            fi
            ;;
        system-proxy)
            if [[ $COMP_CWORD -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "$sysproxy_cmds" -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "--host --port --socks-port --bypass --pac-url --dry-run --shell-env --json --help" -- "$cur") )
            fi
            ;;
        service)
            if [[ $COMP_CWORD -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "$service_cmds" -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "--config --name --binary --workdir --log --user --output-dir --render-target --dry-run --json --help" -- "$cur") )
            fi
            ;;
    esac
}

complete -F _nexus_completions nexus
