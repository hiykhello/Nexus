#!/usr/bin/env python3
"""Generate and independently verify the selected Linux/glibc netlink ABI.

Native headers enter only throwaway probe TUs through compiler -include flags.
The generated named module has no textual include or forwarding function.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

HEADERS = ('sys/socket.h', 'unistd.h', 'poll.h', 'linux/netlink.h', 'linux/rtnetlink.h',
           'linux/if_link.h', 'linux/if_addr.h', 'linux/if.h', 'linux/if_arp.h', 'linux/if_tun.h', 'sys/ioctl.h', 'fcntl.h', 'sched.h', 'errno.h','signal.h','netinet/in.h','pthread.h','linux/fib_rules.h','linux/netconf.h')
STRUCTS = ('sockaddr', 'sockaddr_nl', 'nlmsghdr', 'nlmsgerr', 'ifinfomsg', 'ifaddrmsg', 'ifa_cacheinfo', 'rtmsg', 'rtattr', 'rta_cacheinfo', 'pollfd', 'fib_rule_hdr','netconfmsg')
FUNCTIONS = ('socket', 'bind', 'getsockname', 'sendto', 'recvfrom', 'close', 'poll', 'readlink', '__errno_location', 'ioctl', 'fcntl', 'unshare', 'sigemptyset', 'sigaddset', 'pthread_sigmask', 'write', 'read', 'open')
CONSTANTS = '''AF_UNSPEC AF_INET AF_INET6 AF_NETLINK NETLINK_ROUTE SOCK_RAW SOCK_NONBLOCK SOCK_CLOEXEC MSG_TRUNC
NLMSG_ALIGNTO RTA_ALIGNTO NLMSG_NOOP NLMSG_ERROR NLMSG_DONE NLMSG_OVERRUN
NLM_F_APPEND NLM_F_REPLACE NLM_F_REQUEST NLM_F_ACK NLM_F_EXCL NLM_F_CREATE NLM_F_DUMP NLM_F_DUMP_INTR NLM_F_MULTI NLM_F_CAPPED NLM_F_ACK_TLVS
RTM_DELLINK RTM_GETLINK RTM_NEWLINK RTM_NEWADDR RTM_DELADDR RTM_GETADDR RTM_NEWROUTE RTM_DELROUTE RTM_GETROUTE
IFLA_IFNAME IFLA_MTU IFLA_IFALIAS IFLA_LINKINFO IFLA_INFO_KIND IFLA_AF_SPEC IFLA_INET6_ADDR_GEN_MODE IN6_ADDR_GEN_MODE_NONE
IFA_LOCAL IFA_ADDRESS IFA_FLAGS IFA_LABEL IFA_CACHEINFO IFA_PROTO IFA_F_NOPREFIXROUTE IFA_F_NODAD IFA_F_PERMANENT IFA_F_SECONDARY IFA_F_TENTATIVE IFA_F_DADFAILED
RTA_DST RTA_SRC RTA_OIF RTA_TABLE RTA_PRIORITY RTA_PREFSRC RTA_GATEWAY RTA_MULTIPATH RTA_CACHEINFO RTA_PREF RTA_EXPIRES RTA_MARK RTA_IP_PROTO RTA_SPORT RTA_DPORT
RTNH_F_LINKDOWN RT_TABLE_MAIN RT_TABLE_LOCAL RT_TABLE_COMPAT RTPROT_STATIC RT_SCOPE_UNIVERSE RT_SCOPE_LINK RT_SCOPE_HOST RTN_UNICAST RTN_LOCAL RTM_F_LOOKUP_TABLE IPPROTO_UDP
TUNSETPERSIST F_GETFD F_GETFL O_NONBLOCK CLONE_NEWNET IFF_UP IFF_LOWER_UP IFF_POINTOPOINT IFF_NOARP ARPHRD_NONE ARPHRD_LOOPBACK NLA_F_NESTED NLA_TYPE_MASK POLLIN POLLOUT POLLERR POLLHUP POLLNVAL SIGINT SIGTERM SIGHUP SIGNAL_ERROR SIG_BLOCK SIG_SETMASK
RTM_GETNETCONF RTM_NEWNETCONF RTM_DELNETCONF NETCONFA_IFINDEX NETCONFA_RP_FILTER NETCONFA_IFINDEX_ALL NETCONFA_IFINDEX_DEFAULT RTNLGRP_IPV4_NETCONF O_RDONLY O_WRONLY O_CLOEXEC O_NOFOLLOW
RTM_NEWRULE RTM_DELRULE RTM_GETRULE FRA_PRIORITY FRA_TABLE FRA_FWMARK FRA_FWMASK FRA_PROTOCOL FRA_SUPPRESS_PREFIXLEN
FRA_IIFNAME FRA_OIFNAME FRA_SRC FRA_DST FRA_GOTO FRA_UID_RANGE FRA_L3MDEV FRA_IP_PROTO FRA_SPORT_RANGE FRA_DPORT_RANGE
FR_ACT_TO_TBL FR_ACT_UNREACHABLE FIB_RULE_INVERT RTPROT_KERNEL RTPROT_BOOT RT_TABLE_UNSPEC
RTNLGRP_LINK RTNLGRP_IPV4_IFADDR RTNLGRP_IPV6_IFADDR RTNLGRP_IPV4_ROUTE RTNLGRP_IPV6_ROUTE RTNLGRP_IPV4_RULE RTNLGRP_IPV6_RULE SOL_NETLINK NETLINK_ADD_MEMBERSHIP'''.split()
TYPES = {'__kernel_sa_family_t': 'unsigned short', 'sa_family_t': 'unsigned short',
         '__s32': 'std::int32_t', '__u8': 'std::uint8_t', '__u16': 'std::uint16_t', '__u32': 'std::uint32_t', '__u64': 'std::uint64_t',
         '__sigset_t': 'sigset_t', 'socklen_t': 'unsigned int', 'nfds_t': 'unsigned long', 'ssize_t': 'std::ptrdiff_t', 'size_t': 'std::size_t'}


def command(args, source='', cwd=None):
    result = subprocess.run(args, input=source, capture_output=True, text=True, cwd=cwd, timeout=60)
    if result.returncode:
        raise RuntimeError(f'{args}: {result.stderr}')
    return result.stdout


def includes(headers):
    return [item for header in headers for item in ('-include', header)]


def strip_attributes(text):
    while match := re.search(r'\b__attribute__\s*\(\(', text):
        start, depth, position = match.start(), 0, match.end() - 2
        while position < len(text):
            depth += (text[position] == '(') - (text[position] == ')')
            position += 1
            if depth == 0: break
        if depth: raise ValueError('unbalanced native attribute')
        text = text[:start] + text[position:]
    return re.sub(r'\b__restrict\b', '', text)


def selected_declarations(preprocessed):
    text = strip_attributes(preprocessed)
    structs, fields = [], {}
    # Derive the otherwise anonymous glibc sigset_t from the native typedef.
    sigset = re.findall(r'typedef\s+struct\s*\{([^{}]*)\}\s*__sigset_t\s*;', text)
    if len(sigset) != 1: raise ValueError('native sigset typedef count')
    body = ' '.join(sigset[0].split())
    structs.append('    struct sigset_t { ' + body + ' };')
    fields['sigset_t'] = ['__val']
    for name in STRUCTS:
        matches = list(re.finditer(r'\bstruct\s+' + name + r'\s*\{([^{}]*)\}\s*;', text))
        if len(matches) != 1: raise ValueError(f'{name}: native struct count {len(matches)}')
        body = matches[0][1]
        names = []
        for field in body.split(';'):
            if not field.strip(): continue
            found = re.search(r'\b(\w+)\s*(?:\[[^\]]+\])?\s*$', field)
            if not found: raise ValueError(f'{name}: unsupported field {field}')
            names.append(found[1])
        fields[name] = names
        body = '\n'.join('        ' + ' '.join(line.split()) for line in body.splitlines() if line.strip())
        structs.append(f'    struct {name} {{\n{body}\n    }};')
    functions = []
    for name in FUNCTIONS:
        matches = list(re.finditer(r'\bextern\s+[^;{}]+?\b' + name + r'\s*\([^;{}]+?;', text))
        if len(matches) != 1: raise ValueError(f'{name}: native function count {len(matches)}')
        value = ' '.join(matches[0][0].split()).replace('extern ', 'extern "C" ', 1)
        functions.append('    ' + value)
    result = '\n'.join(structs + functions)
    for original, target in TYPES.items(): result = re.sub(r'\b' + original + r'\b', target, result)
    unknown = set(re.findall(r'\b__[a-zA-Z]\w*\b', result)) - {'__errno_location', '__ifi_pad'}
    # Native parameter identifiers carry __; only types are relevant.
    if any(name in unknown for name in ('__u8', '__u16', '__u32', '__u64', '__kernel_sa_family_t')):
        raise ValueError('unmapped native scalar')
    return result, fields


def printer(fields, prefix=''):
    lines = ['template<class T> void signature(char const* name,T) {',
             '    std::printf("signature %s %s\\n",name,__PRETTY_FUNCTION__);', '}', 'int main() {']
    for name, members in fields.items():
        tag = prefix + name
        lines.append(f'    std::printf("struct {name} %zu %zu\\n",sizeof({tag}),alignof({tag}));')
        for field in members:
            lines.append(f'    std::printf("field {name}.{field} %zu %zu\\n",__builtin_offsetof({tag},{field}),sizeof((({tag}*)0)->{field}));')
    for name in CONSTANTS:
        expression='reinterpret_cast<std::intptr_t>(SIG_ERR)' if name=='SIGNAL_ERROR' and not prefix else prefix+name
        lines.append(f'    std::printf("constant {name} %lld\\n",static_cast<long long>({expression}));')
    for name in FUNCTIONS: lines.append(f'    signature("{name}",&{prefix}{name});')
    return '\n'.join(lines + ['}'])


def parse_probe(output):
    constants, layouts, signatures = {}, {}, {}
    for line in output.splitlines():
        kind, name, rest = line.split(' ', 2)
        if kind == 'struct':
            size, alignment = map(int, rest.split()); layouts[name] = {'size': size, 'align': alignment, 'fields': {}}
        elif kind == 'field':
            tag, field = name.split('.'); layouts[tag]['fields'][field] = list(map(int, rest.split()))
        elif kind == 'constant': constants[name] = int(rest)
        else: signatures[name] = rest.replace('platform::netlink_abi::', '').replace('__sigset_t', 'sigset_t')
    return {'layouts': layouts, 'constants': constants, 'signatures': signatures}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--compiler', default='/usr/bin/g++')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(); root = args.root.resolve()
    probe_flags = [args.compiler, '-std=c++26', '-Werror', '-Wno-ignored-attributes']
    header_flags = includes(HEADERS)
    preprocessed = command([args.compiler, '-E', '-P', '-x', 'c++', *header_flags, '-'])
    declarations, fields = selected_declarations(preprocessed)
    with tempfile.TemporaryDirectory(prefix='netlink-abi-', dir=root) as directory:
        directory = Path(directory)
        native = directory / 'native.cpp'; binary = directory / 'native'
        native.write_text(printer(fields))
        command([*probe_flags, *includes(('cstdio', 'cstddef', 'cstdint')), *header_flags, str(native), '-o', str(binary)])
        native_result = parse_probe(command([str(binary)]))
        constants = '\n'.join(f'    inline constexpr int {name}={value};' for name, value in native_result['constants'].items())
        body = 'namespace platform::netlink_abi {\n' + declarations + '\n' + constants + '\n}\n'
        generated = directory / 'generated.cpp'; binary = directory / 'generated'
        generated.write_text(body + printer(fields, 'platform::netlink_abi::'))
        command([*probe_flags, *includes(('cstdio', 'cstddef', 'cstdint')), str(generated), '-o', str(binary)])
        generated_result = parse_probe(command([str(binary)]))
        if generated_result != native_result:
            raise ValueError('native/generated mismatch: ' + json.dumps({'native': native_result, 'generated': generated_result}, indent=2))
    system_headers = command([args.compiler, '-M', '-x', 'c++', *header_flags, '-']).replace('\\\n', ' ').split(':', 1)[1].split()
    header_hashes = {str(Path(path).resolve()): hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in system_headers}
    profile = {**native_result, 'target': 'Linux x86-64 LP64 glibc', 'headers': header_hashes}
    profile_data = json.dumps(profile, indent=2, sort_keys=True) + '\n'
    digest = hashlib.sha256(profile_data.encode()).hexdigest()
    module = ('// Generated by scripts/netlink-boundary.py; do not edit.\n'
              f'// Native profile SHA-256: {digest}\n'
              '#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)\n'
              '#error "This netlink boundary is verified for Linux x86-64 LP64 glibc only"\n#endif\n\n'
              'export module platform.netlink_abi;\nimport std;\n\n' + body.replace('namespace platform::', 'export namespace platform::', 1))
    outputs = {root / 'src/platform/netlink_abi.cppm': module, root / 'scripts/netlink-boundary.json': profile_data}
    for path, value in outputs.items():
        if args.check:
            if path.read_text() != value: raise ValueError(f'{path}: generated drift')
        else:
            path.parent.mkdir(parents=True, exist_ok=True); path.write_text(value)
    print(f'netlink native/generated: {len(fields)} structs, {sum(map(len,fields.values()))} fields, {len(CONSTANTS)} constants and {len(FUNCTIONS)} exact C signatures match; profile {digest}')


if __name__ == '__main__': main()
