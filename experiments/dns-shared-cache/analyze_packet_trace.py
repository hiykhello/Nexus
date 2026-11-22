#!/usr/bin/env python3
"""Locate synthetic UDP delays in one isolated diagnostic run.

SS ciphertext cannot carry a readable test token. Intermediate packets are
associated in socket order, and reported only if counts and timestamps are
consistent throughout that direction. This inference does not prove identity
if packets reorder without breaking the timestamp checks.
"""
import collections
import json
import pathlib
import sys


def read_capture(path, start):
    lines = pathlib.Path(path).read_text().splitlines()
    if not lines or not lines[0].startswith("offset_start "):
        raise ValueError("missing capture offset")
    offset = int(lines[0].split()[1])
    packets = []
    end_offset = stats = None
    for line in lines[1:]:
        fields = line.split()
        if fields[0] == "packet" and len(fields) == 6:
            ns, source, dest, length, suffix = map(int, fields[1:])
            if ns - offset >= start:
                packets.append(((ns - offset - start) // 1000, source, dest, length, suffix))
        elif fields[0] == "offset_end" and len(fields) == 2:
            end_offset = int(fields[1])
        elif fields[0] == "stats" and len(fields) == 4:
            stats = tuple(map(int, fields[1:]))
        else:
            raise ValueError("invalid capture line: " + line)
    if end_offset is None or stats is None:
        raise ValueError("incomplete capture")
    return packets, {"clock_offset_change_ns": end_offset - offset,
                     "kernel_packets": stats[0], "kernel_drops": stats[1], "recorded_ipv4_udp": stats[2]}


def analyze(run, packets, index):
    client, socks = run["udp_client_ports"][index], run["udp_socks_ports"][index]
    listener, echo = run["udp_listener_ports"][index], run["udp_echo_port"]
    flows = collections.defaultdict(list)
    for time, source, dest, length, suffix in packets:
        flows[source, dest].append((time, length, suffix))
    endpoints = {source for source, dest in flows if dest == listener}
    result = {"listener_upstream_ports": sorted(endpoints)}
    if len(endpoints) != 1:
        result["error"] = "expected one encrypted upstream UDP socket"
        return result
    upstream = endpoints.pop()
    clients = flows[client, socks]
    encrypted_requests = flows[upstream, listener]
    encrypted_responses = flows[listener, upstream]
    replies = flows[socks, client]
    target_in = {suffix: time for (source, dest), events in flows.items() if dest == echo
                 for time, length, suffix in events if length == 8}
    target_out = {suffix: time for (source, dest), events in flows.items() if source == echo
                  for time, length, suffix in events if length == 8}
    result["counts"] = {"client_sent": len(clients), "encrypted_to_listener": len(encrypted_requests),
                        "encrypted_from_listener": len(encrypted_responses), "client_received": len(replies)}
    if len(clients) != len(encrypted_requests) or len(encrypted_responses) != len(replies):
        result["error"] = "packet counts differ; no ciphertext association attempted"
        return result
    forward = {token: (sent, encrypted, target_in.get(token))
               for (sent, _, token), (encrypted, _, _) in zip(clients, encrypted_requests)}
    reverse = {token: (target_out.get(token), encrypted, received)
               for (encrypted, _, _), (received, _, token) in zip(encrypted_responses, replies)}
    bad_forward = sum(t is None or not a <= b <= t for a, b, t in forward.values())
    bad_reverse = sum(t is None or not t <= a <= b for t, a, b in reverse.values())
    result["ordering_check_failures"] = {"forward": bad_forward, "reverse": bad_reverse}
    if bad_forward or bad_reverse:
        result["error"] = "timestamp consistency failed; no ciphertext association reported"
        return result
    selected = []
    for item in run["udp_trace"][f"udp{index}"]["slowest"]:
        token = item["token"]
        if token not in forward or token not in reverse:
            selected.append({"token": token, "error": "token absent from capture"})
            continue
        client_sent, box_sent, target_received = forward[token]
        target_sent, proxy_sent, box_received = reverse[token]
        selected.append({"token": token, "relative_us": {"client_sent": client_sent, "box_sent": box_sent,
                         "target_received": target_received, "target_sent": target_sent,
                         "proxy_sent": proxy_sent, "box_received": box_received,
                         "client_callback": item["response_at_us"]},
                         "segment_us": {"client_to_box_send": box_sent - client_sent,
                                        "box_to_target": target_received - box_sent,
                                        "target_callback": target_sent - target_received,
                                        "target_to_proxy_send": proxy_sent - target_sent,
                                        "proxy_to_box_send": box_received - proxy_sent,
                                        "box_to_client_callback": item["response_at_us"] - box_received}})
    result["slowest"] = selected
    return result


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: analyze_packet_trace.py RESULT.jsonl CAPTURE.txt")
    lines = pathlib.Path(sys.argv[1]).read_text().splitlines()
    if len(lines) != 1:
        raise ValueError("expected exactly one JSON result")
    run = json.loads(lines[0])
    packets, capture = read_capture(sys.argv[2], run["trace_start_monotonic_ns"])
    result = {"capture": capture, "counts": run["counts"],
              "proxy_loop_stalls": run["proxy_loop_stalls"],
              "proxy_loop_stalls_dropped": run["proxy_loop_stalls_dropped"],
              "harness_loop_stalls": run["harness_loop_stalls"],
              "udp0": analyze(run, packets, 0), "udp1": analyze(run, packets, 1)}
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
