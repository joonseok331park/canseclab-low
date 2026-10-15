#!/usr/bin/env bash
set -euo pipefail

elevate=()
if (( EUID != 0 )); then
    elevate=(sudo)
fi

"${elevate[@]}" modprobe vcan
if ip link show dev vcan0 >/dev/null 2>&1; then
    ip -details -json link show dev vcan0 | python3 -c '
import json, sys
links = json.load(sys.stdin)
if (len(links) != 1 or links[0].get("ifname") != "vcan0"
        or links[0].get("linkinfo", {}).get("info_kind") != "vcan"):
    sys.exit("Existing vcan0 is not a virtual CAN interface; no link was changed.")
'
else
    "${elevate[@]}" ip link add dev vcan0 type vcan
fi
"${elevate[@]}" ip link set dev vcan0 up
ip -details -json link show dev vcan0
