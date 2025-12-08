#!/usr/bin/env bash
set -euo pipefail

# usage:
#   sudo ./run_client_netns.sh BINARY_PATH RATE DELAY HOST PORT [extra client args...]

if [[ "$EUID" -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

if [ "$#" -lt 5 ]; then
  echo "usage: $0 BINARY_PATH RATE DELAY HOST PORT [extra client args...]" >&2
  exit 1
fi

BINARY_PATH="$1"
RATE="$2"    # e.g. "8kbit"
DELAY="$3"   # e.g. "25ms"
shift 3      # leave HOST PORT [extra args...] for the client binary

#######################################
# Configurable parameters (env overrides)
#######################################

# Network namespace & veth names
: "${NS_NAME:=rtt_clientns}"
: "${VETH_ROOT:=veth-rtt-root}"
: "${VETH_NS:=veth-rtt-ns}"

# Link characteristics
: "${MTU:=256}"

# L3 addresses on the point-to-point link
# You can override these via environment if you like:
#   NS_ADDR="10.10.0.2/30" GW_ADDR="10.10.0.1" ./run_client_netns.sh ...
: "${NS_ADDR:=10.200.1.2/30}"
: "${GW_ADDR:=10.200.1.1}"

# Netem queue length (in packets). Can be overridden via env.
: "${NETEM_LIMIT_PKTS:=1000}"

cleanup() {
  set +e
  ip netns del "$NS_NAME" 2>/dev/null || true
  ip link del "$VETH_ROOT" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Make sure any stale state is gone
ip netns del "$NS_NAME" 2>/dev/null || true
ip link del "$VETH_ROOT" 2>/dev/null || true

# Create namespace
ip netns add "$NS_NAME"

# Create veth pair
ip link add "$VETH_ROOT" type veth peer name "$VETH_NS"

ip link set dev "$VETH_ROOT" mtu "$MTU"
ip link set dev "$VETH_NS" mtu "$MTU"

ip link set "$VETH_NS" netns "$NS_NAME"

ip link set "$VETH_ROOT" up

# Bring up interfaces inside the namespace
ip netns exec "$NS_NAME" ip link set lo up
ip netns exec "$NS_NAME" ip link set "$VETH_NS" up

# L3 addresses on the point-to-point link between root ns and client ns
ip addr add "${GW_ADDR}/30" dev "$VETH_ROOT"
ip netns exec "$NS_NAME" ip addr add "$NS_ADDR" dev "$VETH_NS"
ip netns exec "$NS_NAME" ip route add default via "$GW_ADDR"

#######################################
# Traffic control: netem (delay + rate)
#######################################

# Root namespace side
tc qdisc add dev "$VETH_ROOT" root handle 1: netem \
  limit "$NETEM_LIMIT_PKTS" delay "$DELAY" rate "$RATE"

# Namespace side
ip netns exec "$NS_NAME" tc qdisc add dev "$VETH_NS" root handle 1: netem \
  limit "$NETEM_LIMIT_PKTS" delay "$DELAY" rate "$RATE"

# Finally, run the client binary inside the namespace
ip netns exec "$NS_NAME" "$BINARY_PATH" "$@"

