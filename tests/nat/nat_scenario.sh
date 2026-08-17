#!/usr/bin/env bash
# Linux network-namespace NAT scenario for TunnelMate.
#
# Topology:
#
#   [ peer ns ]            [ broker/router ns ]              [ private ns ]
#   198.51.100.2  <--->  198.51.100.1 | 10.10.0.1  <--->  10.10.0.2
#     "Internet"              "the VPS"                 "behind CGNAT"
#
# The private namespace can reach the broker outbound, but the peer namespace
# has no route to 10.10.0.0/24 at all. That is the whole point: the only way in
# is the tunnel the agent dials out.
#
# Requires root. Run: sudo tests/nat/nat_scenario.sh [build-dir]

set -euo pipefail

BUILD_DIR="${1:-${TUNNELMATE_BUILD_DIR:-build}}"
BUILD_DIR="$(cd "$BUILD_DIR" && pwd)"
BROKER_BIN="$BUILD_DIR/broker/tunnelmated"
AGENT_BIN="$BUILD_DIR/agent/tunnelmate-agent"

NS_PEER=tm-peer
NS_VPS=tm-vps
NS_PRIV=tm-priv
RUN=/tmp/tunnelmate-nat.$$
CONTROL_PORT=7000
PUBLIC_START=24100
PUBLIC_END=24110

log() { printf '\n=== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

drop_namespaces() {
    for ns in "$NS_PEER" "$NS_VPS" "$NS_PRIV"; do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
        ip netns del "$ns" 2>/dev/null || true
    done
}

cleanup() {
    drop_namespaces
    rm -rf "$RUN"
}

[ "$(id -u)" -eq 0 ] || fail "must run as root (network namespaces)"
[ -x "$BROKER_BIN" ] || fail "missing $BROKER_BIN"
[ -x "$AGENT_BIN" ] || fail "missing $AGENT_BIN"

log "building namespaces"
# Clear any leftovers from an interrupted previous run *before* creating this
# run's directory, so the pre-clean cannot delete what we are about to write.
drop_namespaces
trap cleanup EXIT

mkdir -p "$RUN"
chmod 700 "$RUN"

ip netns add "$NS_PEER"
ip netns add "$NS_VPS"
ip netns add "$NS_PRIV"

# public link: peer <-> vps
ip link add veth-pub type veth peer name veth-pub-vps
ip link set veth-pub netns "$NS_PEER"
ip link set veth-pub-vps netns "$NS_VPS"
ip netns exec "$NS_PEER" ip addr add 198.51.100.2/24 dev veth-pub
ip netns exec "$NS_VPS" ip addr add 198.51.100.1/24 dev veth-pub-vps
ip netns exec "$NS_PEER" ip link set veth-pub up
ip netns exec "$NS_VPS" ip link set veth-pub-vps up
ip netns exec "$NS_PEER" ip link set lo up
ip netns exec "$NS_VPS" ip link set lo up

# private link: vps <-> private (the NAT'd side)
ip link add veth-priv type veth peer name veth-priv-vps
ip link set veth-priv netns "$NS_PRIV"
ip link set veth-priv-vps netns "$NS_VPS"
ip netns exec "$NS_PRIV" ip addr add 10.10.0.2/24 dev veth-priv
ip netns exec "$NS_VPS" ip addr add 10.10.0.1/24 dev veth-priv-vps
ip netns exec "$NS_PRIV" ip link set veth-priv up
ip netns exec "$NS_VPS" ip link set veth-priv-vps up
ip netns exec "$NS_PRIV" ip link set lo up

# The private side routes outbound through the VPS and is masqueraded, exactly
# like a host behind CGNAT. The peer side gets no route inward.
ip netns exec "$NS_PRIV" ip route add default via 10.10.0.1
ip netns exec "$NS_VPS" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "$NS_VPS" iptables -t nat -A POSTROUTING -s 10.10.0.0/24 -j MASQUERADE
# Explicitly refuse any inbound attempt from the public side to the private net.
ip netns exec "$NS_VPS" iptables -A FORWARD -i veth-pub-vps -d 10.10.0.0/24 -j DROP

log "generating broker certificate"
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$RUN/broker.key" -out "$RUN/broker.crt" -days 1 \
    -subj "/CN=broker.tunnelmate.test" \
    -addext "subjectAltName=DNS:broker.tunnelmate.test,IP:198.51.100.1,IP:10.10.0.1" \
    >/dev/null 2>&1
chmod 600 "$RUN/broker.key"

cat > "$RUN/broker.conf" <<EOF
broker.listen_host = 0.0.0.0
broker.control_port = $CONTROL_PORT
broker.public_port_start = $PUBLIC_START
broker.public_port_end = $PUBLIC_END
broker.tls_cert = $RUN/broker.crt
broker.tls_key = $RUN/broker.key
broker.hmac_key_file = $RUN/hmac.key
broker.broker_socket = $RUN/broker.sock
broker.log_level = debug
EOF

log "starting private services (behind NAT)"
# TCP echo service, private namespace only.
ip netns exec "$NS_PRIV" python3 -c '
import socketserver
class H(socketserver.BaseRequestHandler):
    def handle(self):
        while d := self.request.recv(65536):
            self.request.sendall(b"tcp:" + d)
s = socketserver.ThreadingTCPServer(("10.10.0.2", 5001), H)
s.daemon_threads = True
s.serve_forever()
' >"$RUN/tcp-service.log" 2>&1 &

# UDP echo service, private namespace only.
ip netns exec "$NS_PRIV" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.10.0.2", 5002))
while True:
    data, addr = s.recvfrom(65535)
    s.sendto(b"udp:" + data, addr)
' >"$RUN/udp-service.log" 2>&1 &
sleep 1

log "starting broker on the VPS namespace"
ip netns exec "$NS_VPS" "$BROKER_BIN" -c "$RUN/broker.conf" \
    >"$RUN/broker.log" 2>&1 &
for _ in $(seq 50); do [ -S "$RUN/broker.sock" ] && break; sleep 0.1; done
[ -S "$RUN/broker.sock" ] || { cat "$RUN/broker.log"; fail "broker did not start"; }

ipc() {
    ip netns exec "$NS_VPS" python3 -c '
import json, socket, sys
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
s.sendall((sys.argv[2] + "\n").encode())
data = b""
while not data.endswith(b"\n"):
    data += s.recv(65536)
print(data.decode().strip())
' "$RUN/broker.sock" "$1"
}

log "proving the Internet side cannot reach the private host directly"
if ip netns exec "$NS_PEER" timeout 3 bash -c \
        "echo probe > /dev/tcp/10.10.0.2/5001" 2>/dev/null; then
    fail "the peer namespace reached the private TCP service directly"
fi
echo "  direct TCP to 10.10.0.2:5001 refused, as required"

if ip netns exec "$NS_PEER" python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
try:
    s.sendto(b"probe", ("10.10.0.2", 5002))
    s.recvfrom(4096)
except Exception:
    sys.exit(1)
sys.exit(0)
' 2>/dev/null; then
    fail "the peer namespace reached the private UDP service directly"
fi
echo "  direct UDP to 10.10.0.2:5002 unanswered, as required"

log "creating tunnels and starting agents (outbound only)"
TCP_JSON="$(ipc '{"op":"create_tunnel","tunnel_id":"nat-tcp","proto":"tcp","closed":false}')"
UDP_JSON="$(ipc '{"op":"create_tunnel","tunnel_id":"nat-udp","proto":"udp","closed":false}')"

read_field() { python3 -c "import json,sys;print(json.loads(sys.argv[1])[sys.argv[2]])" "$1" "$2"; }
TCP_PORT="$(read_field "$TCP_JSON" public_port)"
TCP_SECRET="$(read_field "$TCP_JSON" agent_secret)"
UDP_PORT="$(read_field "$UDP_JSON" public_port)"
UDP_SECRET="$(read_field "$UDP_JSON" agent_secret)"

for spec in "tcp $TCP_PORT $TCP_SECRET 5001" "udp $UDP_PORT $UDP_SECRET 5002"; do
    set -- $spec
    cat > "$RUN/agent-$1.conf" <<EOF
agent.tunnel_id = nat-$1
agent.agent_secret = $3
agent.local_host = 10.10.0.2
agent.local_port = $4
agent.broker_host = 10.10.0.1
agent.broker_port = $CONTROL_PORT
agent.broker_udp_port = $2
agent.protocol = $1
agent.verify_ca = false
agent.log_level = debug
EOF
    chmod 600 "$RUN/agent-$1.conf"
    ip netns exec "$NS_PRIV" "$AGENT_BIN" -c "$RUN/agent-$1.conf" \
        >"$RUN/agent-$1.log" 2>&1 &
done

for _ in $(seq 100); do
    if ipc '{"op":"get_tunnels"}' | grep -q '"agent_online":true'; then break; fi
    sleep 0.2
done
echo "  agents registered from behind NAT: $(ipc '{"op":"get_tunnels"}' | grep -o '"agent_online":true' | wc -l)/2"

log "reaching the private services through TunnelMate"
TCP_RESULT="$(ip netns exec "$NS_PEER" python3 -c '
import socket, sys
with socket.create_connection(("198.51.100.1", int(sys.argv[1])), timeout=10) as c:
    c.settimeout(10)
    c.sendall(b"hello-through-nat")
    print(c.recv(4096).decode())
' "$TCP_PORT")"
[ "$TCP_RESULT" = "tcp:hello-through-nat" ] || fail "TCP through tunnel returned '$TCP_RESULT'"
echo "  TCP via 198.51.100.1:$TCP_PORT -> '$TCP_RESULT'"

UDP_RESULT="$(ip netns exec "$NS_PEER" python3 -c '
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
deadline = time.time() + 20
while time.time() < deadline:
    s.sendto(b"hello-datagram", ("198.51.100.1", int(sys.argv[1])))
    try:
        data, _ = s.recvfrom(65535)
        print(data.decode())
        break
    except TimeoutError:
        continue
' "$UDP_PORT")"
[ "$UDP_RESULT" = "udp:hello-datagram" ] || fail "UDP through tunnel returned '$UDP_RESULT'"
echo "  UDP via 198.51.100.1:$UDP_PORT -> '$UDP_RESULT'"

log "verifying UDP datagram boundaries survive the NAT path"
BOUNDARY="$(ip netns exec "$NS_PEER" python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
port = int(sys.argv[1])
sizes = []
for size in (1, 57, 256, 1200):
    s.sendto(b"z" * size, ("198.51.100.1", port))
    data, _ = s.recvfrom(65535)
    sizes.append(len(data) - 4)   # strip the "udp:" prefix the service adds
print(",".join(str(n) for n in sizes))
' "$UDP_PORT")"
[ "$BOUNDARY" = "1,57,256,1200" ] || fail "datagram boundaries changed: $BOUNDARY"
echo "  datagram sizes preserved: $BOUNDARY"

log "PASS: NAT traversal works for TCP and UDP, direct access stays blocked"
