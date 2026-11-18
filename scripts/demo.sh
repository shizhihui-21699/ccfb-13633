#!/bin/bash
# Runs both designs side by side and prints the abuse comparison.
#
# Everything runs unprivileged (the helper uses --simulate), so this is safe to
# run on a laptop. What differs between the runs is not privilege in the demo —
# it is the privilege each design *requires* from its own architecture, which
# the attack matrix in `syncd-redteam` models.
set -euo pipefail

cd "$(dirname "$0")/.."

WORKDIR="$(mktemp -d /tmp/syncd-demo.XXXXXX)"
trap 'kill "${PIDS[@]:-}" 2>/dev/null || true; rm -rf "$WORKDIR"' EXIT
PIDS=()

cargo build --bins --quiet

cat > "$WORKDIR/volumes.txt" <<'EOF'
1b4e28ba-2fa1-11d2-883f-0016d3cca427 /Volumes/Data 1
2b4e28ba-2fa1-11d2-883f-0016d3cca427 /Volumes/Archive 0
EOF

# A small client that speaks the TCP protocol to either server.
cat > "$WORKDIR/client.py" <<'PY'
import socket, struct, sys
def req(op, seq, tail):
    f = bytearray(64); f[0:4]=b'SYNC'; f[4]=1; f[5]=op
    f[8:16]=struct.pack('<Q',seq); f[16:48]=b'\xAB'*32; f[48:64]=tail
    return bytes(f)
port = int(sys.argv[1]); op = int(sys.argv[2]); tail = bytes.fromhex(sys.argv[3]) if len(sys.argv)>3 else b'\0'*16
s = socket.create_connection(("127.0.0.1", port), timeout=3)
s.sendall(req(op, 1, tail)); r = s.recv(32)
names = {0:"Ok",1:"Denied",2:"BadRequest",3:"NotAvailable",4:"Busy",5:"Internal"}
print(f"{names.get(r[4], '?' )} (detail {r[5]})")
PY

DATA=1b4e28ba2fa111d2883f0016d3cca427
ARCHIVE=2b4e28ba2fa111d2883f0016d3cca427
ROW=0000000000000000

echo "############################################################"
echo "# BEFORE: one process, everything privileged"
echo "############################################################"
echo
./target/debug/syncd-monolith --listen 127.0.0.1:17701 --volumes "$WORKDIR/volumes.txt" \
    --store "$WORKDIR/mono-store" >"$WORKDIR/mono.log" 2>&1 &
PIDS+=($!)
sleep 0.6
head -2 "$WORKDIR/mono.log"
echo
echo "A single request reaches the parser and the mounted filesystem in the same"
echo "process, with the same credentials:"
echo -n "  mount allow-listed volume : "; python3 "$WORKDIR/client.py" 17701 1 "$DATA$ROW"
echo -n "  mount non-mountable volume: "; python3 "$WORKDIR/client.py" 17701 1 "$ARCHIVE$ROW"
echo
echo "But the binary itself is designed to run as root, so the compromise is not"
echo "in the request path — it is in the process:"
echo "  * every line of parsing code shares euid 0"
echo "  * arbitrary files, processes and persistence are one function call away"
echo
MONO_PID="${PIDS[0]}"
kill "$MONO_PID" 2>/dev/null; wait "$MONO_PID" 2>/dev/null || true

echo "############################################################"
echo "# AFTER: unprivileged agent + privileged helper"
echo "############################################################"
echo
AGENT_HASH="$(codesign -dvvv target/debug/syncd-agent 2>&1 | awk '/^CandidateCDHash /{print $2}')"
./target/debug/syncd-helper --socket "$WORKDIR/helper.sock" --table "$WORKDIR/volumes.txt" \
    --simulate --decisions --allow-cdhash "$AGENT_HASH" >"$WORKDIR/helper.log" 2>&1 &
PIDS+=($!)
sleep 0.4
./target/debug/syncd-agent --listen 127.0.0.1:17702 --helper "$WORKDIR/helper.sock" \
    --store "$WORKDIR/agent-store" >"$WORKDIR/agent.log" 2>&1 &
PIDS+=($!)
sleep 0.6
cat "$WORKDIR/agent.log"
echo
echo "The same two requests, over the same wire protocol:"
echo -n "  mount allow-listed volume : "; python3 "$WORKDIR/client.py" 17702 1 "$DATA$ROW"
echo -n "  mount non-mountable volume: "; python3 "$WORKDIR/client.py" 17702 1 "$ARCHIVE$ROW"
echo
echo "The helper's own view of who asked, for each exchange:"
sed 's/^/  /' "$WORKDIR/helper.log"
echo
echo "A caller that is NOT the agent is refused before any policy runs. Try it"
echo "with a program the helper has never heard of:"
python3 - "$WORKDIR/helper.sock" <<'PY'
import socket, struct, sys, os
# Connect with the Python interpreter, whose cdhash is not allow-listed.
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(sys.argv[1])
f = bytearray(64); f[0:4]=b'SYNC'; f[4]=1; f[5]=0; f[8:16]=struct.pack('<Q',1)
s.sendall(bytes(f)); r = s.recv(32)
names = {0:"Ok",1:"Denied",2:"BadRequest",3:"NotAvailable",4:"Busy",5:"Internal"}
print(f"  python3 -> {names.get(r[4])} (detail {r[5]}: authentication failure code)")
PY
echo
echo "############################################################"
echo "# Abuse matrix (pure logic, printed by syncd-redteam)"
echo "############################################################"
cargo run -q -p syncd-redteam --bin redteam
