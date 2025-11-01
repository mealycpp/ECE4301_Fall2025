LEADER_ADDR=192.168.1.20:5000   # <-- set to leader IP:port
BIN_NAME=${BIN_NAME:-rpi-secure-stream}
BIN="$(find /opt/rpisec -type f -path '*/target/release/*' -name "$BIN_NAME" | head -n1)"
test -x "$BIN" || { echo "binary not found"; exit 1; }
"$BIN" \
  --role=member \
  --mech=ecdh \
  --leader="$LEADER_ADDR" \
  --bind=0.0.0.0:5001 \
  --video-src=v4l2:/dev/video0 \
  --log-csv-dir=/var/log/rpisec \
  --rekey-interval 600
