BIN_NAME=${BIN_NAME:-rpi-secure-stream}
BIN="$(find /opt/rpisec -type f -path '*/target/release/*' -name "$BIN_NAME" | head -n1)"
test -x "$BIN" || { echo "binary not found"; exit 1; }
"$BIN" \
  --role=leader \
  --mech=ecdh \
  --bind=0.0.0.0:5000 \
  --members-file=/etc/rpisec/members.txt \
  --video-src=v4l2:/dev/video0 \
  --log-csv-dir=/var/log/rpisec \
  --rekey-interval 600
