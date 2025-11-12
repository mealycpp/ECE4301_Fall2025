# Change Peer addresses to be specific

# Node A listens on 10.0.0.1:5000; it will connect to node B and C
./target/release/rpi-secure-stream --mode=mesh \
  --bind 10.42.0.1:5000 \
  --peer 10.42.0.2:5000 \
  --peer 10.42.0.3:5000 \
  --metrics-dir /home/pi/metrics/pi1 \
  --payload video
