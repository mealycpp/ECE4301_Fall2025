3 Node DEMO:
https://youtube.com/shorts/0J4BwBcO6Xw
RSA DEMO:
https://youtube.com/shorts/zTQZJj5UTTY
ECDH DEMO:
https://youtube.com/shorts/jws7VQcnI1A


=========================================================================

To run direct secure streaming (2 PI’s)

=========================================================================

Commands to run in terminal to run to get all necessary libraries
sudo apt update
sudo apt full-upgrade -y

sudo apt install -y \
  gstreamer1.0-tools gstreamer1.0-libav \
  gstreamer1.0-plugins-base gstreamer1.0-plugins-good \
  gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly

sudo apt install -y \
  gstreamer1.0-tools gstreamer1.0-libav \
  gstreamer1.0-plugins-base gstreamer1.0-plugins-good \
  gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly 

sudo apt install -y gstreamer1.0-libcamera v4l-utils libcamera-tools

sudo apt install -y clang pkg-config libssl-dev \
  libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev libglib2.0-dev

sudo usermod -aG video "$(whoami)"
newgrp video     # or log out/in

#Install rust on PI if not already installed
curl -fsSL https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
rustup default stable

Test the camera functionality no receive/send video feed just testing
cam -l
GST_DEBUG=2 gst-launch-1.0 -v \
  libcamerasrc ! video/x-raw,format=NV12,width=640,height=480,framerate=15/1 ! \
  fakesink sync=false
#Above should return sometime of a timer increasing in number

Need to run these 2 after to reset and kill current cam operation
pkill -f 'gst-launch-1.0.*libcamerasrc'
pkill -f 'rpi-secure-stream.*--payload=video'


Open which encryption method you want from Files(RSA or ECDH)
For self streaming test:
#Put this one in the first terminal
cargo run -p app --release -- \
  --mode=receiver --bind 127.0.0.1:5000 --payload=video --fps 15

#Put this one in the second terminal below
cargo run -p app --release -- \
  --mode=sender --host 127.0.0.1:5000 --payload=video \
  --device libcamera --width 640 --height 480 --fps 15 --rekey 10s
#Should see video footage streaming to yourself from the camera

Need to run these 2 after to reset and kill current cam operation
pkill -f 'gst-launch-1.0.*libcamerasrc'
pkill -f 'rpi-secure-stream.*--payload=video'

To set addresses of each PI’s
sudo nmcli con add type ethernet ifname eth0 con-name p2p-eth \
  ipv4.method manual ipv4.addresses 10.42.0.1/30 ipv4.never-default yes \
  ipv6.method ignore autoconnect yes
sudo nmcli con up p2p-eth

sudo nmcli con add type ethernet ifname eth0 con-name p2p-eth \
  ipv4.method manual ipv4.addresses 10.42.0.2/30 ipv4.never-default yes \
  ipv6.method ignore autoconnect yes
sudo nmcli con up p2p-eth

For direct send/receive mode(Only 2 PIs)
#Receive mode
#Assuming your ip = 10.42.0.1, neigbor1_ip=10.42.0.2
cargo run --bin rpi-secure-stream -- --mode=receiver --payload=video --bind 10.42.0.1:5000 --fps 30 --metrics-dir ./metrics/recv

#Send mode with rekey
#Assuming your ip = 10.42.0.2, neigbor1_ip=10.42.0.1
cargo run --bin rpi-secure-stream -- --mode=sender --payload=video   --host 10.42.01:5000 --device libcamera --width 1280 --height 720   --fps 30 --rekey 10s --metrics-dir ./metrics/sender

#run it again in a another terminal window in each pi with the roles and addresses reversed to send video from the second pi to the first pi.

Need to run these 2 after to reset and kill current cam operation
pkill -f 'gst-launch-1.0.*libcamerasrc'
pkill -f 'rpi-secure-stream.*--payload=video'


=========================================================================

To run 3 node secure streaming

=========================================================================

Open up the 3node Folder and enter its directory in terminal

Run these 1 of 3 command from below in the terminal of each Pi to set addresses to each
sudo nmcli con add type ethernet ifname eth0 con-name p2p-eth \
  ipv4.method manual ipv4.addresses 10.42.0.1/30 ipv4.never-default yes \
  ipv6.method ignore autoconnect yes
sudo nmcli con up p2p-eth

sudo nmcli con add type ethernet ifname eth0 con-name p2p-eth \
  ipv4.method manual ipv4.addresses 10.42.0.2/30 ipv4.never-default yes \
  ipv6.method ignore autoconnect yes
sudo nmcli con up p2p-eth

sudo nmcli con add type ethernet ifname eth0 con-name p2p-eth \
  ipv4.method manual ipv4.addresses 10.42.0.3/30 ipv4.never-default yes \
  ipv6.method ignore autoconnect yes
sudo nmcli con up p2p-eth

Type this in terminal to see ip ethernet address
ip addr

Build all 3 pi’s files
cargo build --release

Run this command in each terminal
#Assuming your ip = 10.42.0.1, neigbor1_ip=10.42.0.2, neighbor2_ip = 10.42.03
./target/release/rpi-secure-stream --mode=mesh --bind 10.42.0.1:5000 --peer 10.42.0.2:5000 --peer 10.42.0.3:5000 --metrics-dir /home/pi/metrics/pi1 --payload video
#Put your own address for --bind and your neighbors’ addresses for --peer

Run this command to end
pkill -f rpi-secure-stream
