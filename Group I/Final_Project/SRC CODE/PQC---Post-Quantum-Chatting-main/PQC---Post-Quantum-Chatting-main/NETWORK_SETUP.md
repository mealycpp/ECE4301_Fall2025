# Static Network Setup for PQC Chat - 3 Raspberry Pi 5s

This guide will help you set up a static network for your 3 Raspberry Pi 5s connected via ethernet to a switch, and configure the PQC Chat program to work across the network.

## Dual Network Support

This setup supports **dual network configuration**:
- **Ethernet (eth0)**: Static IP for PQC Chat communication (192.168.10.x/24)
- **WLAN (wlan0)**: DHCP for internet access (separate subnet)

The configurations are designed to work together without interference.

## Network Topology

```
                    ┌─────────────────┐
                    │  Internet/WLAN  │
                    │ (192.168.1.x)   │
                    └─────────┬───────┘
                              │ WiFi
            ┌─────────────────┼─────────────────┐
            │                 │                 │
┌───────────┴─────────┐ ┌─────┴─────────┐ ┌─────┴─────────┐
│   Raspberry Pi 1    │ │   Raspberry Pi 2│ │   Raspberry Pi 3│
│   (SERVER)          │ │   (CLIENT 1)    │ │   (CLIENT 2)    │
│ eth0: 192.168.10.101│ │eth0: 192.168.10.102│ │eth0: 192.168.10.103│
│ wlan0: DHCP         │ │wlan0: DHCP      │ │wlan0: DHCP      │
└──────┬──────────────┘ └──────┬──────────┘ └──────┬──────────┘
       │                       │                   │
       └───────────────────────┼───────────────────┘
                               │
                    ┌──────────┴──────────┐
                    │   Ethernet Switch   │
                    │ (PQC Chat Network)  │
                    └─────────────────────┘
```

## Step 1: Configure Static IPs on Each Raspberry Pi

On **each** Raspberry Pi, you need to configure a static IP address.

**First, check which network management system your Pi uses:**
```bash
# Check if NetworkManager is running (most likely on Pi 5)
nmcli connection show

# If NetworkManager is not available, check for systemd-networkd
systemctl status systemd-networkd
```

### Method 1: Using NetworkManager (Most common on Raspberry Pi 5)

**First, check current connections:**
```bash
nmcli connection show
```

Configure each Pi with NetworkManager:

**For Pi 1 (Server - 192.168.10.101):**
```bash
# Configure ethernet for static IP
sudo nmcli connection modify eth0 ipv4.method manual ipv4.addresses 192.168.10.101/24 ipv4.dns "8.8.8.8,8.8.4.4" ipv4.route-metric 200

# Configure WiFi for internet (lower metric = higher priority)
# Replace "YourWiFiName" with your actual WiFi connection name from nmcli connection show
sudo nmcli connection modify "YourWiFiName" ipv4.route-metric 100

# Enable auto-connect on boot (IMPORTANT!)
sudo nmcli connection modify eth0 connection.autoconnect yes

# Apply changes
sudo nmcli connection down eth0 && sudo nmcli connection up eth0
```

**For Pi 2 (Client 1 - 192.168.10.102):**
```bash
# Configure ethernet for static IP
sudo nmcli connection modify eth0 ipv4.method manual ipv4.addresses 192.168.10.102/24 ipv4.dns "8.8.8.8,8.8.4.4" ipv4.route-metric 200

# Configure WiFi for internet (lower metric = higher priority)
# Replace "YourWiFiName" with your actual WiFi connection name from nmcli connection show
sudo nmcli connection modify "YourWiFiName" ipv4.route-metric 100

# Enable auto-connect on boot (IMPORTANT!)
sudo nmcli connection modify eth0 connection.autoconnect yes

# Apply changes
sudo nmcli connection down eth0 && sudo nmcli connection up eth0
```

**For Pi 3 (Client 2 - 192.168.10.103):**
```bash
# Configure ethernet for static IP
sudo nmcli connection modify eth0 ipv4.method manual ipv4.addresses 192.168.10.103/24 ipv4.dns "8.8.8.8,8.8.4.4" ipv4.route-metric 200

# Configure WiFi for internet (lower metric = higher priority)
# Replace "YourWiFiName" with your actual WiFi connection name from nmcli connection show
sudo nmcli connection modify "YourWiFiName" ipv4.route-metric 100

# Enable auto-connect on boot (IMPORTANT!)
sudo nmcli connection modify eth0 connection.autoconnect yes

# Apply changes
sudo nmcli connection down eth0 && sudo nmcli connection up eth0
```

### Method 2: Using systemd-networkd (Alternative method)

If your Raspberry Pi uses systemd-networkd instead of NetworkManager:

1. **Create ethernet network configuration file:**

```bash
sudo nano /etc/systemd/network/10-eth0.network
```

2. **For each Pi, use the appropriate IP configuration:**

```ini
# Pi 1: 192.168.10.101, Pi 2: 192.168.10.102, Pi 3: 192.168.10.103
[Match]
Name=eth0

[Network]
DHCP=no
Address=192.168.10.XXX/24  # Replace XXX with 101, 102, or 103
DNS=8.8.8.8
DNS=8.8.4.4

[Route]
Destination=192.168.10.0/24
Gateway=0.0.0.0
Metric=100
```

3. **Create WLAN configuration:**

```bash
sudo nano /etc/systemd/network/20-wlan0.network
```

```ini
[Match]
Name=wlan0

[Network]
DHCP=yes
```

4. **Enable systemd-networkd:**
```bash
sudo systemctl enable systemd-networkd
sudo systemctl start systemd-networkd
sudo systemctl disable dhcpcd
```

### Method 3: Using dhcpcd (Legacy method)

If your Raspberry Pi OS still uses dhcpcd, edit `/etc/dhcpcd.conf`:

```bash
sudo nano /etc/dhcpcd.conf
```

Add at the end for each Pi respectively:

**For Pi 1 (Server):**
```
# Ethernet interface for PQC Chat (no default gateway)
interface eth0
static ip_address=192.168.10.101/24
# Note: No static routers line - WLAN will provide default route
static domain_name_servers=8.8.8.8 8.8.4.4
metric 200

# WLAN interface for internet (DHCP with higher priority)
interface wlan0
metric 100
```

**For Pi 2 (Client 1):**
```
# Ethernet interface for PQC Chat (no default gateway)
interface eth0
static ip_address=192.168.10.102/24
# Note: No static routers line - WLAN will provide default route
static domain_name_servers=8.8.8.8 8.8.4.4
metric 200

# WLAN interface for internet (DHCP with higher priority)
interface wlan0
metric 100
```

**For Pi 3 (Client 2):**
```
# Ethernet interface for PQC Chat (no default gateway)
interface eth0
static ip_address=192.168.10.103/24
# Note: No static routers line - WLAN will provide default route
static domain_name_servers=8.8.8.8 8.8.4.4
metric 200

# WLAN interface for internet (DHCP with higher priority)
interface wlan0
metric 100
```

## Step 2: Configure WiFi (if using dual network setup)

If you want internet access via WLAN alongside the PQC Chat ethernet network:

1. **Connect to WiFi (on each Pi):**
```bash
sudo raspi-config
# Network Options → Wireless LAN → Enter SSID and passphrase
```

Or manually configure:
```bash
sudo nano /etc/wpa_supplicant/wpa_supplicant.conf
```

Add your WiFi network:
```
network={
    ssid="Your_WiFi_Network"
    psk="your_wifi_password"
}
```

## Step 3: Apply Network Configuration

After configuring both ethernet and WiFi on all three Pis:

1. **Reboot each Pi:**
```bash
sudo reboot
```

2. **Verify dual network configuration on each Pi:**
```bash
# Check both interfaces
ip addr show eth0     # Should show 192.168.10.x
ip addr show wlan0    # Should show WiFi IP (e.g., 192.168.1.x)

# Test PQC Chat network connectivity
ping 192.168.10.101   # Test connectivity to server
ping 192.168.10.102   # Test connectivity to client 1  
ping 192.168.10.103   # Test connectivity to client 2

# Test internet connectivity via WiFi
ping google.com       # Should work via WLAN

# Check routing table
ip route show         # WLAN should have default route
```

## Step 3: Configure Hostnames (Optional but Recommended)

On each Pi, set a unique hostname and add all Pis to the hosts file:

**For Pi 1 (Server):**
```bash
sudo hostnamectl set-hostname pqc-server
```

**For Pi 2 (Client 1):**
```bash
sudo hostnamectl set-hostname pqc-client1
```

**For Pi 3 (Client 2):**
```bash
sudo hostnamectl set-hostname pqc-client2
```

**On all Pis, add to `/etc/hosts`:**
```bash
sudo nano /etc/hosts
```

Add these lines:
```
192.168.10.101  pqc-server
192.168.10.102  pqc-client1
192.168.10.103  pqc-client2
```

## Step 4: Test Network Connectivity

From each Pi, test connectivity:

```bash
# Test from any Pi
ping pqc-server     # Should ping 192.168.10.101
ping pqc-client1    # Should ping 192.168.10.102
ping pqc-client2    # Should ping 192.168.10.103
```

## Dual Network Configuration Details

### Key Points for Ethernet + WLAN Setup:

- **Ethernet (eth0)**: Static IP for PQC Chat (192.168.10.0/24 subnet)
- **WLAN (wlan0)**: DHCP for internet access (typically 192.168.1.0/24 or similar)
- **Routing**: WLAN gets default gateway for internet, ethernet routes PQC Chat traffic
- **Metrics**: WLAN has higher priority (lower metric) for internet traffic

### Why This Works:

1. **Separate subnets**: 192.168.10.x (ethernet) vs 192.168.1.x (WLAN) don't conflict
2. **Traffic routing**: PQC Chat traffic (192.168.10.x) stays on ethernet
3. **Internet traffic**: Routes through WLAN default gateway
4. **No interference**: Each interface handles its designated traffic

### Subnet Selection:

- **PQC Chat**: Using 192.168.10.0/24 (adjust if conflicts with your WLAN)
- **WLAN**: Usually 192.168.1.0/24 or 192.168.0.0/24 (depends on your router)
- **DNS**: Using Google DNS (8.8.8.8, 8.8.4.4) available on both networks

## Notes

- **Switch**: Make sure your ethernet switch supports the speeds/features you need
- **Cables**: Use quality ethernet cables (Cat 5e or Cat 6)
- **WiFi Performance**: May affect overall bandwidth if sharing internet during video chat

## Troubleshooting

### General Network Issues

1. **If network doesn't work after reboot:**
   - Check cable connections
   - Verify switch is powered and working
   - Check if static IP configuration was applied correctly

2. **Test connectivity step by step:**
   ```bash
   # Check both interfaces are up
   ip link show eth0
   ip link show wlan0
   
   # Check IP addresses are assigned
   ip addr show eth0    # Should show 192.168.10.x
   ip addr show wlan0   # Should show WLAN IP
   
   # Check routing table
   ip route show
   # Look for:
   # - Default route via WLAN gateway
   # - 192.168.10.0/24 route via eth0
   
   # Test layer 2 connectivity (if you have arp-scan)
   sudo arp-scan -I eth0 192.168.10.0/24
   ```

### Dual Network Specific Issues

3. **If PQC Chat can't connect but internet works:**
   ```bash
   # Test ethernet connectivity specifically
   ping -I eth0 192.168.10.101
   
   # Check if PQC Chat ports are accessible
   nc -zv 192.168.10.101 8443
   
   # Verify routing for PQC Chat subnet
   ip route get 192.168.10.101
   ```

4. **If internet doesn't work but PQC Chat does:**
   ```bash
   # Check WLAN connection
   iwconfig wlan0
   
   # Test DNS resolution
   nslookup google.com
   
   # Check default gateway
   ip route show default
   
   # Test internet via WLAN specifically
   ping -I wlan0 8.8.8.8
   ```

5. **If both networks interfere with each other:**
   ```bash
   # Check for IP conflicts
   ip addr show | grep "192.168"
   
   # Verify metric priorities
   ip route show | grep metric
   
   # Check for duplicate gateways
   ip route show default
   ```

### Revert to Single Network

6. **If you need to revert to ethernet-only (DHCP):**
   ```bash
   sudo systemctl enable dhcpcd
   sudo systemctl disable systemd-networkd
   sudo rm /etc/systemd/network/10-eth0.network
   sudo rm /etc/systemd/network/20-wlan0.network
   sudo reboot
   ```

7. **If you need to disable WLAN temporarily:**
   ```bash
   sudo ifdown wlan0
   # Or permanently:
   echo 'dtoverlay=disable-wifi' | sudo tee -a /boot/config.txt
   ```

Once the network is configured and working, proceed to configure the PQC Chat application with the server on Pi 1 and clients on Pi 2 and 3.