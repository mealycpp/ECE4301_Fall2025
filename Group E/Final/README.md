# 🔐 Raspberry Pi Pico Hardware-Backed Sudo Authentication (Ed25519)

This project implements a **hardware-backed authentication system for
Linux `sudo`** using a **Raspberry Pi Pico** as a cryptographic security
token. The Pico performs **Ed25519 digital signatures** over USB, and
Linux verifies those signatures via **PAM (Pluggable Authentication
Modules)** before allowing privileged access.

This creates a **physical root of trust for sudo**: even if a password
is stolen, `sudo` cannot run without the physical Pico device.

------------------------------------------------------------------------

## ✅ Features

-   🔑 **Ed25519 hardware-backed authentication**
-   🔌 USB CDC serial communication (`/dev/ttyACM0`)
-   🧠 **Challenge--response with random nonce** (replay-proof)
-   🛡️ **Private key stored only on the Pico**
-   🗂️ Host stores **public key only**
-   ⏱️ Built-in **timeout failsafe** for PAM
-   🖥️ Works with **VMware Linux VMs**
-   ✅ Stable integration with:
    -   `sudo`
    -   `pam_exec.so`
    -   Python + PyNaCl
    -   Pico C SDK + Monocypher

------------------------------------------------------------------------

## 🧠 System Architecture

User → sudo → PAM → pico_pam.sh → pico_unlock.py → USB → Raspberry Pi
Pico → USB → Host Verification

The Pico **never exposes its private key**.\
The host verifies using the public key at:

    /etc/usb_unlock/pico.pub

------------------------------------------------------------------------

## 🔄 Authentication Protocol

1.  User runs:

    ``` bash
    sudo <command>
    ```

2.  PAM executes:

    ``` bash
    pico_pam.sh
    ```

3.  `pico_unlock.py`:

    -   Generates a **32-byte random nonce**

    -   Sends:

            USB-LOGIN|<username>|<nonce>

4.  Pico:

    -   Signs the message using **Ed25519 private key**
    -   Returns a **64-byte signature**

5.  Host:

    -   Verifies signature with the stored public key
    -   ✅ Valid → `sudo` allowed\
    -   ❌ Invalid → `sudo` blocked

------------------------------------------------------------------------

## 🔑 Cryptography Overview

-   **Algorithm:** Ed25519 (EdDSA over Curve25519)
-   **Key Sizes:**
    -   Public Key: 32 bytes
    -   Private Seed: 32 bytes
    -   Signature: 64 bytes
-   **Security Level:** \~128-bit classical
-   **Signature Type:** Deterministic

------------------------------------------------------------------------

## 📁 Repository Structure

    .
    ├── pico_firmware/
    ├── host/
    ├── pam/
    └── README.md

------------------------------------------------------------------------

## ⚙️ Host Setup

``` bash
sudo apt update
sudo apt install -y python3 python3-pip python3-serial libpam0g-dev
pip3 install pynacl pyserial
```

------------------------------------------------------------------------

## ✅ Test

``` bash
sudo -K
sudo -v
```

  Pico State      Result
  --------------- ----------------
  ✅ Plugged in   `sudo` allowed
  ❌ Unplugged    `sudo` denied

------------------------------------------------------------------------

## 🚀 Future Work

-   🔁 Flash-backed **Ed25519 key rotation**
-   🔐 **X25519 key exchange**
-   🧬 **Dilithium post-quantum signatures**
-   🔏 Encrypted USB transport

------------------------------------------------------------------------

## ⚠️ Safety Notes

-   Always keep a **recovery path** before modifying PAM
-   Never attach experimental scripts to `common-auth`
-   Always use a `timeout` inside PAM scripts

------------------------------------------------------------------------

## 📜 License

This project is for research and educational use.

------------------------------------------------------------------------

## 👤 Author

Developed as a **hardware-backed Linux authentication research
project**.
