#!/usr/bin/env python3
import sys, serial
from nacl.signing import VerifyKey
from nacl.utils import random
from nacl.exceptions import BadSignatureError

PK_PATH = "/etc/usb_unlock/pico.pub"
DEV = "/dev/ttyACM0"

def main():
    if len(sys.argv) < 2:
        print("usage: pico_unlock.py <username>", file=sys.stderr)
        return 1

    user = sys.argv[1]

    with open(PK_PATH) as f:
        pk = VerifyKey(bytes.fromhex(f.read().strip()))

    nonce = random(32)
    msg = b"USB-LOGIN|" + user.encode() + b"|" + nonce

    ser = serial.Serial(DEV, 115200, timeout=3)
    ser.write(msg + b"\n")
    ser.flush()

    sig_hex = ser.readline().strip()
    if not sig_hex:
        print("No response from Pico", file=sys.stderr)
        return 1

    try:
        sig = bytes.fromhex(sig_hex.decode())
        pk.verify(msg, sig)
        return 0
    except (ValueError, BadSignatureError):
        print("Signature verification failed", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
