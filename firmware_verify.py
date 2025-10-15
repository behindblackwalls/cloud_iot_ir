#!/usr/bin/env python3
import argparse, sys
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pubkey", required=True)
    ap.add_argument("--fw", required=True)
    ap.add_argument("--sig", required=True, help="DER-encoded signature")
    args = ap.parse_args()

    pub = load_pem_public_key(open(args.pubkey,"rb").read())
    firmware = open(args.fw,"rb").read()
    sig = open(args.sig,"rb").read()

    try:
        pub.verify(sig, firmware, ec.ECDSA(hashes.SHA256()))
        print("Signature OK (ECDSA P-256 / SHA-256)")
    except Exception as e:
        print(f"Signature verification FAILED: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
