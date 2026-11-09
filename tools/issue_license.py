#!/usr/bin/env python3
"""Vendor-side tool. Keep the private key offline; ship only vendor_public.pem to customers.

  python tools/issue_license.py keygen --out keys/
  python tools/issue_license.py issue --key keys/vendor_private.pem --customer "Acme" --plan trial -o license.rbl
"""
import argparse, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from riskbyte import licensing  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen"); k.add_argument("--out", default="keys")
    i = sub.add_parser("issue")
    i.add_argument("--key", required=True); i.add_argument("--customer", required=True)
    i.add_argument("--plan", choices=sorted(licensing.PLANS), required=True)
    i.add_argument("--endpoints", type=int); i.add_argument("--days", type=int)
    i.add_argument("-o", "--output", default="license.rbl")
    a = ap.parse_args()
    if a.cmd == "keygen":
        os.makedirs(a.out, exist_ok=True)
        priv, pub = licensing.generate_keypair()
        pp = os.path.join(a.out, "vendor_private.pem")
        with os.fdopen(os.open(pp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
            f.write(priv)
        open(os.path.join(a.out, "vendor_public.pem"), "wb").write(pub)
        print(f"wrote {pp} (keep secret) and vendor_public.pem (ship to customers)")
    else:
        text = licensing.issue(open(a.key, "rb").read(), a.customer, a.plan, a.endpoints, a.days)
        open(a.output, "w").write(text)
        print(f"wrote {a.output}")


main()
