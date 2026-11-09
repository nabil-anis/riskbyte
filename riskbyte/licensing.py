"""Offline-verifiable licenses: a payload signed with the vendor's Ed25519 key. The customer holds only the public key."""
from __future__ import annotations
import base64, json, os, time
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

GRACE_DAYS = 7
PLANS = {  # endpoints 0 = unlimited
    "trial": {"endpoints": 25, "days": 14},
    "team": {"endpoints": 250, "days": 365},
    "business": {"endpoints": 2500, "days": 365},
    "enterprise": {"endpoints": 0, "days": 365},
}


class LicenseError(Exception):
    pass


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical(d: dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def generate_keypair():
    k = Ed25519PrivateKey.generate()
    priv = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    pub = k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv, pub


def issue(priv_pem: bytes, customer: str, plan: str, endpoints=None, days=None, now=None) -> str:
    if plan not in PLANS:
        raise LicenseError(f"unknown plan {plan!r}")
    now = now or time.time()
    payload = {"customer": customer, "plan": plan,
               "endpoints": PLANS[plan]["endpoints"] if endpoints is None else int(endpoints),
               "issued": int(now), "expires": int(now + 86400 * (days or PLANS[plan]["days"]))}
    key = serialization.load_pem_private_key(priv_pem, None)
    return _b64(canonical(payload)) + "." + _b64(key.sign(canonical(payload)))


def verify(text: str, pub_pem: bytes) -> dict:
    try:
        p, s = text.strip().split(".")
        payload, sig = _unb64(p), _unb64(s)
        serialization.load_pem_public_key(pub_pem).verify(sig, payload)
        data = json.loads(payload)
    except (ValueError, InvalidSignature, TypeError) as exc:
        raise LicenseError("license signature is invalid") from exc
    if not {"customer", "plan", "endpoints", "expires"} <= set(data):
        raise LicenseError("license payload is incomplete")
    return data


class LicenseManager:
    def __init__(self, path: str, pubkey_path: str, dev_mode: bool = False):
        self.path, self.pubkey_path, self.dev = path, pubkey_path, dev_mode

    def status(self, hosts_seen_24h: int = 0, now=None) -> dict:
        now = now or time.time()
        if self.dev:
            return self._s("dev", "Developer mode: license checks bypassed.", True, True)
        try:
            with open(self.pubkey_path, "rb") as f:
                pub = f.read()
            with open(self.path, "r", encoding="utf-8") as f:
                lic = verify(f.read(), pub)
        except FileNotFoundError:
            return self._s("unlicensed", "No license found. Start a trial or install a license file.", False, False)
        except LicenseError as exc:
            return self._s("invalid", str(exc), False, False)
        exp = lic["expires"]
        limit = int(lic["endpoints"])
        info = {"customer": lic["customer"], "plan": lic["plan"], "endpoints": limit, "expires": exp,
                "days_left": round((exp - now) / 86400, 1), "hosts_seen_24h": hosts_seen_24h}
        if now <= exp:
            st, msg, tri, app = "active", "License active.", True, True
        elif now <= exp + GRACE_DAYS * 86400:
            st, msg, tri, app = "grace", "License expired: read-only grace period. Renew to restore triage and response.", False, False
        else:
            st, msg, tri, app = "expired", "License expired. Triage and response are paused; ingestion continues.", False, False
        if limit and hosts_seen_24h > limit:
            msg += f" Warning: {hosts_seen_24h} hosts seen, licensed for {limit}."
            if hosts_seen_24h > limit * 1.1:
                tri = False
                msg += " Triage paused until the endpoint count is back within the limit."
        return self._s(st, msg, tri, app, info)

    @staticmethod
    def _s(state, message, can_triage, can_approve, info=None):
        d = {"state": state, "message": message, "can_triage": can_triage, "can_approve": can_approve}
        d.update(info or {})
        return d
