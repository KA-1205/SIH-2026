#!/usr/bin/env python3
"""SIH26145 — TLS-malware detector (JA4-lite).   [PROTOTYPE]

Fingerprints the TLS ClientHello observed on the monitor-side tap without ever
decrypting traffic. The fingerprint captures TLS version, cipher-suite list
length/shape and extension list length — the parts of the hello that are
cheaply observable through a one-way lens.

STATUS — explicit prototype, by design:
  * It can only fire via the raw tap for TCP:443 (the UDP relay never carries
    TLS), so the mirror must actually face ClientHellos.
  * A rare fingerprint is evidence, not guilt: without a JA3/JA4 bad-list a
    first-seen fingerprint cannot be called malware. Therefore this detector
    NEVER raises an alert on its own (score is capped at 0). It contributes
    borderline evidence so the fusion gate can weigh it when other strands are
    present, and the coverage panel marks it PROTOTYPE.
Change this file's POLICY only after auditing mirror direction AND obtaining a
threat-intel list (e.g. JA3DB) for validation.
"""
from __future__ import annotations

import struct

NAME = "tls_malware"
THREAT_CLASS = "tls_malware"

PORT_TLS = 443


def parse_client_hello(payload: bytes) -> dict | None:
    """Minimal ClientHello extractor following the real TLS wire layout:

        TLS record:  [22][0x03 xx][len2]
        handshake:   [1=ClientHello][len3][legacy_version2][random32]
                     [sid_len1][sid...][cipher_len2][ciphers...][ext_len2]...

    Returns None when the bytes are not a well-formed ClientHello fragment.
    """
    try:
        if len(payload) < 9 or payload[0] != 0x16:       # not TLS handshake rec
            return None
        rec_len = struct.unpack(">H", payload[3:5])[0]
        body = payload[5:5 + rec_len]
        if len(body) < 4 or body[0] != 0x01:             # not ClientHello
            return None
        hs_len = (body[1] << 16) | (body[2] << 8) | body[3]
        tail = body[4:4 + hs_len]
        if len(tail) < 38:                               # ver(2)+random(32)+sid(1)
            return None
        ver = struct.unpack(">H", tail[0:2])[0]
        sid_len = tail[34]
        cs_off = 35 + sid_len
        if len(tail) < cs_off + 2:
            return None
        cs_len = struct.unpack(">H", tail[cs_off:cs_off + 2])[0]
        ext_off = cs_off + 2 + cs_len
        cs_count = cs_len // 2
        ext_count = 0
        if len(tail) >= ext_off + 2:
            ext_len = struct.unpack(">H", tail[ext_off:ext_off + 2])[0]
            ext_count = max(0, (ext_len - 2) // 4)       # rough, sizes vary
        return {"tls_version": f"0x{ver:04x}",
                "cipher_count": cs_count, "ext_count": ext_count}
    except Exception:                                    # noqa: BLE001
        return None


class TLSPrototype:
    def __init__(self) -> None:
        self._fingerprints: dict[str, int] = {}

    def on_event(self, ev: dict) -> None:
        if not ev.get("tap") or ev.get("proto") != 6:
            return
        if ev.get("dst_port") != PORT_TLS:
            return
        c = parse_client_hello(ev.get("payload") or b"")
        if not c:
            return
        fpr = (f"tl-{c['tls_version']}-cs{c['cipher_count']}-"
               f"ext{c['ext_count']}")
        self._fingerprints[fpr] = self._fingerprints.get(fpr, 0) + 1

    def flush_window(self, t: float, window_id: int) -> list[dict]:
        rows = []
        total = sum(self._fingerprints.values()) or 1
        for fpr, n in sorted(self._fingerprints.items(),
                             key=lambda kv: -kv[1])[:6]:
            rows.append({
                "detector": NAME, "threat_class": THREAT_CLASS,
                "score": 0.0,                 # policy: prototype never alerts solo
                "confidence": 0.0,
                "features": {"fingerprint": fpr, "sightings": n,
                             "share": round(n / total, 2)},
                "why": "rare TLS fingerprint sighted — evidence only (PROTOTYPE, "
                       "mirror direction + threat-intel list required)",
            })
        self._fingerprints.clear()
        return rows


if __name__ == "__main__":
    # Build a plausible TLS 1.3 ClientHello byte blob and confirm parsing.
    # record: 22 0304 len2 | handshake: 01 len3(0x00002f) ver 0304 rand32 sidlen0
    # ciphers:[1303,1301,1302] ext_len 4 (one empty ext)
    body = (b"\x01\x00\x00\x2f\x03\x04" + b"\x00" * 32 + b"\x00"
            + b"\x00\x06\x13\x03\x13\x01\x13\x02" + b"\x00\x04\x00\x00\x00\x00")
    rec = b"\x16\x03\x04" + struct.pack(">H", len(body)) + body
    d = TLSPrototype()
    d.on_event({"tap": True, "proto": 6, "dst_port": 443, "payload": rec})
    print("matched:", parse_client_hello(rec))
    print("row:", d.flush_window(0.0, 0))