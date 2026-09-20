#!/usr/bin/env python3
"""SIH26145 — Threat-detector package.

Per-threat detectors that operate ON the monitor-side live stream (relay
payloads + an optional L3 tap) and emit evidence in the alert-contract shape.

    event      -> {t, window_id, src, size, payload?, tap?, proto?, dst_ip?,
                   dst_port?}
    flush      -> list[evidence_row]
    evidence   -> {detector, threat_class, score, confidence, features[], why}

Coverage (six problem-statement classes):
  volumetric     volumetric/source-entropy  [production, needs --tap-dev]
  scan_recon     port-fanout / -cover       [production]
  anomaly        (existing fusion/classifier/AE)
  beacon         inter-arrival regularity  [production]
  exfiltration   byte-volume asymmetry     [production]
  dns_tunneling  qname entropy / tunnels   [production]
  tls_malware    JA4-lite fingerprint      [PROTOTYPE, never alerts solo]
"""
from __future__ import annotations

from detectors.volumetric import VolumetricDetector
from detectors.exfil import ExfilDetector
from detectors.beacon import BeaconDetector
from detectors.dns_dga import DGADetector
from detectors.tls import TLSPrototype
from detectors import scan as scan_detector

# coverage panel metadata: name -> (threat_class, status)
COVERAGE: dict[str, tuple[str, str]] = {
    "volumetric": ("volumetric", "production"),
    "scan": ("scan_recon", "production"),
    "beacon": ("beacon", "production"),
    "exfiltration": ("exfiltration", "production"),
    "dns_dga": ("dns_tunneling", "production"),
    "tls_malware": ("tls_malware", "prototype"),
}


class DetectorCoordinator:
    DEFAULT = ("volumetric", "exfil", "beacon", "dns_dga", "tls_malware")

    def __init__(self, enabled: tuple[str, ...] = DEFAULT,
                 min_score: float = 0.45) -> None:
        self._dets: list = []
        self.min_score = min_score
        for name in enabled:
            cls = {"volumetric": VolumetricDetector, "exfil": ExfilDetector,
                   "beacon": BeaconDetector, "dns_dga": DGADetector,
                   "tls_malware": TLSPrototype}.get(name)
            if cls:
                self._dets.append(cls())
        self._flushed = 0

    def feed(self, ev: dict) -> None:
        for d in self._dets:
            d.on_event(ev)

    def flush(self, t: float, window_id: int) -> list[dict]:
        """Gather evidence rows; drop anything below the alert floor."""
        rows: list[dict] = []
        for d in self._dets:
            out = d.flush_window(t, window_id)
            if not out:
                continue
            if isinstance(out, dict):
                out = [out]
            rows.extend(out)
        self._flushed += 1
        return [r for r in rows if (r.get("score") or 0) >= self.min_score]

    @staticmethod
    def strongest(rows: list[dict]) -> dict | None:
        return max(rows, key=lambda r: r.get("score", 0)) if rows else None

    def reset(self) -> None:
        for d in self._dets:
            reset = getattr(d, "reset", None)
            if reset:
                reset()
        self._flushed = 0


if __name__ == "__main__":
    print(COVERAGE)