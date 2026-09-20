#!/usr/bin/env python3
"""SIH26145 — Canonical alert record (the contract).

Every detector, the fusion layer and the dashboard write to this ONE shape.
The fields mirror the problem-statement schema — timestamp, flow id, threat
class, verdict/score, calibrated confidence, structured evidence:

  {
    "timestamp":   1720000000000,
    "flow_id":     "10.0.2.7:51324 -> 8.8.8.8:53/UDP",
    "threat_class": "dns_tunneling",
    "verdict":     "HIGH",
    "threat_score": 0.87,
    "confidence":  0.91,
    "detector":    "dns_dga",
    "evidence":    [{"feature": "...", "value": ..., "why": "..."}],
    "latency_ms":  4.3
  }

The six threat classes are the ones named in the problem statement; anything
the models detect that does NOT map cleanly to a named class is reported as
`anomaly` rather than over-claiming a specific family.
"""
import time

THREAT_CLASSES: dict[str, str] = {
    "volumetric":   "Volumetric / protocol DDoS (incl. spoofed-source floods)",
    "beacon":       "Botnet C2 beaconing (periodic phone-home)",
    "dns_tunneling": "DGA domains / DNS tunnelling",
    "tls_malware":  "Malware in encrypted sessions (JA3/JA4)",
    "scan_recon":   "Reconnaissance / port scanning",
    "exfiltration": "Data exfiltration (byte-volume asymmetry)",
    "anomaly":      "General anomaly — no named-class match",
}

# CICIDS2017 families -> problem-statement classes. Only semantically clean
# mappings. Everything else stays `anomaly` so we never over-claim a named
# class our evidence does not actually establish.
FAMILY_TO_CLASS: dict[str, str] = {
    "DDoS": "volumetric",
    "DoS Hulk": "volumetric",
    "DoS GoldenEye": "volumetric",
    "DoS slowloris": "volumetric",
    "DoS Slowhttptest": "volumetric",
    "Heartbleed": "volumetric",
    "PortScan": "scan_recon",
}


def classify_family(family: str | None) -> str:
    """Best-fit threat class for a predicted attack family (never raises)."""
    if not family:
        return "anomaly"
    return FAMILY_TO_CLASS.get(family, "anomaly")


def build_alert(*, timestamp: float | None = None, flow_id: str = "",
                threat_class: str = "anomaly", verdict: str = "OK",
                threat_score: float = 0.0, confidence: float | None = None,
                detector: str = "fusion", evidence: list[dict] | None = None,
                latency_ms: float | None = None, **legacy) -> dict:
    """Assemble one compliant alert record.

    `legacy` carries the existing response fields (reasons, attack_family,
    components, ae_error, ...) so the dashboard and /score response stay
    backward-compatible while the record itself is the new contract.
    """
    record = {
        "timestamp": int((timestamp if timestamp is not None else time.time()) * 1000),
        "flow_id": flow_id or "unknown-source",
        "threat_class": threat_class,
        "verdict": verdict,
        "threat_score": round(float(threat_score), 3),
        "confidence": round(float(confidence if confidence is not None else threat_score), 3),
        "detector": detector,
        "evidence": evidence or [],
        "latency_ms": round(float(latency_ms), 2) if latency_ms is not None else None,
    }
    record.update(legacy)
    return record


if __name__ == "__main__":
    import json
    sample = build_alert(
        flow_id="10.0.2.7:51324 -> 8.8.8.8:53/UDP",
        threat_class=classify_family("Bot"),
        verdict="HIGH", threat_score=0.87, confidence=0.91,
        detector="fusion", latency_ms=4.3,
        evidence=[{"feature": "domain_entropy", "value": 4.2,
                   "why": "entropy >> benign DNS"}],
    )
    print(json.dumps(sample, indent=2))