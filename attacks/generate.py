#!/usr/bin/env python3
"""SIH26145 — Custom diode-relevant threat generators (Scapy).

These produce the attack classes the base plan identifies as diode-specific —
the ones public datasets DON'T cover, which is what makes the "AI-based"
claim defensible. Each generator pushes UDP datagrams to the relay input
(127.0.0.1:<port> inside ns-source) or raw-injects frames when malformed L2/L3
content is required.

Generators:
  benign          simulated OT telemetry: periodic sensor readings, varied rates
  udp_flood       volumetric burst on the monitor path (random ports + payload)
  covert_timing   bits encoded in inter-packet delays (slow-drip exfil channel)
  stego_payload   hidden data smuggled in low-entropy-looking telemetry payloads
  malformed       off-spec frames: bad IP total_length, bogus protocol, bad csum

Usage (inside ns-source):
  ip netns exec ns-source python attacks/generate.py benign --seconds 30
  ip netns exec ns-source python attacks/generate.py udp_flood --rate-pps 3000 --seconds 5
  ...
"""
import argparse
import random
import socket
import struct
import time

RELAY = ("127.0.0.1", 10500)


def sock() -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return s


# ------------------------------------------------------------------ benign

def gen_benign(seconds: float, sensors: int = 6) -> None:
    """Simulated industrial telemetry: each sensor has its own cadence and
    value distribution; occasional bursts (historian sync) keep it honest."""
    s = sock()
    t_end = time.time() + seconds
    state = [{"id": i, "next": 0.0, "period": random.uniform(0.2, 2.0),
              "val": random.uniform(20, 90)} for i in range(sensors)]
    while time.time() < t_end:
        now = time.time()
        for st in state:
            if now >= st["next"]:
                st["val"] += random.uniform(-1.5, 1.5)
                msg = f"sensor={st['id']};ts={int(now)};value={st['val']:.2f};unit=C".encode()
                s.sendto(msg, RELAY)
                # historian sync burst: ~0.5% chance of a 20-packet backfill
                if random.random() < 0.005:
                    for k in range(20):
                        s.sendto(f"backfill;s={st['id']};k={k}".encode(), RELAY)
                st["next"] = now + st["period"] * random.uniform(0.7, 1.4)
        time.sleep(0.01)


# ------------------------------------------------------------------ attacks

def _packet_raw_snd(iface: str = "veth-src"):
    """Fast raw-L2 injector for the source veth (an attacker can forge frames;
    the diode's one-way property is ENFORCED on the monitor side, not here).
    Checksums are zeroed — L2 capture software (dpkt/tcpdump) does not validate,
    and the frames travel a veth, not a real stack."""
    import socket   # noqa: PLC0415
    import struct   # noqa: PLC0415
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    s.bind((iface, 0))
    try:
        src_mac = bytes.fromhex(
            open(f"/sys/class/net/{iface}/address").read().strip().replace(":", ""))
    except OSError:
        src_mac = b"\x02\x00\x00\x00\x00\x01"

    def send(src_ip: str, sport: int, dport: int, payload: bytes) -> None:
        total = 20 + 8 + len(payload)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 17, 0,
                         socket.inet_aton(src_ip), socket.inet_aton("10.200.0.2"))
        udp = struct.pack("!HHHH", sport & 0xffff, dport & 0xffff,
                          8 + len(payload), 0)
        frame = (b"\xff\xff\xff\xff\xff\xff" + src_mac + b"\x08\x00") + ip \
            + udp + payload
        s.send(frame)

    return send


def _rand_src() -> str:
    return "%d.%d.%d.%d" % tuple(random.randrange(1, 255) for _ in range(4))

def gen_udp_flood(rate_pps: float, seconds: float, spoof: bool = False) -> None:
    """Volumetric attack on the monitor path.

    Default (relay) mode randomizes src ports per packet so per-5-tuple flows
    fragment — only the source-bucket view sees it whole. With --spoof the
    datagrams are raw-injected straight onto the source veth from a stream of
    FAKE source IPs, so the monitor-side tap sees exactly what a spoofed-source
    flood looks like and the volumetric (source-entropy) detector fires."""
    s = sock()
    t_end = time.time() + seconds
    n = 0
    if spoof:
        snd = _packet_raw_snd()
        pace = 1.0 / 1200.0              # ~1.2k f/s: real-shaped, GIL-friendly
        while time.time() < t_end:
            payload = bytes(random.randrange(256) for _ in range(random.randint(32, 512)))
            snd(_rand_src(), random.randrange(1024, 65535), 9999, payload)
            n += 1
            time.sleep(pace)
    else:
        interval = 1.0 / max(rate_pps, 1)
        while time.time() < t_end:
            payload = bytes(random.randrange(256) for _ in range(random.randint(32, 512)))
            s.sendto(payload, RELAY)
            n += 1
            time.sleep(interval * random.uniform(0.5, 1.5))
    print(f"[udp_flood] sent {n}")


def gen_beacon(seconds: float, period_ms: float = 250.0) -> None:
    """C2 beaconing: phone-home datagrams on a METRONOME cadence (default
    every 250 ms) from a DEDICATED source. The beacon detector's coefficient-
    of-variation reads the fixed rhythm inside the tap stream; a dedicated
    source is required so the CV isn't polluted by concurrent benign chatter
    on the relay source."""
    snd = _packet_raw_snd()
    period = max(60.0, period_ms) / 1000.0        # beacon floor: >= 60 ms
    t_end = time.time() + seconds
    n = 0
    while time.time() < t_end:
        snd("10.200.0.42", 10500, 10500, b"phonehome;v=%d" % random.randrange(1 << 20))
        time.sleep(period)
        n += 1
    print(f"[beacon] sent {n} at {period * 1000:.0f} ms cadence")


def gen_portscan(rate_pps: float, seconds: float) -> None:
    """Recon / port-scan reconnaissance: raw-inject lightweight UDP probes to a
    wide fan-out of distinct destination ports (plus occasional SYN-flagged TCP
    hints). The scan detector reads the port-spread cover on the tap; probing
    the FULL 1-65535 space keeps probes mostly distinct so cover stays high
    even at a fast pps."""
    snd = _packet_raw_snd()
    t_end = time.time() + seconds
    pace = 1.0 / 1200.0              # ~1.2k probes/s: real-shaped, GIL-friendly
    n = 0
    while time.time() < t_end:
        if n % 4 == 0:
            # hint at a SYN-probe by pinging a proxy port too
            snd("10.200.0.77", random.randrange(1024, 65535),
                random.randrange(1, 65535), b"\x00" * 8)
        else:
            snd("10.200.0.77", random.randrange(1024, 65535),
                random.randrange(1, 65535), b"X" * 8)
        n += 1
        time.sleep(pace)
    print(f"[portscan] fanned out {n} probes")


def gen_covert_timing(seconds: float, message: str = "SECRET", bit0_ms: float = 15,
                      bit1_ms: float = 70) -> None:
    """Covert timing channel: message bytes -> bits -> inter-packet delays.
    Statistically subtle; needs sequence modeling of IATs to surface."""
    s = sock()
    bits = "".join(f"{b:08b}" for b in message.encode())
    t_end = time.time() + seconds
    i = 0
    seq = random.Random(1234)
    while time.time() < t_end:
        b = bits[i % len(bits)]
        delay = (bit0_ms if b == "0" else bit1_ms) / 1000.0
        delay *= random.uniform(0.9, 1.1)           # light jitter to evade thresholds
        s.sendto(b"x%02x" % seq.randrange(256), RELAY)
        time.sleep(delay)
        i += 1
    print(f"[covert_timing] sent {i} packets encoding {len(bits)} bits")


def gen_stego_payload(seconds: float, secret: str = "EXFIL-ME") -> None:
    """Payload steganography: telemetry-shaped packets whose numeric fields
    carry secret nibbles in their decimals. Entropy looks normal; content is not."""
    s = sock()
    nibbles = "".join(f"{ord(c):04b}" for c in secret)[:64]
    t_end = time.time() + seconds
    i = 0
    while time.time() < t_end:
        val = 40.0
        if i < len(nibbles):
            val += int(nibbles[i]) * 0.03           # LSB-ish carrier in the decimal
        msg = f"sensor=9;ts={int(time.time())};value={val:.2f};unit=C".encode()
        s.sendto(msg, RELAY)
        time.sleep(random.uniform(0.8, 1.6))        # innocent cadence
        i += 1
    print(f"[stego_payload] sent {i} carriers")


def gen_malformed(count: int, use_raw: bool = False) -> None:
    """Off-spec frames via scapy raw injection (needs root inside ns-source):
    - IP total_length field lying about the real size
    - unknown protocol number
    - UDP length mismatch / zero checksum abuse
    The monitor-side kernel must still ACCEPT these onto the wire for us to
    observe them, so malformations stay within pcap-capturable bounds."""
    from scapy.all import Ether, IP, UDP, Raw, sendp   # noqa: PLC0415
    payload = b"A" * 24
    for i in range(count):
        ip = IP(src="10.200.0.77", dst="10.200.0.2", ttl=random.choice([1, 37, 255]))
        udp = UDP(sport=40000 + i, dport=9999, chksum=0)
        # lie about IP total length (short by 8) — classic off-spec shape
        # scapy auto-fills IP.len at build; compute the honest total first, then
        # pin an explicit (wrong) value so the wire frame carries the lie.
        frame = Ether(src="de:ad:be:ef:00:01", dst="ee:11:22:33:44:55") / ip / udp / Raw(payload)
        frame[IP].len = len(bytes(ip / udp / Raw(payload))) - 8
        sendp(frame, verbose=False)
    print(f"[malformed] injected {count} frames")


GENERATORS = {
    "benign": lambda a: gen_benign(a.seconds),
    "udp_flood": lambda a: gen_udp_flood(a.rate_pps, a.seconds, a.spoof),
    "beacon": lambda a: gen_beacon(a.seconds, a.period_ms),
    "portscan": lambda a: gen_portscan(a.rate_pps, a.seconds),
    "covert_timing": lambda a: gen_covert_timing(a.seconds, bit0_ms=a.bit0_ms,
                                                 bit1_ms=a.bit1_ms),
    "stego_payload": lambda a: gen_stego_payload(a.seconds),
    "malformed": lambda a: gen_malformed(a.count),
}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="gen", required=True)
    for name in GENERATORS:
        p = sub.add_parser(name)
        p.add_argument("--seconds", type=float, default=10.0)
        p.add_argument("--rate-pps", type=float, default=1000.0)
        p.add_argument("--count", type=int, default=50)
        p.add_argument("--bit0-ms", type=float, default=15.0)
        p.add_argument("--bit1-ms", type=float, default=70.0)
        p.add_argument("--period-ms", type=float, default=250.0)
        p.add_argument("--spoof", action="store_true", default=False)
    args = ap.parse_args()
    GENERATORS[args.gen](args)


if __name__ == "__main__":
    main()
