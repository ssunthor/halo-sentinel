#!/usr/bin/env python3
"""Publish synthetic syslog/firewall and netflow-DFP records to the local
docker-compose Kafka stack, so the dashboard (and the Destinations map / arcs)
can be exercised without access to the real production Kafka cluster.

Run inside the running `backend` container — it already has confluent-kafka
installed and sits on the right docker network to resolve the `kafka` host:

    docker compose exec -T backend python - < gen_test_data.py

Stop with Ctrl+C; the producer flushes on exit.
"""
import json
import os
import random
import time

from confluent_kafka import Producer

BOOTSTRAP = os.getenv("KAFKA_SECURITY_SERVERS", "kafka:9092")
SYSLOG_TOPIC = os.getenv("KAFKA_SECURITY_TOPIC", "gtt-scott-dev-syslog-output")
NETFLOW_TOPIC = os.getenv("KAFKA_NETFLOW_TOPIC", "gtt-scott-dev-netflow-output")

# A mix of public IPs (so GeoIP resolves real-ish locations and the new
# netflow map-enrichment path fires) and RFC1918 addresses (internal hosts).
PUBLIC_IPS = [
    "8.8.8.8", "1.1.1.1", "9.9.9.9", "203.0.113.7", "198.51.100.23",
    "45.33.32.156", "104.16.85.20", "185.199.108.153", "139.130.4.5",
    "210.6.144.130",
]
PRIVATE_IPS = [f"10.0.1.{n}" for n in range(10, 30)] + [f"192.168.1.{n}" for n in range(10, 30)]
HOSTS = ["fw-edge-01", "fw-edge-02", "core-sw-01", "ftd-dc-east"]
ANOMALY_CAUSES = [None, None, "Port Scan Detected", "Traffic Volume Spike", "Unusual Geo Access"]


def syslog_event():
    """Raw-text firewall log shaped to satisfy main.py's SYSLOG branch:
    needs '%FTD' for is_firewall, and 'SrcIP:'/'DstIP:' for RE_SRC_IP/RE_DST_IP."""
    src = random.choice(PUBLIC_IPS + PRIVATE_IPS)
    dst = random.choice(PUBLIC_IPS + PRIVATE_IPS)
    action = random.choice(["Deny", "Allow"])
    sport, dport = random.randint(1024, 65535), random.choice([22, 80, 443, 3389, 53, 8080])
    proto = random.choice(["TCP", "UDP"])
    msg = (
        f"<166>{time.strftime('%b %d %H:%M:%S')} {random.choice(HOSTS)} %FTD-3-430002: "
        f"{action} {proto} connection from SrcIP: {src}/{sport} to DstIP: {dst}/{dport} "
        f"on interface OUTSIDE"
    )
    return {
        "message": msg,
        "source": random.choice(HOSTS),
        "main_label": "SECURITY/FIREWALL" if action == "Deny" else "NON_SECURITY",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }


def netflow_event():
    """JSON shaped to satisfy main.py's NETFLOW DFP branch (needs anomaly_score
    plus src_ip/src_addr/user_id). Mixes internal/external pairs so both the
    existing syslog destination path and the new netflow public-IP path fire."""
    roll = random.random()
    if roll < 0.35:
        src, dst = random.choice(PRIVATE_IPS), random.choice(PUBLIC_IPS)
    elif roll < 0.45:
        src, dst = random.choice(PUBLIC_IPS), random.choice(PRIVATE_IPS)
    else:
        src, dst = random.choice(PRIVATE_IPS), random.choice(PRIVATE_IPS)

    score = round(random.choice([0, 0, 0, 1.2, 2.5, 4.0, 6.8, 9.1]) + random.random(), 2)
    return {
        "anomaly_score": score,
        "anomaly_cause": random.choice(ANOMALY_CAUSES) if score > 2.0 else None,
        "mean_abs_err": round(random.random() * 2, 3),
        "src_ip": src,
        "dst_ip": dst,
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice([22, 80, 443, 3389, 53, 8080]),
        "protocol": random.choice(["TCP", "UDP"]),
        "bytes": random.randint(500, 5_000_000),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }


def main(events_per_second=4, duration_seconds=300):
    producer = Producer({"bootstrap.servers": BOOTSTRAP})
    print(f"Publishing to '{SYSLOG_TOPIC}' and '{NETFLOW_TOPIC}' via {BOOTSTRAP} "
          f"for {duration_seconds}s (Ctrl+C to stop early)...")
    sent = 0
    deadline = time.time() + duration_seconds
    try:
        while time.time() < deadline:
            producer.produce(SYSLOG_TOPIC, json.dumps(syslog_event()).encode("utf-8"))
            producer.produce(NETFLOW_TOPIC, json.dumps(netflow_event()).encode("utf-8"))
            sent += 2
            producer.poll(0)
            if sent % 40 == 0:
                print(f"  ...published {sent} messages")
            time.sleep(1.0 / events_per_second)
    except KeyboardInterrupt:
        print("Stopping...")
    finally:
        producer.flush()
        print(f"Done. Published {sent} messages total.")


if __name__ == "__main__":
    main()
