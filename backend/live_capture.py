from scapy.all import sniff
import numpy as np

from backend.predictor import predict_attack
from backend.ips_engine import process_attack


def simple_packet_to_features(pkt):
    """
    Convert packet → lightweight 41-feature vector
    """

    length = len(pkt)
    proto = 0
    sport = 0
    dport = 0
    ttl = 0
    flags = 0
    window = 0
    payload_size = 0

    if pkt.haslayer("IP"):
        proto = pkt["IP"].proto
        ttl = pkt["IP"].ttl

    if pkt.haslayer("TCP"):
        sport = pkt["TCP"].sport
        dport = pkt["TCP"].dport
        flags = int(pkt["TCP"].flags)
        window = pkt["TCP"].window
        payload_size = len(pkt["TCP"].payload)

    elif pkt.haslayer("UDP"):
        sport = pkt["UDP"].sport
        dport = pkt["UDP"].dport
        payload_size = len(pkt["UDP"].payload)

    features = [
        length, proto, sport, dport,
        ttl, flags, window, payload_size
    ]

    while len(features) < 41:
        features.append(0)

    return np.array(features, dtype=float).reshape(1, -1)

def live_packet_stream(packet_count=10):
    """
    Continuous packet capture → Predict → IPS → Yield results
    """

    while True:   # continuous monitoring

        results = []

        def process(pkt):
            features = simple_packet_to_features(pkt)
            attack = predict_attack(features)[0]
            action = process_attack(attack)

            results.append({
                "attack": attack,
                "action": action
            })

        sniff(count=packet_count, prn=process, store=False)

        for r in results:
            yield r


    