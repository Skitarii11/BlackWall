from collections import defaultdict, deque
import time

port_scan_tracker = defaultdict(lambda: defaultdict(deque))
SCAN_WINDOW_SECONDS = 10
SCAN_PORT_THRESHOLD = 15

worm_tracker = defaultdict(lambda: deque())
WORM_WINDOW_SECONDS = 60
WORM_CONNECTION_THRESHOLD = 20

TROJAN_PORTS = {
    6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669, # Common IRC ports used by botnets
    27374, # SubSeven Trojan
    31337, # Back Orifice Trojan
    12345, 12346, # NetBus Trojan
    8080, 8443, # Common alternate web ports used by malware C2 servers.
    40421 # Gh0st RAT
}

WORM_TARGET_PORTS = {
    135, 137, 139, 445, # Windows SMB/NetBIOS (e.g., Conficker, WannaCry)
    3389, # RDP (e.g., BlueKeep)
    1433, 1434, # SQL Server (e.g., SQL Slammer)
    445, # SMB (Server Message Block)
    5900, # VNC (Remote Desktop)
    4899, # Radmin (Remote Admin Tool)
    5060 # VoIP-related worms
}


def analyze_anomaly(packet_features):
    src_ip = packet_features.get('src_ip')
    dst_ip = packet_features.get('dst_ip')
    dst_port = packet_features.get('dst_port')
    pkt_len = packet_features.get('pkt_len')

    # --- Layer 1: Signature-Based Detection ---

    # Rule 1: Trojan Port Signature
    if dst_port in TROJAN_PORTS:
        return ("Trojan C2 Communication", "Critical")

    # Rule 2: Worm Propagation Signature
    if dst_port in WORM_TARGET_PORTS and src_ip:
        current_time = time.time()
        activity = worm_tracker[src_ip]
        activity.append((current_time, dst_ip))

        while activity and current_time - activity[0][0] > WORM_WINDOW_SECONDS:
            activity.popleft()

        unique_destinations = len(set(dest for _, dest in activity))
        if unique_destinations > WORM_CONNECTION_THRESHOLD:
            activity.clear()
            return ("Worm Propagation Detected", "Critical")


    # --- Layer 2: Heuristic-Based Detection ---

    # Rule 3: Port Scan Detection (existing)
    if src_ip and dst_ip and dst_port:
        current_time = time.time()
        activity = port_scan_tracker[src_ip][dst_ip]
        activity.append((current_time, dst_port))
        
        while activity and current_time - activity[0][0] > SCAN_WINDOW_SECONDS:
            activity.popleft()
            
        unique_ports = len(set(port for _, port in activity))
        if unique_ports > SCAN_PORT_THRESHOLD:
            activity.clear()
            return ("Port Scan", "High")

    # Rule 4: Unusual Port Activity (existing)
    if dst_port and (1 <= dst_port <= 1024 and dst_port not in {80, 443, 53, 22, 25, 110, 143}) or dst_port > 49151:
        return ("Unusual Port Activity", "Medium")

    # Rule 5: Anomalous Packet Size (existing)
    if pkt_len and pkt_len > 1450:
        return ("Anomalous Packet Size", "Low")

    # generic anomaly found by the IsolationForest model.
    return ("General Anomaly", "High")