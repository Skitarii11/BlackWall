from scapy.all import IP, TCP, UDP

def extract_features(packet):
    log_features = {}
    numerical_features = {}

    if not packet.haslayer(IP):
        return None, None

    # --- Features for logging/display ---
    log_features['src_ip'] = packet[IP].src
    log_features['dst_ip'] = packet[IP].dst
    log_features['protocol'] = packet[IP].proto

    if packet.haslayer(TCP):
        log_features['src_port'] = packet[TCP].sport
        log_features['dst_port'] = packet[TCP].dport
    elif packet.haslayer(UDP):
        log_features['src_port'] = packet[UDP].sport
        log_features['dst_port'] = packet[UDP].dport
    else:
        log_features['src_port'] = 0
        log_features['dst_port'] = 0
    
    # --- Features for the ML model ---
    numerical_features['protocol'] = packet[IP].proto
    numerical_features['pkt_len'] = len(packet)
    numerical_features['src_port'] = log_features['src_port']
    numerical_features['dst_port'] = log_features['dst_port']

    return numerical_features, log_features