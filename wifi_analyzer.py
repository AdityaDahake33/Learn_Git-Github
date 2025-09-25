import pywifi
import time
import os
from scapy.all import sniff, Dot11, IP, TCP, UDP
import pandas as pd

def extract_features(packet):
    features = {}
    if IP in packet:
        features['src_ip'] = packet[IP].src
        features['dst_ip'] = packet[IP].dst
        features['protocol'] = packet[IP].proto
        features['len'] = packet[IP].len

        if TCP in packet:
            features['src_port'] = packet[TCP].sport
            features['dst_port'] = packet[TCP].dport
            features['flags'] = str(packet[TCP].flags)
        elif UDP in packet:
            features['src_port'] = packet[UDP].sport
            features['dst_port'] = packet[UDP].dport
        else:
            features['src_port'] = None
            features['dst_port'] = None
            features['flags'] = None
    else:
        features['src_ip'] = None
        features['dst_ip'] = None
        features['protocol'] = None
        features['len'] = None
        features['src_port'] = None
        features['dst_port'] = None
        features['flags'] = None

    # Add more feature extraction here as needed for your ML model
    # For example, you might want to extract features related to Wi-Fi frames (Dot11)
    # if Dot11 in packet:
    #     features['ssid'] = packet[Dot11].info.decode() if packet[Dot11].info else None
    #     features['addr1'] = packet[Dot11].addr1
    #     features['addr2'] = packet[Dot11].addr2

    return features

def scan_wifi_networks():
    wifi = pywifi.PyWiFi()
    ifaces = wifi.interfaces()

    if len(ifaces) == 0:
        print("No Wi-Fi interface found.")
        return

    iface = ifaces[0] 

    while True:
        os.system('cls' if os.name == 'nt' else 'clear') # Clear console for continuous update
        print(f"Scanning Wi-Fi networks using interface: {iface.name()}")

        iface.scan()
        time.sleep(5)  # Give the interface some time to scan

        scan_results = iface.scan_results()

        if len(scan_results) == 0:
            print("No Wi-Fi networks found.")
        else:
            print("\nAvailable Wi-Fi Networks:")
            for i, network in enumerate(scan_results):
                print(f"  {i+1}. SSID: {network.ssid}, BSSID: {network.bssid}, Signal: {network.signal} dBm")
        time.sleep(10) # Wait for 10 seconds before the next scan

def detect_malicious_activity(features):
    # Placeholder for ML model detection
    # In a real scenario, this would use the trained XGBoost model
    # For demonstration, let's say a large UDP packet is 'malicious'
    if features['protocol'] == 17 and \
       features['dst_ip'] == '127.0.0.1' and \
       features['dst_port'] == 5000 and \
       features['len'] and features['len'] > 400 and features['len'] < 600: # Check for UDP to 127.0.0.1:5000 with length around 500
        return True, "Simulated UDP Flood Detected"
    return False, None

def trigger_alert(alert_message, packet_features):
    print(f"\n!!! ALERT !!! {alert_message}")
    print(f"Malicious Packet Features: {packet_features}")
    # In the future, this will send the alert to n8n

def sniff_network_packets(iface_name):
    print(f"\nStarting packet sniffing on interface: {iface_name}")
    print("Press Ctrl+C to stop sniffing.")
    captured_features = []
    def packet_callback(packet):
        features = extract_features(packet)
        if features['protocol'] is not None: # Only process IP packets for now
            captured_features.append(features)
            print(f"Captured: {features}")
            
            is_malicious, alert_msg = detect_malicious_activity(features)
            if is_malicious:
                trigger_alert(alert_msg, features)

    try:
        sniff(iface=iface_name, prn=packet_callback, store=0, timeout=60) # Sniff for 60 seconds
    except Exception as e:
        print(f"Error during packet sniffing: {e}")
    return captured_features

if __name__ == "__main__":
    # First, get the Wi-Fi interface name from pywifi
    wifi = pywifi.PyWiFi()
    ifaces = wifi.interfaces()

    if len(ifaces) == 0:
        print("No Wi-Fi interface found. Cannot proceed with sniffing.")
    else:
        # Assuming the first interface is the one we want to use for both scanning and sniffing
        iface_name = ifaces[0].name()
        
        # You can choose to run either scan_wifi_networks() or sniff_network_packets()
        # For now, let's run sniff_network_packets() to demonstrate packet capture.
        # To run scan_wifi_networks(), uncomment the line below and comment out sniff_network_packets()
        # scan_wifi_networks()
        captured_data = sniff_network_packets(iface_name)
        print("\n--- Captured Packet Features ---")
        for data in captured_data:
            print(data)

        if captured_data:
            df = pd.DataFrame(captured_data)
            csv_file = "network_traffic_features.csv"
            df.to_csv(csv_file, index=False)
            print(f"\nCaptured features saved to {csv_file}")