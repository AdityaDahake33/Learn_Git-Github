import pywifi
import time
import os

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

if __name__ == "__main__":
    scan_wifi_networks()