
from scapy.all import sniff

from analyzer import analyze_packets
from report import generate_report

import socket
import time


CAPTURE_TIME = 60


def get_local_ip():
    """Detect the local IPv4 address used by the current machine."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        local_ip = sock.getsockname()[0]
        sock.close()
        return local_ip

    except OSError:
        return "127.0.0.1"


print("=" * 50)
print(" Network Traffic Analyzer")
print("=" * 50)

print(f"\nCapturing network traffic for {CAPTURE_TIME} seconds...\n")

start_time = time.time()

packets = sniff(timeout=CAPTURE_TIME)

elapsed_time = time.time() - start_time


print("\n" + "=" * 50)
print(" Capture Finished")
print("=" * 50)

print(f"Captured packets : {len(packets)}")
print(f"Time elapsed     : {elapsed_time:.1f} seconds")

print("\nAnalyzing traffic...")


LOCAL_IP = get_local_ip()

print(f"Local IP         : {LOCAL_IP}")

stats = analyze_packets(packets, LOCAL_IP)


print("\n" + "=" * 50)
print(" Network Statistics")
print("=" * 50)

print(f"Total Packets          : {stats['total_packets']}")
print(f"TCP Packets            : {stats['tcp']}")
print(f"UDP Packets            : {stats['udp']}")

print(f"Incoming Packets       : {stats['incoming_packets']}")
print(f"Outgoing Packets       : {stats['outgoing_packets']}")

print(f"Unique Source IPs      : {stats['unique_source_ips']}")
print(f"Unique Destination IPs : {stats['unique_destination_ips']}")

print(f"SYN Packets            : {stats['syn']}")
print(f"RST Packets             : {stats['rst']}")


print("\n--- Top UDP Destination Ports ---")

for port, count in stats["top_udp_ports"]:
    print(f"Port {port}: {count} packets")


print("\n--- Top TCP Destination Ports ---")

for port, count in stats["top_tcp_ports"]:
    print(f"Port {port}: {count} packets")


print("\nGenerating traffic charts...")

generate_report(stats)

print("\nAnalysis complete.")

