### `report.py`

import matplotlib.pyplot as plt
import os


def generate_report(stats):

    # Create reports folder if it does not exist
    os.makedirs("reports", exist_ok=True)

    tcp = stats["tcp"]
    udp = stats["udp"]

    # =========================
    # 1. TCP vs UDP
    # =========================

    labels = ["TCP", "UDP"]
    values = [tcp, udp]

    plt.figure(figsize=(7, 7))

    plt.pie(
        values,
        labels=labels,
        autopct="%1.1f%%",
        startangle=90
    )

    plt.title("Network Traffic - TCP vs UDP")
    plt.tight_layout()

    plt.savefig("reports/traffic_protocols.png")
    plt.show()

    # =========================
    # 2. Top UDP Destination Ports
    # =========================

    top_udp_ports = stats.get("top_udp_ports", [])

    if top_udp_ports:

        ports = [str(port) for port, count in top_udp_ports]
        counts = [count for port, count in top_udp_ports]

        plt.figure(figsize=(10, 6))

        plt.bar(ports, counts)

        plt.title("Top UDP Destination Ports")
        plt.xlabel("Destination Port (UDP)")
        plt.ylabel("Packet Count")

        plt.xticks(rotation=45)

        plt.tight_layout()

        plt.savefig("reports/top_udp_ports.png")
        plt.show()

    # =========================
    # 3. Top TCP Destination Ports
    # =========================

    top_tcp_ports = stats.get("top_tcp_ports", [])

    if top_tcp_ports:

        ports = [str(port) for port, count in top_tcp_ports]
        counts = [count for port, count in top_tcp_ports]

        plt.figure(figsize=(10, 6))

        plt.bar(ports, counts)

        plt.title("Top TCP Destination Ports")
        plt.xlabel("Destination Port (TCP)")
        plt.ylabel("Packet Count")

        plt.xticks(rotation=45)

        plt.tight_layout()

        plt.savefig("reports/top_tcp_ports.png")
        plt.show()

    # =========================
    # 4. Incoming vs Outgoing
    # =========================

    incoming = stats["incoming_packets"]
    outgoing = stats["outgoing_packets"]

    labels = ["Incoming", "Outgoing"]
    values = [incoming, outgoing]

    plt.figure(figsize=(8, 6))

    plt.bar(labels, values)

    plt.title("Incoming vs Outgoing Traffic")
    plt.ylabel("Packet Count")

    plt.tight_layout()

    plt.savefig("reports/traffic_direction.png")
    plt.show()


