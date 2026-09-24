
from collections import Counter


def analyze_packets(packets, local_ip):

    total_packets = len(packets)

    tcp_count = 0
    udp_count = 0

    incoming_packets = 0
    outgoing_packets = 0

    source_ips = set()
    destination_ips = set()

    tcp_ports = Counter()
    udp_ports = Counter()

    syn_count = 0
    rst_count = 0

    for packet in packets:

        # =========================
        # IP Information
        # Supports IPv4 and IPv6
        # =========================

        src_ip = None
        dst_ip = None

        if packet.haslayer("IP"):
            src_ip = packet["IP"].src
            dst_ip = packet["IP"].dst

        elif packet.haslayer("IPv6"):
            src_ip = packet["IPv6"].src
            dst_ip = packet["IPv6"].dst

        # Non-IP packets are safely ignored
        # for IP-related analysis

        if src_ip is not None and dst_ip is not None:

            source_ips.add(src_ip)
            destination_ips.add(dst_ip)

            # Traffic direction
            if src_ip == local_ip:
                outgoing_packets += 1

            elif dst_ip == local_ip:
                incoming_packets += 1

        # =========================
        # TCP Traffic
        # =========================

        if packet.haslayer("TCP"):

            tcp_count += 1

            # Count destination ports for outgoing IPv4/IPv6 traffic
            if src_ip == local_ip:

                tcp_ports[packet["TCP"].dport] += 1

            # TCP flags
            flags = str(packet["TCP"].flags)

            if "S" in flags:
                syn_count += 1

            if "R" in flags:
                rst_count += 1

        # =========================
        # UDP Traffic
        # =========================

        elif packet.haslayer("UDP"):

            udp_count += 1

            # Count destination ports for outgoing IPv4/IPv6 traffic
            if src_ip == local_ip:

                udp_ports[packet["UDP"].dport] += 1

    return {

        "total_packets": total_packets,

        "tcp": tcp_count,
        "udp": udp_count,

        "incoming_packets": incoming_packets,
        "outgoing_packets": outgoing_packets,

        "unique_source_ips": len(source_ips),
        "unique_destination_ips": len(destination_ips),

        "top_udp_ports": udp_ports.most_common(5),
        "top_tcp_ports": tcp_ports.most_common(5),

        "syn": syn_count,
        "rst": rst_count,
    }

