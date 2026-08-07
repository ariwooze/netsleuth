import pyshark
import pandas as pd


def get_layer_value(packet, layer_name, field_name):
    """Safely retrieve a field from a packet layer."""

    try:
        layer = getattr(packet, layer_name)
        return getattr(layer, field_name)
    except (AttributeError, KeyError):
        return None


def parse_pcap(file_path, packet_limit=10000):
    """Convert packets from a PCAP file into a Pandas DataFrame."""

    capture = pyshark.FileCapture(
        file_path,
        keep_packets=False
    )

    records = []

    try:
        for packet_number, packet in enumerate(capture, start=1):
            if packet_number > packet_limit:
                break

            protocol = getattr(packet, "highest_layer", None)
            timestamp = getattr(packet, "sniff_timestamp", None)
            packet_length = getattr(packet, "length", None)

            ip_source = get_layer_value(packet, "ip", "src")
            ip_destination = get_layer_value(packet, "ip", "dst")

            # Use IPv6 addresses when IPv4 fields are unavailable.
            if ip_source is None:
                ip_source = get_layer_value(packet, "ipv6", "src")

            if ip_destination is None:
                ip_destination = get_layer_value(packet, "ipv6", "dst")

            record = {
                "packet_number": packet_number,
                "timestamp": timestamp,
                "source_ip": ip_source,
                "destination_ip": ip_destination,
                "protocol": protocol,
                "source_port": (
                    get_layer_value(packet, "tcp", "srcport")
                    or get_layer_value(packet, "udp", "srcport")
                ),
                "destination_port": (
                    get_layer_value(packet, "tcp", "dstport")
                    or get_layer_value(packet, "udp", "dstport")
                ),
                "packet_length": packet_length,
                "tcp_syn": get_layer_value(packet, "tcp", "flags_syn"),
                "tcp_ack": get_layer_value(packet, "tcp", "flags_ack"),
                "dns_query": get_layer_value(packet, "dns", "qry_name"),
            }

            records.append(record)

    finally:
        capture.close()

    dataframe = pd.DataFrame(records)

    if dataframe.empty:
        return dataframe

    dataframe["timestamp"] = pd.to_numeric(
        dataframe["timestamp"],
        errors="coerce"
    )

    dataframe["packet_length"] = pd.to_numeric(
        dataframe["packet_length"],
        errors="coerce"
    )

    dataframe["source_port"] = pd.to_numeric(
        dataframe["source_port"],
        errors="coerce"
    )

    dataframe["destination_port"] = pd.to_numeric(
        dataframe["destination_port"],
        errors="coerce"
    )

    return dataframe