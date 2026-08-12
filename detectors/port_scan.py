import pandas as pd 


def detect_port_scans(packets, port_threshold=15):
    """Identify sources contacting many ports on one destination."""

    tcp_packets = packets.dropna(
        subset=["source_ip", "destination_ip", "destination_port"]
    ).copy()

    if tcp_packets.empty:
        return pd.DataFrame()

    results = (
        tcp_packets
        .groupby(["source_ip", "destination_ip"])
        .agg(
            unique_ports=("destination_port", "nunique"),
            packet_count=("packet_number", "count"),
            first_packets=("packet_number", "min"),
            last_packet=("packet_number", "max"),
        )
        .reset_index()
    )

    suspicious = results[
        results["unique_ports"] >= port_threshold
    ].copy()

    if suspicious.empty:
        return suspicious

    suspicious["alert_type"] = "Possible port scan"
    suspicious["severity"] = suspicious["unique_ports"].apply(
        assign_severity
    )

    return suspicious.sort_values(
        "unique_ports",
        ascending=False
    )

def assign_severity(unique_ports):
    if unique_ports >= 100:
        return "High"
    if unique_ports >= 40:
        return "Medium"
    return "Low"