import pandas as pd


def detect_syn_floods(
    packets,
    syn_threshold=100,
    unanswered_ratio_threshold=0.80
):
    """
    Detect possible SYN-flood activity.

    A possible SYN flood occurs when:
    1. One source sends many SYN packets to a destination.
    2. Most SYN packets do not receive a SYN-ACK response.

    Parameters:
        packets: DataFrame produced by parse_pcap().
        syn_threshold: Minimum SYN packets required.
        unanswered_ratio_threshold: Required unanswered SYN ratio.

    Returns:
        A DataFrame containing possible SYN-flood alerts.
    """

    required_columns = {
        "packet_number",
        "source_ip",
        "destination_ip",
        "tcp_syn",
        "tcp_ack",
    }

    if packets.empty or not required_columns.issubset(packets.columns):
        return pd.DataFrame()

    tcp_packets = packets.dropna(
        subset=["source_ip", "destination_ip"]
    ).copy()

    # PyShark normally returns TCP flag values as strings.
    tcp_packets["tcp_syn"] = (
        tcp_packets["tcp_syn"]
        .astype(str)
        .str.lower()
        .isin(["1", "true"])
    )

    tcp_packets["tcp_ack"] = (
        tcp_packets["tcp_ack"]
        .astype(str)
        .str.lower()
        .isin(["1", "true"])
    )

    # Initial SYN: SYN=1 and ACK=0
    syn_packets = tcp_packets[
        tcp_packets["tcp_syn"] & ~tcp_packets["tcp_ack"]
    ].copy()

    if syn_packets.empty:
        return pd.DataFrame()

    syn_counts = (
        syn_packets
        .groupby(["source_ip", "destination_ip"])
        .agg(
            syn_count=("packet_number", "count"),
            first_packet=("packet_number", "min"),
            last_packet=("packet_number", "max"),
        )
        .reset_index()
    )

    # Response SYN-ACK: SYN=1 and ACK=1
    syn_ack_packets = tcp_packets[
        tcp_packets["tcp_syn"] & tcp_packets["tcp_ack"]
    ].copy()

    if syn_ack_packets.empty:
        syn_counts["syn_ack_count"] = 0
    else:
        syn_ack_counts = (
            syn_ack_packets
            .groupby(["source_ip", "destination_ip"])
            .size()
            .reset_index(name="syn_ack_count")
        )

        # Reverse the response direction so it matches the original SYN.
        syn_ack_counts = syn_ack_counts.rename(
            columns={
                "source_ip": "destination_ip",
                "destination_ip": "source_ip",
            }
        )

        syn_counts = syn_counts.merge(
            syn_ack_counts,
            on=["source_ip", "destination_ip"],
            how="left",
        )

        syn_counts["syn_ack_count"] = (
            syn_counts["syn_ack_count"].fillna(0).astype(int)
        )

    syn_counts["unanswered_syns"] = (
        syn_counts["syn_count"] - syn_counts["syn_ack_count"]
    ).clip(lower=0)

    syn_counts["unanswered_ratio"] = (
        syn_counts["unanswered_syns"] / syn_counts["syn_count"]
    )

    suspicious = syn_counts[
        (syn_counts["syn_count"] >= syn_threshold)
        & (
            syn_counts["unanswered_ratio"]
            >= unanswered_ratio_threshold
        )
    ].copy()

    if suspicious.empty:
        return suspicious

    suspicious["alert_type"] = "Possible SYN flood"
    suspicious["severity"] = suspicious["syn_count"].apply(
        assign_severity
    )

    suspicious["description"] = (
        suspicious["source_ip"].astype(str)
        + " sent "
        + suspicious["syn_count"].astype(str)
        + " SYN packets to "
        + suspicious["destination_ip"].astype(str)
    )

    suspicious["unanswered_ratio"] = (
        suspicious["unanswered_ratio"] * 100
    ).round(2)

    return suspicious.sort_values(
        "syn_count",
        ascending=False
    ).reset_index(drop=True)


def assign_severity(syn_count):
    if syn_count >= 1000:
        return "High"

    if syn_count >= 500:
        return "Medium"

    return "Low"