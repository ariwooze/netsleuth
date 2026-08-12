import pandas as pd


def detect_dns_anomalies(
    packets,
    length_threshold=50,
    repetition_threshold=20
):
    """
    Detect unusually long or frequently repeated DNS queries.

    Parameters:
        packets: DataFrame produced by parse_pcap().
        length_threshold: Query length considered unusual.
        repetition_threshold: Number of repeated requests required.

    Returns:
        A DataFrame containing possible DNS anomalies.
    """

    required_columns = {
        "packet_number",
        "source_ip",
        "dns_query",
    }

    if packets.empty or not required_columns.issubset(packets.columns):
        return pd.DataFrame()

    dns_packets = packets.dropna(
        subset=["source_ip", "dns_query"]
    ).copy()

    if dns_packets.empty:
        return pd.DataFrame()

    dns_packets["dns_query"] = (
        dns_packets["dns_query"]
        .astype(str)
        .str.strip()
        .str.rstrip(".")
        .str.lower()
    )

    dns_packets = dns_packets[
        dns_packets["dns_query"] != ""
    ].copy()

    if dns_packets.empty:
        return pd.DataFrame()

    dns_packets["query_length"] = (
        dns_packets["dns_query"].str.len()
    )

    query_summary = (
        dns_packets
        .groupby(["source_ip", "dns_query"])
        .agg(
            query_count=("packet_number", "count"),
            query_length=("query_length", "max"),
            first_packet=("packet_number", "min"),
            last_packet=("packet_number", "max"),
        )
        .reset_index()
    )

    suspicious = query_summary[
        (query_summary["query_length"] >= length_threshold)
        | (query_summary["query_count"] >= repetition_threshold)
    ].copy()

    if suspicious.empty:
        return suspicious

    suspicious["reason"] = suspicious.apply(
        determine_reason,
        axis=1,
        length_threshold=length_threshold,
        repetition_threshold=repetition_threshold,
    )

    suspicious["alert_type"] = "Possible DNS anomaly"

    suspicious["severity"] = suspicious.apply(
        assign_severity,
        axis=1,
    )

    suspicious["description"] = (
        suspicious["source_ip"].astype(str)
        + " requested "
        + suspicious["dns_query"]
        + " "
        + suspicious["query_count"].astype(str)
        + " time(s)"
    )

    severity_order = {
        "High": 3,
        "Medium": 2,
        "Low": 1,
    }

    suspicious["severity_rank"] = (
        suspicious["severity"].map(severity_order)
    )

    suspicious = suspicious.sort_values(
        ["severity_rank", "query_count", "query_length"],
        ascending=[False, False, False],
    )

    return suspicious.drop(
        columns=["severity_rank"]
    ).reset_index(drop=True)


def determine_reason(
    row,
    length_threshold,
    repetition_threshold
):
    long_query = row["query_length"] >= length_threshold
    repeated_query = row["query_count"] >= repetition_threshold

    if long_query and repeated_query:
        return "Long and frequently repeated DNS query"

    if long_query:
        return "Unusually long DNS query"

    return "Frequently repeated DNS query"


def assign_severity(row):
    if row["query_length"] >= 100 or row["query_count"] >= 100:
        return "High"

    if row["query_length"] >= 70 or row["query_count"] >= 50:
        return "Medium"

    return "Low"