import pandas as pd

from detectors.port_scan import detect_port_scans
from detectors.syn_flood import detect_syn_floods
from detectors.dns_anomaly import detect_dns_anomalies


def analyze_packets(packets):
    """
    Run NetSleuth's detection rules against parsed packets.

    Returns a dictionary containing:
    - Traffic summary
    - Port-scan findings
    - SYN-flood findings
    - DNS-anomaly findings
    - Alert counts
    """

    if packets is None or packets.empty:
        return empty_analysis()

    port_scan_alerts = detect_port_scans(packets)
    syn_flood_alerts = detect_syn_floods(packets)
    dns_anomaly_alerts = detect_dns_anomalies(packets)

    summary = create_traffic_summary(packets)

    total_alerts = (
        len(port_scan_alerts)
        + len(syn_flood_alerts)
        + len(dns_anomaly_alerts)
    )

    alert_counts = {
        "port_scans": len(port_scan_alerts),
        "syn_floods": len(syn_flood_alerts),
        "dns_anomalies": len(dns_anomaly_alerts),
        "total": total_alerts,
    }

    severity_counts = count_severities(
        port_scan_alerts,
        syn_flood_alerts,
        dns_anomaly_alerts,
    )

    return {
        "summary": summary,
        "alert_counts": alert_counts,
        "severity_counts": severity_counts,
        "port_scan_alerts": port_scan_alerts,
        "syn_flood_alerts": syn_flood_alerts,
        "dns_anomaly_alerts": dns_anomaly_alerts,
    }


def create_traffic_summary(packets):
    """Calculate general information about the capture."""

    total_bytes = 0

    if "packet_length" in packets.columns:
        total_bytes = int(
            pd.to_numeric(
                packets["packet_length"],
                errors="coerce"
            )
            .fillna(0)
            .sum()
        )

    return {
        "total_packets": len(packets),
        "total_bytes": total_bytes,
        "unique_sources": safe_nunique(
            packets,
            "source_ip"
        ),
        "unique_destinations": safe_nunique(
            packets,
            "destination_ip"
        ),
        "unique_protocols": safe_nunique(
            packets,
            "protocol"
        ),
        "dns_queries": safe_non_null_count(
            packets,
            "dns_query"
        ),
    }


def count_severities(*alert_tables):
    """Count Low, Medium and High alerts."""

    counts = {
        "High": 0,
        "Medium": 0,
        "Low": 0,
    }

    for table in alert_tables:
        if table.empty or "severity" not in table.columns:
            continue

        table_counts = table["severity"].value_counts()

        for severity in counts:
            counts[severity] += int(
                table_counts.get(severity, 0)
            )

    return counts


def safe_nunique(packets, column):
    if column not in packets.columns:
        return 0

    return int(packets[column].dropna().nunique())


def safe_non_null_count(packets, column):
    if column not in packets.columns:
        return 0

    return int(packets[column].notna().sum())


def empty_analysis():
    """Return a consistent result for an empty capture."""

    return {
        "summary": {
            "total_packets": 0,
            "total_bytes": 0,
            "unique_sources": 0,
            "unique_destinations": 0,
            "unique_protocols": 0,
            "dns_queries": 0,
        },
        "alert_counts": {
            "port_scans": 0,
            "syn_floods": 0,
            "dns_anomalies": 0,
            "total": 0,
        },
        "severity_counts": {
            "High": 0,
            "Medium": 0,
            "Low": 0,
        },
        "port_scan_alerts": pd.DataFrame(),
        "syn_flood_alerts": pd.DataFrame(),
        "dns_anomaly_alerts": pd.DataFrame(),
    }