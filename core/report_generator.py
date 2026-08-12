from datetime import datetime, timezone
from html import escape

import pandas as pd


def generate_html_report(analysis, capture_name):
    """
    Generate a downloadable HTML investigation report.

    Parameters:
        analysis: Dictionary returned by analyze_packets().
        capture_name: Original uploaded PCAP filename.

    Returns:
        The completed report as an HTML string.
    """

    summary = analysis["summary"]
    alert_counts = analysis["alert_counts"]
    severity_counts = analysis["severity_counts"]

    generated_at = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )

    overall_assessment = determine_overall_assessment(
        alert_counts,
        severity_counts,
    )

    port_scan_table = dataframe_to_html(
        analysis["port_scan_alerts"],
        "No possible port scans were detected.",
    )

    syn_flood_table = dataframe_to_html(
        analysis["syn_flood_alerts"],
        "No possible SYN floods were detected.",
    )

    dns_anomaly_table = dataframe_to_html(
        analysis["dns_anomaly_alerts"],
        "No DNS anomalies were detected.",
    )

    report = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>NetSleuth Investigation Report</title>

    <style>
        body {{
            font-family: Arial, sans-serif;
            max-width: 1100px;
            margin: 40px auto;
            padding: 0 20px;
            color: #1f2937;
            line-height: 1.5;
        }}

        h1 {{
            color: #0f172a;
            border-bottom: 3px solid #2563eb;
            padding-bottom: 10px;
        }}

        h2 {{
            color: #1e3a8a;
            margin-top: 35px;
        }}

        .metadata {{
            background-color: #f1f5f9;
            padding: 15px;
            border-left: 5px solid #2563eb;
            border-radius: 4px;
        }}

        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 12px;
            margin: 20px 0;
        }}

        .summary-card {{
            background-color: #f8fafc;
            border: 1px solid #cbd5e1;
            border-radius: 6px;
            padding: 15px;
        }}

        .summary-card strong {{
            display: block;
            color: #475569;
        }}

        .summary-card span {{
            display: block;
            margin-top: 5px;
            font-size: 24px;
            font-weight: bold;
        }}

        .assessment {{
            background-color: #fff7ed;
            border-left: 5px solid #f97316;
            padding: 15px;
            margin: 20px 0;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            font-size: 14px;
        }}

        th {{
            background-color: #1e3a8a;
            color: white;
            text-align: left;
            padding: 9px;
        }}

        td {{
            border: 1px solid #cbd5e1;
            padding: 8px;
            overflow-wrap: anywhere;
        }}

        tr:nth-child(even) {{
            background-color: #f8fafc;
        }}

        .no-findings {{
            color: #166534;
            background-color: #f0fdf4;
            border-left: 5px solid #22c55e;
            padding: 12px;
        }}

        .notice {{
            background-color: #fefce8;
            border-left: 5px solid #eab308;
            padding: 12px;
            margin-top: 30px;
        }}

        footer {{
            border-top: 1px solid #cbd5e1;
            margin-top: 40px;
            padding-top: 15px;
            color: #64748b;
            font-size: 13px;
        }}

        @media print {{
            body {{
                margin: 15px;
            }}

            .summary-card,
            table {{
                break-inside: avoid;
            }}
        }}
    </style>
</head>

<body>
    <h1>NetSleuth Security Investigation Report</h1>

    <div class="metadata">
        <strong>Capture file:</strong> {escape(capture_name)}<br>
        <strong>Report generated:</strong> {generated_at}<br>
        <strong>Analysis type:</strong> Offline rule-based PCAP analysis
    </div>

    <h2>Executive Summary</h2>

    <div class="assessment">
        {escape(overall_assessment)}
    </div>

    <div class="summary-grid">
        {create_card("Packets analyzed", summary["total_packets"])}
        {create_card("Traffic volume", format_bytes(summary["total_bytes"]))}
        {create_card("Source IPs", summary["unique_sources"])}
        {create_card("Destination IPs", summary["unique_destinations"])}
        {create_card("Protocols", summary["unique_protocols"])}
        {create_card("DNS queries", summary["dns_queries"])}
    </div>

    <h2>Alert Summary</h2>

    <table>
        <thead>
            <tr>
                <th>Finding type</th>
                <th>Number of alerts</th>
            </tr>
        </thead>

        <tbody>
            <tr>
                <td>Possible port scans</td>
                <td>{alert_counts["port_scans"]}</td>
            </tr>
            <tr>
                <td>Possible SYN floods</td>
                <td>{alert_counts["syn_floods"]}</td>
            </tr>
            <tr>
                <td>Possible DNS anomalies</td>
                <td>{alert_counts["dns_anomalies"]}</td>
            </tr>
            <tr>
                <td><strong>Total</strong></td>
                <td><strong>{alert_counts["total"]}</strong></td>
            </tr>
        </tbody>
    </table>

    <h2>Severity Summary</h2>

    <table>
        <thead>
            <tr>
                <th>Severity</th>
                <th>Number of alerts</th>
            </tr>
        </thead>

        <tbody>
            <tr>
                <td>High</td>
                <td>{severity_counts["High"]}</td>
            </tr>
            <tr>
                <td>Medium</td>
                <td>{severity_counts["Medium"]}</td>
            </tr>
            <tr>
                <td>Low</td>
                <td>{severity_counts["Low"]}</td>
            </tr>
        </tbody>
    </table>

    <h2>Port-Scan Findings</h2>
    {port_scan_table}

    <h2>SYN-Flood Findings</h2>
    {syn_flood_table}

    <h2>DNS-Anomaly Findings</h2>
    {dns_anomaly_table}

    <h2>Recommended Investigation Actions</h2>

    <ol>
        <li>Verify whether the source and destination systems are authorized.</li>
        <li>Inspect the packet numbers listed in each finding using Wireshark.</li>
        <li>Compare the activity with approved scans or administrative tasks.</li>
        <li>Review related firewall, DNS, server and endpoint logs.</li>
        <li>Escalate high-severity findings when the activity is unexplained.</li>
    </ol>

    <div class="notice">
        <strong>Analyst notice:</strong>
        These findings are generated using rule-based detection.
        They indicate activity requiring investigation and do not prove
        that a confirmed cyberattack occurred.
    </div>

    <footer>
        Generated by NetSleuth — PCAP Security Investigation Dashboard
    </footer>
</body>
</html>
"""

    return report


def dataframe_to_html(dataframe, empty_message):
    """Convert a findings DataFrame into a safe HTML table."""

    if dataframe is None or dataframe.empty:
        return f'<p class="no-findings">{escape(empty_message)}</p>'

    display_table = dataframe.copy()

    # Make column names easier to read.
    display_table.columns = [
        column.replace("_", " ").title()
        for column in display_table.columns
    ]

    return display_table.to_html(
        index=False,
        border=0,
        escape=True,
        na_rep="-",
    )


def create_card(label, value):
    """Create one summary card."""

    return (
        '<div class="summary-card">'
        f"<strong>{escape(str(label))}</strong>"
        f"<span>{escape(str(value))}</span>"
        "</div>"
    )


def determine_overall_assessment(alert_counts, severity_counts):
    """Create a short, non-definitive assessment."""

    if alert_counts["total"] == 0:
        return (
            "No activity matched the current detection rules. "
            "This does not guarantee that the capture is free from threats."
        )

    if severity_counts["High"] > 0:
        return (
            "High-severity activity was identified. Immediate manual "
            "investigation of the supporting packets is recommended."
        )

    if severity_counts["Medium"] > 0:
        return (
            "Potentially suspicious activity was identified. The findings "
            "should be validated against expected network behavior."
        )

    return (
        "Low-severity activity was identified. Review the evidence to "
        "determine whether it represents normal or suspicious behavior."
    )


def format_bytes(byte_count):
    """Convert a byte count into a readable value."""

    byte_count = float(byte_count)

    for unit in ["bytes", "KB", "MB", "GB"]:
        if byte_count < 1024 or unit == "GB":
            if unit == "bytes":
                return f"{int(byte_count):,} {unit}"

            return f"{byte_count:,.2f} {unit}"

        byte_count /= 1024