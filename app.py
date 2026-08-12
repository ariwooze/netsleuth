import os
import tempfile

import pandas as pd
import plotly.express as px
import streamlit as st

from core.analyzer import analyze_packets
from core.pcap_parser import parse_pcap


st.set_page_config(
    page_title="NetSleuth",
    page_icon="🔍",
    layout="wide",
)

st.title("🔍 NetSleuth")
st.subheader("PCAP Security Investigation Dashboard")

st.info(
    "Upload a PCAP or PCAPNG file to summarize network traffic "
    "and identify possible port scans, SYN floods, and DNS anomalies."
)

uploaded_file = st.file_uploader(
    "Upload a packet capture",
    type=["pcap", "pcapng"],
)

if uploaded_file is None:
    st.write("No packet capture has been uploaded.")
    st.stop()

temporary_path = None

try:
    file_suffix = os.path.splitext(uploaded_file.name)[1]

    with tempfile.NamedTemporaryFile(
        delete=False,
        suffix=file_suffix,
    ) as temporary_file:
        temporary_file.write(uploaded_file.getbuffer())
        temporary_path = temporary_file.name

    with st.spinner("Extracting and analyzing packets..."):
        packets = parse_pcap(temporary_path)
        analysis = analyze_packets(packets)

    if packets.empty:
        st.warning("No readable packets were found in this capture.")
        st.stop()

    summary = analysis["summary"]
    alert_counts = analysis["alert_counts"]
    severity_counts = analysis["severity_counts"]

    st.success(
        f"Successfully analyzed {summary['total_packets']:,} packets "
        f"from {uploaded_file.name}"
    )

    # ---------------------------------------------------------
    # Traffic summary
    # ---------------------------------------------------------

    st.header("Traffic Summary")

    column1, column2, column3, column4 = st.columns(4)

    column1.metric(
        "Total packets",
        f"{summary['total_packets']:,}",
    )
    column2.metric(
        "Traffic volume",
        f"{summary['total_bytes']:,} bytes",
    )
    column3.metric(
        "Source IPs",
        summary["unique_sources"],
    )
    column4.metric(
        "Destination IPs",
        summary["unique_destinations"],
    )

    column5, column6 = st.columns(2)

    column5.metric(
        "Protocols",
        summary["unique_protocols"],
    )
    column6.metric(
        "DNS queries",
        summary["dns_queries"],
    )

    # ---------------------------------------------------------
    # Security overview
    # ---------------------------------------------------------

    st.header("Security Overview")

    alert_column1, alert_column2, alert_column3, alert_column4 = (
        st.columns(4)
    )

    alert_column1.metric(
        "Total alerts",
        alert_counts["total"],
    )
    alert_column2.metric(
        "Port scans",
        alert_counts["port_scans"],
    )
    alert_column3.metric(
        "SYN floods",
        alert_counts["syn_floods"],
    )
    alert_column4.metric(
        "DNS anomalies",
        alert_counts["dns_anomalies"],
    )

    if alert_counts["total"] == 0:
        st.success(
            "No activity matched the current detection thresholds."
        )
    else:
        st.warning(
            f"{alert_counts['total']} possible security finding(s) "
            "require investigation."
        )

    severity_table = pd.DataFrame(
        {
            "Severity": ["High", "Medium", "Low"],
            "Alert count": [
                severity_counts["High"],
                severity_counts["Medium"],
                severity_counts["Low"],
            ],
        }
    )

    severity_chart = px.bar(
        severity_table,
        x="Severity",
        y="Alert count",
        color="Severity",
        title="Alerts by severity",
        color_discrete_map={
            "High": "#d62728",
            "Medium": "#ff7f0e",
            "Low": "#f1c40f",
        },
        category_orders={
            "Severity": ["High", "Medium", "Low"],
        },
    )

    severity_chart.update_layout(showlegend=False)

    st.plotly_chart(
        severity_chart,
        use_container_width=True,
    )

    # ---------------------------------------------------------
    # Security findings
    # ---------------------------------------------------------

    st.header("Security Findings")

    port_scan_tab, syn_flood_tab, dns_anomaly_tab = st.tabs(
        [
            "Port Scans",
            "SYN Floods",
            "DNS Anomalies",
        ]
    )

    with port_scan_tab:
        port_scan_alerts = analysis["port_scan_alerts"]

        st.caption(
            "Detects a source contacting many destination ports "
            "on the same target."
        )

        if port_scan_alerts.empty:
            st.success("No possible port scans detected.")
        else:
            st.warning(
                f"{len(port_scan_alerts)} possible port scan(s) detected."
            )

            st.dataframe(
                port_scan_alerts,
                use_container_width=True,
                hide_index=True,
            )

    with syn_flood_tab:
        syn_flood_alerts = analysis["syn_flood_alerts"]

        st.caption(
            "Detects a high number of TCP SYN packets with a large "
            "proportion of unanswered connection attempts."
        )

        if syn_flood_alerts.empty:
            st.success("No possible SYN floods detected.")
        else:
            st.warning(
                f"{len(syn_flood_alerts)} possible SYN flood(s) detected."
            )

            st.dataframe(
                syn_flood_alerts,
                use_container_width=True,
                hide_index=True,
            )

    with dns_anomaly_tab:
        dns_anomaly_alerts = analysis["dns_anomaly_alerts"]

        st.caption(
            "Detects unusually long or frequently repeated DNS queries."
        )

        if dns_anomaly_alerts.empty:
            st.success("No possible DNS anomalies detected.")
        else:
            st.warning(
                f"{len(dns_anomaly_alerts)} possible DNS "
                "anomaly alert(s) detected."
            )

            st.dataframe(
                dns_anomaly_alerts,
                use_container_width=True,
                hide_index=True,
            )

    # ---------------------------------------------------------
    # Traffic visualizations
    # ---------------------------------------------------------

    st.header("Traffic Visualizations")

    protocol_column, source_column = st.columns(2)

    with protocol_column:
        protocol_counts = (
            packets["protocol"]
            .fillna("Unknown")
            .value_counts()
            .head(15)
            .reset_index()
        )

        protocol_counts.columns = [
            "Protocol",
            "Packet count",
        ]

        protocol_chart = px.bar(
            protocol_counts,
            x="Protocol",
            y="Packet count",
            title="Most Common Protocols",
            color="Packet count",
            color_continuous_scale="Blues",
        )

        protocol_chart.update_layout(
            coloraxis_showscale=False
        )

        st.plotly_chart(
            protocol_chart,
            use_container_width=True,
        )

    with source_column:
        source_counts = (
            packets["source_ip"]
            .dropna()
            .value_counts()
            .head(10)
            .reset_index()
        )

        source_counts.columns = [
            "Source IP",
            "Packet count",
        ]

        if source_counts.empty:
            st.info("No source IP addresses were extracted.")
        else:
            source_chart = px.bar(
                source_counts,
                x="Packet count",
                y="Source IP",
                orientation="h",
                title="Top Source IP Addresses",
                color="Packet count",
                color_continuous_scale="Oranges",
            )

            source_chart.update_layout(
                yaxis={
                    "categoryorder": "total ascending"
                },
                coloraxis_showscale=False,
            )

            st.plotly_chart(
                source_chart,
                use_container_width=True,
            )

    # ---------------------------------------------------------
    # Network conversations
    # ---------------------------------------------------------

    st.header("Top Network Conversations")

    conversations = packets.dropna(
        subset=["source_ip", "destination_ip"]
    ).copy()

    if conversations.empty:
        st.info("No IP conversations were found.")
    else:
        conversations = (
            conversations
            .groupby(
                ["source_ip", "destination_ip"],
                dropna=False,
            )
            .agg(
                packet_count=("packet_number", "count"),
                total_bytes=("packet_length", "sum"),
            )
            .reset_index()
            .sort_values(
                "packet_count",
                ascending=False,
            )
            .head(20)
        )

        conversations["total_bytes"] = pd.to_numeric(
            conversations["total_bytes"],
            errors="coerce",
        ).fillna(0).astype(int)

        conversations = conversations.rename(
            columns={
                "source_ip": "Source IP",
                "destination_ip": "Destination IP",
                "packet_count": "Packet count",
                "total_bytes": "Total bytes",
            }
        )

        st.dataframe(
            conversations,
            use_container_width=True,
            hide_index=True,
        )

    # ---------------------------------------------------------
    # Packet evidence
    # ---------------------------------------------------------

    st.header("Packet Evidence")

    st.caption(
        "Use the controls below to narrow the packet table. "
        "A security finding is an indicator requiring investigation, "
        "not proof of an attack."
    )

    filter_column1, filter_column2 = st.columns(2)

    available_protocols = sorted(
        packets["protocol"]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    with filter_column1:
        selected_protocols = st.multiselect(
            "Filter by protocol",
            options=available_protocols,
        )

    available_sources = sorted(
        packets["source_ip"]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    with filter_column2:
        selected_sources = st.multiselect(
            "Filter by source IP",
            options=available_sources,
        )

    filtered_packets = packets.copy()

    if selected_protocols:
        filtered_packets = filtered_packets[
            filtered_packets["protocol"]
            .astype(str)
            .isin(selected_protocols)
        ]

    if selected_sources:
        filtered_packets = filtered_packets[
            filtered_packets["source_ip"]
            .astype(str)
            .isin(selected_sources)
        ]

    st.write(
        f"Showing {len(filtered_packets):,} of "
        f"{len(packets):,} packets"
    )

    preferred_columns = [
        "packet_number",
        "timestamp",
        "source_ip",
        "destination_ip",
        "protocol",
        "source_port",
        "destination_port",
        "packet_length",
        "tcp_syn",
        "tcp_ack",
        "dns_query",
    ]

    visible_columns = [
        column
        for column in preferred_columns
        if column in filtered_packets.columns
    ]

    st.dataframe(
        filtered_packets[visible_columns],
        use_container_width=True,
        hide_index=True,
    )

    # ---------------------------------------------------------
    # Download packet data
    # ---------------------------------------------------------

    packet_csv = filtered_packets[
        visible_columns
    ].to_csv(index=False)

    st.download_button(
        label="Download filtered packet evidence as CSV",
        data=packet_csv,
        file_name="netsleuth_packet_evidence.csv",
        mime="text/csv",
    )

    # ---------------------------------------------------------
    # Limitations
    # ---------------------------------------------------------

    with st.expander("Detection limitations"):
        st.markdown(
            """
            - Findings are generated using rule-based thresholds.
            - An alert does not confirm that an attack occurred.
            - Legitimate scanning or testing can produce alerts.
            - Packet loss and incomplete captures can affect SYN analysis.
            - Legitimate cloud services may generate long DNS queries.
            - Only the configured packet limit is analyzed.
            """
        )

finally:
    if temporary_path and os.path.exists(temporary_path):
        os.remove(temporary_path)