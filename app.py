import os
import tempfile

import plotly.express as px
import streamlit as st

from core.analyzer import analyze_packets
from core.pcap_parser import parse_pcap
from core.report_generator import generate_html_report


# ---------------------------------------------------------
# Page configuration
# ---------------------------------------------------------

st.set_page_config(
    page_title="NetSleuth",
    page_icon="🔍",
    layout="wide",
)


# ---------------------------------------------------------
# Helper functions
# ---------------------------------------------------------

def format_bytes(byte_count):
    """Convert bytes into a readable format."""

    byte_count = float(byte_count or 0)

    for unit in ["bytes", "KB", "MB", "GB"]:
        if byte_count < 1024 or unit == "GB":
            if unit == "bytes":
                return f"{int(byte_count):,} {unit}"

            return f"{byte_count:,.2f} {unit}"

        byte_count /= 1024


def display_alert_table(
    alerts,
    empty_message,
    finding_name,
):
    """Display one detector's findings."""

    if alerts is None or alerts.empty:
        st.success(empty_message)
        return

    st.warning(
        f"Detected {len(alerts)} possible "
        f"{finding_name}(s) requiring investigation."
    )

    st.dataframe(
        alerts,
        use_container_width=True,
        hide_index=True,
    )


# ---------------------------------------------------------
# Application header
# ---------------------------------------------------------

st.title("🔍 NetSleuth")
st.subheader("PCAP Security Investigation Dashboard")

st.write(
    "Upload a PCAP or PCAPNG file to summarize network traffic, "
    "identify suspicious activity and generate an investigation report."
)

st.info(
    "NetSleuth uses rule-based detection. Its findings indicate "
    "activity requiring investigation and do not prove that an "
    "attack occurred."
)


# ---------------------------------------------------------
# Sidebar
# ---------------------------------------------------------

with st.sidebar:
    st.header("About NetSleuth")

    st.write(
        "NetSleuth is an offline packet-capture analysis platform "
        "for investigating network activity."
    )

    st.subheader("Current detectors")

    st.markdown(
        """
        - Possible port scans
        - Possible SYN floods
        - DNS anomalies
        """
    )

    st.subheader("Privacy reminder")

    st.caption(
        "Only upload packet captures that you are authorized to "
        "analyze. PCAP files may contain sensitive information."
    )


# ---------------------------------------------------------
# File upload
# ---------------------------------------------------------

uploaded_file = st.file_uploader(
    "Upload a packet capture",
    type=["pcap", "pcapng"],
    help="Maximum packet processing depends on the limit in pcap_parser.py.",
)

if uploaded_file is None:
    st.info("Upload a PCAP or PCAPNG file to begin the investigation.")
    st.stop()


# ---------------------------------------------------------
# Save uploaded capture temporarily
# ---------------------------------------------------------

temporary_path = None

try:
    file_suffix = os.path.splitext(uploaded_file.name)[1]

    if not file_suffix:
        file_suffix = ".pcap"

    with tempfile.NamedTemporaryFile(
        delete=False,
        suffix=file_suffix,
    ) as temporary_file:
        temporary_file.write(uploaded_file.getbuffer())
        temporary_path = temporary_file.name

    # -----------------------------------------------------
    # Parse the capture
    # -----------------------------------------------------

    with st.spinner("Extracting and analyzing packets..."):
        packets = parse_pcap(temporary_path)

    if packets is None or packets.empty:
        st.warning(
            "No readable packets were found in the uploaded capture."
        )
        st.stop()

    # -----------------------------------------------------
    # Run the analyzers
    # -----------------------------------------------------

    analysis = analyze_packets(packets)

    summary = analysis["summary"]
    alert_counts = analysis["alert_counts"]
    severity_counts = analysis["severity_counts"]

    st.success(
        f"Successfully analyzed {summary['total_packets']:,} packets "
        f"from {uploaded_file.name}."
    )

    # -----------------------------------------------------
    # Capture summary
    # -----------------------------------------------------

    st.header("Capture summary")

    column1, column2, column3, column4 = st.columns(4)

    column1.metric(
        "Packets",
        f"{summary['total_packets']:,}",
    )

    column2.metric(
        "Traffic volume",
        format_bytes(summary["total_bytes"]),
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

    # -----------------------------------------------------
    # Security overview
    # -----------------------------------------------------

    st.header("Security overview")

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

    severity_column1, severity_column2, severity_column3 = (
        st.columns(3)
    )

    severity_column1.metric(
        "High severity",
        severity_counts["High"],
    )

    severity_column2.metric(
        "Medium severity",
        severity_counts["Medium"],
    )

    severity_column3.metric(
        "Low severity",
        severity_counts["Low"],
    )

    if alert_counts["total"] == 0:
        st.success(
            "No activity matched the current detection rules. "
            "This does not guarantee that the capture is threat-free."
        )
    elif severity_counts["High"] > 0:
        st.error(
            "High-severity activity was detected. Review the "
            "supporting packets as soon as possible."
        )
    elif severity_counts["Medium"] > 0:
        st.warning(
            "Potentially suspicious activity was detected and "
            "should be manually investigated."
        )
    else:
        st.info(
            "Low-severity findings were detected. Review them to "
            "determine whether the activity is expected."
        )

    # -----------------------------------------------------
    # Traffic visualizations
    # -----------------------------------------------------

    st.header("Traffic analysis")

    chart_tab1, chart_tab2, chart_tab3 = st.tabs(
        [
            "Protocols",
            "Top source IPs",
            "Top destination IPs",
        ]
    )

    with chart_tab1:
        if "protocol" not in packets.columns:
            st.info("Protocol information is unavailable.")
        else:
            protocol_counts = (
                packets["protocol"]
                .fillna("Unknown")
                .value_counts()
                .head(15)
                .reset_index()
            )

            protocol_counts.columns = [
                "protocol",
                "packet_count",
            ]

            protocol_chart = px.bar(
                protocol_counts,
                x="protocol",
                y="packet_count",
                title="Most common protocols",
                labels={
                    "protocol": "Protocol",
                    "packet_count": "Packet count",
                },
                color="packet_count",
                color_continuous_scale="Blues",
            )

            protocol_chart.update_layout(
                coloraxis_showscale=False
            )

            st.plotly_chart(
                protocol_chart,
                use_container_width=True,
            )

    with chart_tab2:
        if "source_ip" not in packets.columns:
            st.info("Source-IP information is unavailable.")
        else:
            source_counts = (
                packets["source_ip"]
                .dropna()
                .value_counts()
                .head(10)
                .reset_index()
            )

            source_counts.columns = [
                "source_ip",
                "packet_count",
            ]

            if source_counts.empty:
                st.info("No source IP addresses were extracted.")
            else:
                source_chart = px.bar(
                    source_counts,
                    x="packet_count",
                    y="source_ip",
                    orientation="h",
                    title="Top source IP addresses",
                    labels={
                        "source_ip": "Source IP",
                        "packet_count": "Packet count",
                    },
                    color="packet_count",
                    color_continuous_scale="Teal",
                )

                source_chart.update_layout(
                    yaxis={"categoryorder": "total ascending"},
                    coloraxis_showscale=False,
                )

                st.plotly_chart(
                    source_chart,
                    use_container_width=True,
                )

                st.dataframe(
                    source_counts,
                    use_container_width=True,
                    hide_index=True,
                )

    with chart_tab3:
        if "destination_ip" not in packets.columns:
            st.info("Destination-IP information is unavailable.")
        else:
            destination_counts = (
                packets["destination_ip"]
                .dropna()
                .value_counts()
                .head(10)
                .reset_index()
            )

            destination_counts.columns = [
                "destination_ip",
                "packet_count",
            ]

            if destination_counts.empty:
                st.info(
                    "No destination IP addresses were extracted."
                )
            else:
                destination_chart = px.bar(
                    destination_counts,
                    x="packet_count",
                    y="destination_ip",
                    orientation="h",
                    title="Top destination IP addresses",
                    labels={
                        "destination_ip": "Destination IP",
                        "packet_count": "Packet count",
                    },
                    color="packet_count",
                    color_continuous_scale="Purples",
                )

                destination_chart.update_layout(
                    yaxis={"categoryorder": "total ascending"},
                    coloraxis_showscale=False,
                )

                st.plotly_chart(
                    destination_chart,
                    use_container_width=True,
                )

                st.dataframe(
                    destination_counts,
                    use_container_width=True,
                    hide_index=True,
                )

    # -----------------------------------------------------
    # Security findings
    # -----------------------------------------------------

    st.header("Security findings")

    finding_tab1, finding_tab2, finding_tab3 = st.tabs(
        [
            "Port scans",
            "SYN floods",
            "DNS anomalies",
        ]
    )

    with finding_tab1:
        st.write(
            "Identifies a source contacting an unusually large "
            "number of destination ports."
        )

        display_alert_table(
            alerts=analysis["port_scan_alerts"],
            empty_message=(
                "No possible port scans matched the current threshold."
            ),
            finding_name="port scan",
        )

    with finding_tab2:
        st.write(
            "Identifies a high number of TCP SYN packets where "
            "many connections appear to remain unanswered."
        )

        display_alert_table(
            alerts=analysis["syn_flood_alerts"],
            empty_message=(
                "No possible SYN floods matched the current threshold."
            ),
            finding_name="SYN flood",
        )

    with finding_tab3:
        st.write(
            "Identifies unusually long or frequently repeated "
            "DNS queries."
        )

        display_alert_table(
            alerts=analysis["dns_anomaly_alerts"],
            empty_message=(
                "No DNS anomalies matched the current threshold."
            ),
            finding_name="DNS anomaly",
        )

    # -----------------------------------------------------
    # Packet evidence
    # -----------------------------------------------------

    st.header("Packet evidence")

    st.caption(
        "Use the filters below to narrow the packet table before "
        "investigating the original capture in Wireshark."
    )

    filtered_packets = packets.copy()

    filter_column1, filter_column2 = st.columns(2)

    with filter_column1:
        if "protocol" in packets.columns:
            available_protocols = sorted(
                packets["protocol"]
                .dropna()
                .astype(str)
                .unique()
                .tolist()
            )

            selected_protocols = st.multiselect(
                "Filter by protocol",
                options=available_protocols,
            )

            if selected_protocols:
                filtered_packets = filtered_packets[
                    filtered_packets["protocol"]
                    .astype(str)
                    .isin(selected_protocols)
                ]

    with filter_column2:
        ip_search = st.text_input(
            "Search for an IP address",
            placeholder="Example: 192.168.56.102",
        )

        if ip_search:
            source_matches = (
                filtered_packets["source_ip"]
                .fillna("")
                .astype(str)
                .str.contains(
                    ip_search,
                    case=False,
                    regex=False,
                )
            )

            destination_matches = (
                filtered_packets["destination_ip"]
                .fillna("")
                .astype(str)
                .str.contains(
                    ip_search,
                    case=False,
                    regex=False,
                )
            )

            filtered_packets = filtered_packets[
                source_matches | destination_matches
            ]

    st.write(
        f"Displaying {len(filtered_packets):,} of "
        f"{len(packets):,} packets."
    )

    st.dataframe(
        filtered_packets,
        use_container_width=True,
        hide_index=True,
    )

    # -----------------------------------------------------
    # Report export
    # -----------------------------------------------------

    st.header("Export investigation report")

    html_report = generate_html_report(
        analysis=analysis,
        capture_name=uploaded_file.name,
    )

    capture_base_name = os.path.splitext(
        uploaded_file.name
    )[0]

    report_filename = (
        f"netsleuth_report_{capture_base_name}.html"
    )

    st.download_button(
        label="Download HTML investigation report",
        data=html_report,
        file_name=report_filename,
        mime="text/html",
        use_container_width=True,
    )

    st.caption(
        "To create a PDF, open the downloaded HTML report in a "
        "browser and select Print → Save as PDF."
    )

except Exception as error:
    st.error("NetSleuth could not analyze the uploaded capture.")

    st.exception(error)

    st.info(
        "Check that TShark is installed, the uploaded file is a "
        "valid PCAP or PCAPNG file, and all required Python "
        "packages are installed."
    )

finally:
    if temporary_path and os.path.exists(temporary_path):
        os.remove(temporary_path)