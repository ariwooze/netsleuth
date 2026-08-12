import os
import tempfile

import plotly.express as px
import streamlit as st

from core.pcap_parser import parse_pcap
from detectors.port_scan import detect_port_scans

st.set_page_config(
    page_title="NetSleuth",
    page_icon="🔍",
    layout="wide"
)

st.title("NetSleuth")
st.subheader("Upload a packet capture")

uploaded_file = st.file_uploader(
    "Upload a PCAP file for analysis",
    type=["pcap", "pcapng"]
)

if uploaded_file is None:
    st.info("Upload a PCAP or PCAPNG file to begin.")
    st.stop()

temporary_path = None

try:
    file_suffix = os.path.splitext(uploaded_file.name)[1]

    with tempfile.NamedTemporaryFile(
        delete=False,
        suffix=file_suffix
    ) as temporary_file:
        temporary_file.write(uploaded_file.getbuffer())
        temporary_path = temporary_file.name

    with st.spinner("Extracting packets..."):
        packets = parse_pcap(temporary_path)

    if packets.empty:
        st.warning("No readable packets were found")
        st.stop()

    st.success(f"Analyzed {len(packets):,} packets")

    total_bytes = int(packets["packet_length"].fillna(0).sum())
    unique_sources = packets["source_ip"].nunique()
    unique_destinations = packets["destination_ip"].nunique()

    column1, column2, column3, column4 = st.columns(4)

    column1.metric("Packets", f"{len(packets):,}")
    column2.metric("Traffic volume", f"{total_bytes:,} bytes")
    column3.metric("Source IPs", unique_sources)
    column4.metric("Destination IPs", unique_destinations)

    port_scan_alerts = detect_port_scans(packets)

    st.header("Security findings")

    if port_scan_alerts.empty:
        st.success("No port scans matched the current detection threshold.")
    else:
        st.warning(
            f"Detected {len(port_scan_alerts)} possible port-scan activities."
        )

        st.dataframe(
            port_scan_alerts,
            use_container_width=True,
            hide_index=True
        )

    st.header("Protocol distribution")

    protocol_counts = (
        packets["protocol"]
        .fillna("Unknown")
        .value_counts()
        .reset_index()
    )
    protocol_counts.columns = ["protocol", "packet_count"]

    protocol_chart = px.bar(
        protocol_counts.head(15),
        x="protocol",
        y="packet_count",
        title="Most common protocols"
    )

    st.plotly_chart(protocol_chart, use_container_width=True)

    st.header("Top source addresses")

    source_counts = (
        packets["source_ip"]
        .dropna()
        .value_counts()
        .head(10)
        .reset_index()
    )
    source_counts.columns = ["source_ip", "packet_count"]

    st.dataframe(source_counts, use_container_width=True)

    st.header("Packet evidence")

    st.dataframe(
        packets,
        use_container_width=True,
        hide_index=True
    )

finally:
    if temporary_path and os.path.exists(temporary_path):
        os.remove(temporary_path)