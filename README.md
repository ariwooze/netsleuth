# NetSleuth

**A PCAP-Based Network Security Investigation and Threat Analysis Dashboard**

NetSleuth is a beginner-friendly, local web application for examining packet-capture files. It converts raw network packets into readable summaries, interactive visualizations, explainable security findings, and packet-level evidence that an analyst can investigate.

The project is intended for offline analysis of `.pcap` and `.pcapng` files. It does not capture live traffic, block attacks, or replace a professional intrusion-detection system

## Why This Project?

Packet captures can contain thousands of records, making manual investigation time-consuming for beginners. NetSleuth aims to simplify the first stage of network investigation by helping users answer questions such as:

- Which hosts generated the most traffic?
- Which protocols and ports appear in the capture?
- Are there patterns consistent with port scanning or a SYN flood?
- What packet evidence supports each security finding?
- Which findings should an analyst investigate first?

All detections are rule-based and explainable. A finding indicates suspicious activity that requires investigation; it does not prove that an attack occurred.

## Features

### Initial version

- Upload `.pcap` and `.pcapng` files
- Parse packets locally with TShark and PyShark
- Display packet count, traffic volume, IP addresses, protocols, and ports
- Visualize protocol distribution and top network talkers
- Detect possible port-scanning activity
- Show the packet-level evidence behind findings

### Planned

- Possible SYN-flood detection
- DNS anomaly detection
- Cleartext credential and protocol warnings
- Suspicious outbound-connection detection
- Search and filtering for investigation tables
- Severity scoring and alert details
- Investigation-report export

## How It Works

1. The user uploads a packet-capture file.
2. The application temporarily saves it for local processing.
3. PyShark uses TShark to extract selected packet fields.
4. Pandas structures the extracted fields for analysis.
5. Detection modules evaluate the traffic using transparent rules.
6. Streamlit and Plotly display summaries, charts, findings, and evidence.
7. The temporary uploaded file is removed after processing.

## Technology Stack

| Tool | Purpose |
|---|---|
| Python | Core application and detection logic |
| TShark | Packet-field extraction from capture files |
| PyShark | Python interface for TShark |
| Pandas | Packet-data cleaning, grouping, and analysis |
| Streamlit | Local web dashboard |
| Plotly | Interactive charts |
| Wireshark | Manual validation of findings |

## Project Structure

```text
netsleuth/
├── app.py                    # Streamlit application
├── requirements.txt          # Python dependencies
├── core/
│   ├── __init__.py
│   ├── pcap_parser.py        # Packet extraction and conversion
│   ├── analyzer.py           # Shared traffic-analysis functions
│   └── report_generator.py   # Generated investigation reports        
├── detectors/
│   ├── __init__.py
│   ├── port_scan.py          # Port-scan detection
│   ├── syn_flood.py          # Planned SYN-flood detection
│   └── dns_anomaly.py        # Planned DNS analysis
├── sample_pcaps/             # Authorized test captures
│   ├── normal_traffic.pcap
│   ├── port_scan.pcap
│   ├── syn_flood.pcap
│   ├── dns_anomaly.pcap
│   └── combined_findings.pcap                
└── README.md
```

The exact structure may change as the project develops.

## Prerequisites

Before starting, install:

- Python 3.10 or newer
- `pip`
- TShark
- Git

The project is being developed on Kali Linux, but it can also run on another operating system if Python and TShark are correctly installed.

Confirm the main tools are available:

```bash
python3 --version
pip3 --version
tshark --version
git --version
```

On Kali or Debian-based Linux, missing packages can be installed with:

```bash
sudo apt update
sudo apt install python3-pip python3-venv tshark git -y
```

## Installation

Clone the repository and enter the project directory:

```bash
git clone https://github.com/ariwooze/netsleuth.git
cd netsleuth
```

Create a virtual environment:

```bash
python3 -m venv venv
```

Activate it:

```bash
source venv/bin/activate
```

Install the Python dependencies:

```bash
pip install -r requirements.txt
```

## Running the Dashboard

Start the application from the project directory:

```bash
streamlit run app.py
```

Streamlit will normally open the dashboard at:

```text
http://localhost:8501
```

Upload an authorized `.pcap` or `.pcapng` file and wait for the analysis to finish. Large captures may take longer to process; the first version limits the number of packets analyzed to keep resource use manageable.

Stop the application by pressing `Ctrl+C` in the terminal.

## Detection Logic

NetSleuth uses rule-based detection to identify network activity that may require further investigation. A finding does not confirm that an attack occurred. Analysts should validate each result using packet evidence and environmental context.

### Possible Port Scan

The detector groups packets by source and destination IP address, then counts the number of unique destination ports contacted. If the number exceeds a configured threshold, NetSleuth creates a finding.

| Unique destination ports | Severity |
| -----------------------: | -------- |
|                    15–39 | Low      |
|                    40–99 | Medium   |
|              100 or more | High     |

Legitimate vulnerability scanners, administrators, monitoring tools, and applications may create similar traffic. Port-scan findings should therefore be validated against authorized scanning activities and expected network behaviour.

### Possible SYN Flood

The detector examines TCP traffic and groups packets by source IP address, destination IP address, and destination port. It counts TCP SYN packets without the ACK flag within a 10-second window.

If the number exceeds a configured threshold, NetSleuth creates a finding.

| SYN packets within 10 seconds | Severity |
| ----------------------------: | -------- |
|                         20–49 | Low      |
|                         50–99 | Medium   |
|                   100 or more | High     |

A large number of SYN packets may indicate an attempt to exhaust the destination system's available connection resources.

However, legitimate traffic bursts, unavailable servers, network interruptions, or incomplete packet captures may produce similar results. Analysts should check for corresponding SYN-ACK or RST responses before confirming a SYN-flood attack.

### Possible DNS Anomaly

The detector examines DNS query traffic for two types of unusual behaviour:

1. Repeated requests for the same domain from the same source.
2. DNS queries containing unusually long domain names.

#### Repeated DNS Queries

The detector groups DNS packets by source IP address and queried domain, then counts identical queries within a 60-second window.

| Identical queries within 60 seconds | Severity |
| ----------------------------------: | -------- |
|                               10–19 | Low      |
|                               20–49 | Medium   |
|                          50 or more | High     |

Repeated DNS requests may be caused by application behaviour, DNS retries, configuration problems, automated scripts, or malware attempting command-and-control communication.

#### Unusually Long DNS Queries

The detector calculates the total number of characters in each queried domain name.

| Domain-name length      | Severity |
| ----------------------: | -------- |
|        50–74 characters | Low      |
|        75–99 characters | Medium   |
| 100 or more characters  | High     |

Long domain names may be associated with encoded information, DNS tunnelling, tracking services, or automatically generated subdomains. However, legitimate cloud services and content-delivery networks may also use long domain names.

When a DNS query matches more than one condition, NetSleuth assigns the highest applicable severity.

DNS findings should be validated using:

- The source system generating the requests
- The queried domain and its reputation
- The number and frequency of queries
- DNS response codes
- Query and response sizes
- Related network and endpoint activity

> **Important:** These thresholds are starting values for a learning project. They may require adjustment for different network sizes, traffic patterns, capture durations, and operational environments.

# Sample PCAP Test Pack

These packet captures contain only synthetic traffic generated for an isolated test environment. The IP ranges (`192.0.2.0/24` and `198.51.100.0/24`) and `.test` domain names are reserved for documentation and testing.

| File | Packets | Intended result |
| --- | ---: | --- |
| `normal_traffic.pcap` | 26 | No alerts under typical thresholds |
| `port_scan.pcap` | 80 | Port-scan alert: one source contacts 80 destination ports |
| `syn_flood.pcap` | 300 | SYN-flood alert: 300 unanswered SYN packets in under one second |
| `dns_anomaly.pcap` | 38 | DNS alerts: 35 repeated queries and 3 long queries |
| `combined_findings.pcap` | 418 | Alerts from all three detectors, 447 packets with different IPs, ports, domains, and traffic volumes.|

## Test procedure

1. Start NetSleuth with `python -m streamlit run app.py`.
2. Upload `normal_traffic.pcap` and confirm that the packet summary loads without a security alert.
3. Upload each attack-specific sample and check the corresponding findings tab.
4. Upload `combined_findings.pcap` and confirm that all three detector categories report findings.
5. Download the PDF report and confirm that its counts and detailed findings match the dashboard.

Exact alert counts depend on the thresholds and grouping logic in your detector modules. If a detector does not trigger, compare its configured threshold with the traffic volumes shown above.

## Wireshark display filters

| Sample | Filter |
| --- | --- |
| Port scan | `ip.src == 192.0.2.50 && tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| SYN flood | `ip.dst == 198.51.100.80 && tcp.dstport == 80 && tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| DNS anomaly | `dns.qry.name` |

## Data and Privacy

- Uploaded captures are processed locally.
- Do not commit PCAP files containing private or sensitive traffic to GitHub.
- Sanitize screenshots before publishing them.
- Avoid displaying credentials, tokens, personal data, internal IP plans, or confidential domain names.
- Use synthetic, public training, or self-generated captures whenever possible.

## Known Limitations

- Rule-based findings may produce false positives and false negatives.
- Thresholds may not suit every network or capture duration.
- Encrypted traffic limits application-layer visibility.
- The initial packet limit may exclude activity later in a large capture.
- IP addresses are not automatically classified as trusted or malicious.
- NetSleuth performs offline analysis and does not provide real-time monitoring.
- A security finding is an investigation lead, not confirmation of an attack.

## Roadmap

- [x] Build the PCAP upload interface
- [x] Implement packet parsing and data cleaning
- [x] Add summary metrics and protocol visualizations
- [x] Implement and validate port-x] Add evidence filters and alert investigation views
- [x] Add investigation-report export
- [x] Add sanitized sample captures

These checkboxes will be updated once each feature is completed so visitors can immediately understand the project's progress.

## Ethical Use

NetSleuth is created for cybersecurity education, defensive analysis, and authorized laboratory testing. Analyze only networks, systems, and capture files that you own or are explicitly authorized to examine. You are responsible for following applicable laws, organizational policies, and privacy requirements.
