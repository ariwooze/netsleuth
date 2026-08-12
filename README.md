# NetSleuth

**A PCAP-Based Network Security Investigation and Threat Analysis Dashboard**

NetSleuth is a beginner-friendly, local web application for examining packet-capture files. It converts raw network packets into readable summaries, interactive visualizations, explainable security findings, and packet-level evidence that an analyst can investigate.

The project is intended for offline analysis of `.pcap` and `.pcapng` files. It does not capture live traffic, block attacks, or replace a professional intrusion-detection system.

> **Project status:** Early development. The initial dashboard and detection modules are being built progressively. Features marked as planned may not be available yet.

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
│   └── analyzer.py           # Shared traffic-analysis functions
├── detectors/
│   ├── __init__.py
│   ├── port_scan.py          # Port-scan detection
│   ├── syn_flood.py          # Planned SYN-flood detection
│   └── dns_anomaly.py        # Planned DNS analysis
├── sample_pcaps/             # Authorized test captures (not committed)
├── reports/                  # Generated investigation reports
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

### Possible port scan

The initial detector groups packets by source and destination IP address, then counts the number of unique destination ports contacted. If the number exceeds a configured threshold, NetSleuth creates a finding.

| Unique destination ports | Severity |
|---:|---|
| 15–39 | Low |
| 40–99 | Medium |
| 100 or more | High |

These thresholds are starting values for a learning project. Legitimate vulnerability scanners, administrators, monitoring tools, and applications may create similar traffic, so the result must be validated using context and packet evidence.

## Testing the Port-Scan Detector

Use only systems that you own or have explicit permission to test. A safe option is an isolated Kali Linux and Metasploitable 2 lab.

1. Start a Wireshark capture on the isolated lab interface.
2. From Kali, scan your Metasploitable 2 VM:

   ```bash
   nmap -sS <METASPLOITABLE_IP>
   ```

3. Stop the capture and save it as `port_scan.pcapng`.
4. Upload the file to NetSleuth.
5. Confirm that the source, destination, port count, and severity are reasonable.
6. Validate the result in Wireshark with:

   ```text
   ip.src == <KALI_IP> && tcp.flags.syn == 1 && tcp.flags.ack == 0
   ```

Record the expected result, actual result, and supporting Wireshark evidence. This makes the testing process reproducible and demonstrates that dashboard findings were manually verified.

## Data and Privacy

- Uploaded captures are processed locally.
- Do not commit PCAP files containing private or sensitive traffic to GitHub.
- Sanitize screenshots before publishing them.
- Avoid displaying credentials, tokens, personal data, internal IP plans, or confidential domain names.
- Use synthetic, public training, or self-generated captures whenever possible.

Add capture files to `.gitignore`, for example:

```gitignore
*.pcap
*.pcapng
venv/
__pycache__/
.streamlit/secrets.toml
reports/*
!reports/.gitkeep
```

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
- [x] Implement and validate port-scan detection
- [ ] Add SYN-flood and DNS-anomaly detection
- [ ] Add evidence filters and alert investigation views
- [ ] Add investigation-report export
- [ ] Add automated tests and sample sanitized captures
- [ ] Publish screenshots and a demonstration video

These checkboxes will be updated once each feature is completed so visitors can immediately understand the project's progress.

## Ethical Use

NetSleuth is created for cybersecurity education, defensive analysis, and authorized laboratory testing. Analyze only networks, systems, and capture files that you own or are explicitly authorized to examine. You are responsible for following applicable laws, organizational policies, and privacy requirements.
