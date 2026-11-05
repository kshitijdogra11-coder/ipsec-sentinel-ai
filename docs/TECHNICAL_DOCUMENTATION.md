# IPsec Sentinel AI: Technical Documentation

## 1. Purpose
The platform assesses the security posture of IPsec VPN deployments from **passively captured traffic**. It needs no keys, does not decrypt, and does not need access to the gateways. It combines deterministic protocol dissection (for everything IKE sends in cleartext) with machine-learning inference (for everything ESP hides), and turns both into a scored, explainable and signed assessment.

## 2. Architecture
```
Capture ─► pcap_reader ─► capture.py ─► pipeline.py ─┬─► ike analysis (rules)          ─┐
 (pcap/ng)  (bounds-checked) (IKE/ESP/AH   (per tunnel) ├─► features.py ─► ml_engine.py   ├─► assessment.py ─► JSON / PDF / UI
                             classification)            └─► SA / replay / lifetime / PFS ─┘
```
| Module | Responsibility |
|---|---|
| `analyzer/pcap_reader.py` | Dependency-free pcap/pcapng reader. Supports Ethernet, RAW, SLL, SLL2, NULL, VLAN and IPv6 extension headers. Every slice is bounds-checked. |
| `analyzer/ike_parser.py` | IKEv1 (ISAKMP) and IKEv2 dissector: SA proposals and transforms, KE, Nonce, Notify, Vendor ID, ID, HASH, SK. |
| `analyzer/capture.py` | Classifies UDP/500 and UDP/4500 (non-ESP marker vs ESP-in-UDP vs keepalive), IP proto 50/51, and cleartext traffic. |
| `analyzer/features.py` | Side-channel feature engineering (§4). |
| `analyzer/ml_engine.py` | Loads the model bundle **only after its SHA-256 matches the manifest**, then serves class probabilities. |
| `analyzer/pipeline.py` | Groups traffic into tunnels and fuses rule-based and AI attributes, each with a confidence and a method. |
| `analyzer/assessment.py` | Scoring, findings, compliance, metadata exposure, threat matrix, executive summary. |
| `reports/pdf_report.py` | Executive and Technical PDF reports (ReportLab). |
| `testbed/` | Configurable IPsec traffic generator (§3). |
| `core/` | Config, database, authentication, audit chain, evidence crypto, middleware, job runner. |

## 3. VPN testbed and dataset generation
### 3.1 Generator (`backend/app/testbed/generator.py`)
- **IKEv2** (RFC 7296): IKE_SA_INIT is built byte-exact with multiple offered proposals, a KE payload of the correct size for the DH group, NAT-D, FRAGMENTATION_SUPPORTED, SIGNATURE_HASH_ALGORITHMS and a strongSwan Vendor ID. IKE_AUTH, CREATE_CHILD_SA and INFORMATIONAL are emitted as SK payloads whose length matches the negotiated cipher (IV, padding and ICV). The size of certificate authentication and of the PFS KE payload is modelled.
- **IKEv1** (RFC 2409): Main Mode (6 messages) and Aggressive Mode (3 messages, with cleartext ID and HASH_R). SA attributes cover encryption, hash, authentication method, group and life duration. Quick Mode includes an optional KE for PFS.
- **ESP/AH data plane:** encrypted with the **real algorithm** through Scapy `SecurityAssociation`: AES-CBC-128/256 + HMAC-SHA1-96/SHA2-256-128/SHA2-512-256/MD5-96, AES-GCM-128/256, 3DES, ESP-NULL, and AH. Tunnel or transport mode, IPv4/IPv6, NAT-T (UDP 4500).
- **Rekeying:** Child SA rekeys after a configurable lifetime, with new SPIs and a sequence number reset.
- **Traffic models** (`profiles.py`):
  - VoIP: SIP plus RTP G.711/G.729/Opus at 20 ms ptime with silence suppression.
  - Video: DASH/QUIC chunked bursts.
  - Web: TLS handshakes plus log-normal object sizes and think time.
  - E-mail: SMTP/IMAP dialogues, bulk upload or fetch, IDLE keepalives.
  - WhatsApp: persistent XMPP/TLS, receipts, typing indicators, media bursts, keepalives.
  - ICMP: echo request/reply.
- **Background traffic:** DNS queries and responses. **Attack injection:** ESP replay of previously sent packets.
- All output validates in Wireshark/tshark (IKE transforms, Vendor IDs and ESP SPIs are decoded correctly).

### 3.2 Real lab (`testbed/`)
`docker-compose.yml` defines two strongSwan gateways, two LAN hosts and a tap container. `gen_profiles.py` writes 12 swanctl profiles covering the PS matrix. `scripts/run_matrix.sh` runs every profile against every traffic type and records each run with tcpdump. These real captures can be uploaded directly, used to validate the model, or added to training.

### 3.3 Dataset (`dataset/`)
The dataset is built with `python -m ml.build_dataset --n 700`. It contains 700 captures (913,873 packets) sampled from four configuration tiers: strong, standard, legacy and weak.
- `labels.csv`: full ground-truth configuration per capture.
- `crypto_features.csv`: 53 crypto side-channel features per capture.
- `traffic_features.csv`: 49 traffic features per 30-second window (2,836 windows).
- `samples/`: 10 ready-to-analyse captures, one per preset.

## 4. AI methodology
### 4.1 Cryptographic side-channel features (per tunnel)
The ESP payload length after SPI and sequence number is `L = IV + pad(P + 2, block) + ICV`, and each cipher leaves its own arithmetic fingerprint:

| Cipher | IV | Block | ICV | Signature |
|---|---|---|---|---|
| AES-CBC + HMAC-SHA1-96 | 16 | 16 | 12 | `L mod 16 = 12` constant |
| AES-CBC + HMAC-SHA256-128 | 16 | 16 | 16 | `L mod 16 = 0` constant |
| AES-GCM-16 | 8 | 4 | 16 | `L mod 4 = 0`, spread over `{0,4,8,12} mod 16` |
| 3DES + HMAC-96 | 8 | 8 | 12 | `L mod 8 = 4` |
| ESP-NULL | 0 | 4 | 12–32 | trailer (pad 1..n, pad length, next header) readable |

Features used:
- histograms of `L mod 16` and `L mod 8`
- the fraction of packets consistent with each of 8 (IV, ICV, block) hypotheses
- a NULL-trailer probe
- entropy of the first 48 bytes
- length percentiles and the fraction of small packets, which captures the extra 20/40-byte inner IP header of **tunnel mode**
- NAT-T and IP version
- a configuration-consistency prior: the ICV length of the IKE SA integrity transform (cleartext)

### 4.2 Traffic-shape features (per 30-second window)
- **Size statistics:** mean, standard deviation and percentiles, bucket fractions, share of the most common size, uniqueness.
- **Direction asymmetry:** per-direction packet and byte shares and size statistics.
- **Timing:** inter-arrival time statistics, including 20 ms periodicity for RTP.
- **Bursts:** burst rate, packets per burst, bytes per burst, longest run of MTU-sized packets, activity ratio.

Window predictions are averaged to give the tunnel-level prediction and are also shown as a timeline.

### 4.3 Models and evaluation
The models are scikit-learn RandomForest classifiers (300 trees, class-balanced). They are evaluated with **GroupShuffleSplit by capture**, so windows from the same capture never appear in both training and test data. After evaluation the final models are re-fitted on all data. Metrics, confusion matrices and feature importances are stored in `models/metrics.json` and shown on the dashboard.

### 4.4 Rule-based inference (deterministic, 99% confidence)
The following are read directly from cleartext protocol fields:
- IKE version and exchange mode
- negotiated IKE transforms and DH group (the KE payload group and its length)
- IKEv1 lifetime and authentication method
- vendor fingerprint
- cleartext identities (IKEv1 Aggressive Mode)
- NAT-T
- AH mode (from the AH Next Header)
- ESP-NULL mode (from the trailer Next Header)
- SPIs, sequence-number replay and reordering
- Child SA lifetime (from the SPI rotation interval)

**PFS** is inferred from the encrypted length of CREATE_CHILD_SA or Quick Mode messages: a KE payload adds 32 to 512 bytes, which reveals both that PFS is on and the likely DH group.

### 4.5 Confidence model
Every attribute carries `{value, confidence, method, evidence}`. Rule-derived attributes are given 0.99. AI attributes use the classifier's class probability. The AES key length is not observable from ciphertext, so it is taken from the IKE SA proposal and marked with reduced confidence. The **AI Confidence Score** is the mean attribute confidence.

## 5. Security assessment
| Category | Weight | Basis |
|---|---|---|
| Cryptographic strength | 22 | ESP and IKE cipher (GCM-256 = 100 … 3DES = 30, NULL/AH-only = 0) |
| Integrity & authentication | 13 | ICV class, IKE PRF (MD5 20, SHA-1 60, SHA-2 100) |
| Key exchange | 15 | DH strength per NIST SP 800-57 (≥128-bit = 100, MODP-2048 = 85, MODP-1024 = 20) |
| Forward secrecy | 10 | PFS present, and its group strength |
| Key lifetime / SA management | 8 | Child SA rotation, IKEv1 LifeDuration |
| Replay protection | 10 | Duplicate (SPI, seq), reordering |
| Protocol & configuration compliance | 12 | IKEv2 vs IKEv1, Aggressive Mode |
| Metadata exposure | 10 | Identity leaks, fingerprinting, DNS leaks, transport-mode endpoint exposure, Vendor IDs |

Scores are capped when severe findings exist: any Critical finding caps the score at 40, two or more High at 60, and one High at 72. Grades are A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 55, F otherwise. **Risk score = 100 − security score.** Risk level is Critical ≥ 60, High ≥ 40, Moderate ≥ 20, Low otherwise.

Each finding carries: ID, severity, evidence, recommendation (including strongSwan syntax), likelihood and impact on a 1–5 scale (these place it in the **threat matrix**), STRIDE category, MITRE ATT&CK technique and references.

Compliance checks cover NIST SP 800-77r1 (6), RFC 8221 (2), RFC 8247 (2) and CNSA/Suite B (3).

## 6. Limitations (stated honestly)
- **The training data is synthetic.** Real-world accuracy, especially for traffic classification, will be lower. Retrain on captures from the strongSwan lab (`testbed/`) or from production before operational use.
- **Some ICV lengths cannot be told apart.** HMAC-SHA2-256-128 and SHA2-512-256 cannot always be distinguished. This ambiguity also affects tunnel-vs-transport inference, and the system reports it through reduced confidence.
- **AES key size cannot be observed** from ESP ciphertext. It is inferred from the IKE SA proposal.
- **PFS and lifetime need a rekey in the capture.** Otherwise they are reported as *undetermined* or as a lower bound.
- **Multiple applications in one tunnel** are reported per 30-second window, not per flow.
- **IKEv2 lifetimes are not negotiated on the wire**, so they can only be observed through rekeys.

## 7. Performance
A capture of about 2,000 packets is analysed in about 0.2 s after the one-time model load. The reader streams packets and is capped at 2 million packets (`MAX_PACKETS`). Analysis runs on a bounded worker pool (`ANALYSIS_WORKERS`).

## 8. Retraining
```bash
cd backend
python -m ml.build_dataset --n 700 --workers 8 --out ../dataset   # add --keep-pcaps to keep captures
python -m ml.train --data ../dataset --out models                  # writes bundle + MANIFEST.sha256 + metrics.json
```
