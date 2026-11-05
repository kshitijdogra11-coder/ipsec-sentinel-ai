# Demonstration Video Script (≈ 5 minutes)

| Time | Screen | Narration |
|---|---|---|
| 0:00 | Title slide / login page | "IPsec Sentinel AI assesses VPN security from encrypted traffic alone. It needs no keys and does not decrypt anything." |
| 0:20 | Login | "The console is hardened: Argon2id passwords, short-lived signed tokens in HttpOnly cookies, lockout after 5 failures, role-based access." |
| 0:40 | VPN Testbed | "Part (a): the testbed establishes IPsec VPNs across the full matrix: tunnel or transport, AES-128 or AES-256, GCM or CBC+HMAC, DH groups, PFS, IPv4 or IPv6, and six application types. Let's build a legacy IKEv1 Aggressive Mode VPN carrying VoIP and inject a replay attack." → select `insecure-aggressive-psk`, voip, replay → Generate. |
| 1:10 | Analysis → Overview | "Part (e): the score is 35, grade F, critical risk. The AI confidence score and the category radar show where the weaknesses are." |
| 1:30 | Protocol Identification | "Part (c): values read from cleartext fields are marked 99%. Values the AI infers from ciphertext side channels are marked as AI inference: 3DES from 8-byte block arithmetic, tunnel mode from the inner-header overhead, and VoIP from 20 ms periodicity. Each has a probability distribution." |
| 2:00 | IKE Negotiation | "The IKE timeline shows Aggressive Mode leaking the identity in cleartext and the PSK hash, which can be cracked offline. Vendor IDs fingerprint strongSwan." |
| 2:20 | Security Associations | "SPI inventory with the replay verdict: 12 packets re-used (SPI, sequence) pairs. The Child SA lifetime is measured from SPI rotation, and PFS is inferred from the size of the encrypted rekey message." |
| 2:45 | Traffic & Metadata | "Even through encryption, the AI classifies the application. This is metadata exposure, alongside DNS leaking outside the tunnel." |
| 3:05 | Threat Matrix & Findings | "Part (d): likelihood × impact matrix with STRIDE and ATT&CK mapping. Each finding carries evidence and a concrete strongSwan fix." |
| 3:25 | Compliance | "NIST SP 800-77r1, RFC 8221, RFC 8247 and CNSA checks." |
| 3:40 | Ground Truth vs AI | "Because the testbed knows the configured values, we can check every inferred attribute against them." |
| 3:55 | Download Executive and Technical PDFs | "Reports are HMAC-signed and bound to the evidence by SHA-256." |
| 4:10 | Analyze Captures → upload `01_cnsa-suite-b_video.pcap` | "The same pipeline handles real Wireshark or tcpdump captures. A CNSA-grade tunnel scores 96, grade A." |
| 4:30 | AI Engine & Dataset | "Four RandomForest models, evaluated on a grouped hold-out: 98.5% cipher, 97% mode, 99.8% traffic. 700 labelled captures are shipped." |
| 4:45 | Users & Audit → Verify hash chain | "Evidence is AES-256-GCM encrypted at rest, and every action goes into a hash-chained, tamper-evident audit log." |
| 5:00 | Architecture slide | "Working prototype, AI engine, dashboard, reports, dataset and a real strongSwan lab: all in the repository." |

Recording tip: run `./run.sh`, record at 1440×900 with OBS, and upload the 10 files from `dataset/samples/` first so the dashboard is populated.
