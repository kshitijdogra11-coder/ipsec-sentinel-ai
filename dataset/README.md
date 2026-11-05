# IPsec Sentinel Dataset

| File | Rows | Description |
|---|---|---|
| `labels.csv` | 700 | Ground-truth VPN configuration of each capture: IKE version/mode, IKE & ESP transforms, DH group, PFS, mode, IP version, NAT-T, traffic type, lifetimes, replay injection, packet counts |
| `crypto_features.csv` | 674 | 53 ESP side-channel features + labels `y_cipher`, `y_icv`, `y_mode` (ESP captures only; AH captures are identified deterministically) |
| `traffic_features.csv` | 2,836 | 49 traffic-shape features per 30 s window + label `y_traffic` |
| `samples/*.pcap` | 10 | Ready-to-analyse captures, one per preset (open them in Wireshark too) |

The dataset contains 913,873 packets in total. The configuration matrix covers:
- tunnel/transport mode, IPv4/IPv6, NAT-T
- AES-128/256-CBC with HMAC-SHA1/SHA2-256/SHA2-512/MD5, AES-GCM-128/256, 3DES, ESP-NULL, AH
- DH groups 1, 2, 5, 14, 15, 16, 19, 20, 21, 31, with PFS on or off
- IKEv1 Main and Aggressive Mode, and IKEv2
- 6 traffic classes: VoIP, WhatsApp, e-mail, web, ICMP, video
- replay attacks

To regenerate, or to keep the raw pcaps:
```bash
cd backend && python -m ml.build_dataset --n 700 --workers 8 --out ../dataset --keep-pcaps
```
Real captures from the strongSwan lab (`testbed/scripts/run_matrix.sh`) should be added for field validation.
