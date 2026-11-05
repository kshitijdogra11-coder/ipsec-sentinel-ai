# strongSwan IPsec Lab

This is a real two-site IPsec lab for producing field captures. It runs on Docker on Linux.

```bash
python3 gen_profiles.py                     # writes profiles/<name>/gw-{a,b}.swanctl.conf (12 profiles)
PROFILE=cnsa-suite-b docker compose up -d   # bring up one configuration
docker compose exec gw-a swanctl --initiate --child net
docker compose exec host-a /scripts/traffic.sh voip 120
DURATION=120 ./scripts/run_matrix.sh        # full matrix → captures/*.pcap + labels.csv
```

Profiles:
- cnsa-suite-b, enterprise-default, modern-ecp, aes128-cbc-nopfs
- host-to-host-transport, ipv6-tunnel, ipv6-transport, gcm-transport-pfs
- legacy-ikev1-main, insecure-aggressive-psk
- null-encryption, ah-integrity-only

Upload the resulting captures in the dashboard, or analyse them with `python -m app.cli analyze`.
The pre-shared key is lab-only. Override it with `LAB_PSK`.

If Docker is not available, the dashboard's **VPN Testbed** page uses the built-in generator. It produces the same configuration matrix with real ESP encryption.
