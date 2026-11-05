#!/bin/bash
# Iterate every profile x traffic type: bring up the lab, capture the WAN with tcpdump,
# generate traffic, tear down. Output: captures/<profile>_<traffic>.pcap + labels.csv
set -euo pipefail
cd "$(dirname "$0")/.."
DURATION=${DURATION:-120}
mkdir -p captures
echo "profile,traffic,file" > captures/labels.csv
for P in $(ls profiles); do
  for T in voip whatsapp email web icmp video; do
    export PROFILE=$P
    docker compose up -d --force-recreate
    sleep 3
    V=ipv4; [[ $P == ipv6* ]] && V=ipv6
    docker compose exec -d tap tcpdump -i eth0 -s 0 -w /captures/${P}_${T}.pcap 'udp port 500 or udp port 4500 or esp or ah or port 53'
    docker compose exec gw-a swanctl --load-all
    docker compose exec gw-b swanctl --load-all
    docker compose exec gw-a swanctl --initiate --child net || true
    docker compose exec host-a /scripts/traffic.sh $T $DURATION $V || true
    docker compose exec tap pkill tcpdump || true
    echo "$P,$T,${P}_${T}.pcap" >> captures/labels.csv
    docker compose down
  done
done
echo "Captures in testbed/captures/ — upload them in the dashboard or run: cd backend && python -m app.cli analyze <pcap> --pdf report.pdf"
