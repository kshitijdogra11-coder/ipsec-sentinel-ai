#!/bin/sh
# Run on host-a:  /scripts/traffic.sh <voip|whatsapp|email|web|icmp|video> <seconds> [ipv4|ipv6]
T=${1:-web}; D=${2:-120}; V=${3:-ipv4}
DST=10.2.0.10; [ "$V" = ipv6 ] && DST=fd02::10
END=$(( $(date +%s) + D ))
case $T in
  icmp)  ping -c "$D" -i 1 -s 56 "$DST" ;;
  voip)  while [ $(date +%s) -lt $END ]; do   # 50 pps x 172 B RTP-like, 3-6 s calls
           timeout $(( 3 + RANDOM % 4 )) sh -c "while :; do head -c 172 /dev/urandom; sleep 0.02; done" | socat - UDP:$DST:5004 >/dev/null
           sleep $(( 8 + RANDOM % 12 )); done ;;
  video) iperf3 -c "$DST" -R -t "$D" -b 4M -l 1400 >/dev/null ;;
  web)   while [ $(date +%s) -lt $END ]; do for i in 1 2 3; do curl -s -o /dev/null "http://[$DST]:8080/" -g || curl -s -o /dev/null "http://$DST:8080/"; done; sleep $(( 2 + RANDOM % 10 )); done ;;
  email) while [ $(date +%s) -lt $END ]; do head -c $(( 3000 + RANDOM * 5 )) /dev/urandom | base64 | socat - TCP:$DST:587 >/dev/null; sleep $(( 8 + RANDOM % 15 )); done ;;
  whatsapp) while [ $(date +%s) -lt $END ]; do head -c $(( 90 + RANDOM % 330 )) /dev/urandom | socat - TCP:$DST:5222 >/dev/null; sleep $(( 2 + RANDOM % 8 )); done ;;
esac
