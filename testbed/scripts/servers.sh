#!/bin/sh
# Lightweight application servers on host-b for traffic generation.
python3 -m http.server 8080 >/dev/null 2>&1 &
iperf3 -s -D >/dev/null 2>&1
socat TCP-LISTEN:5222,fork,reuseaddr SYSTEM:'cat' >/dev/null 2>&1 &   # chat echo (WhatsApp-like)
socat TCP-LISTEN:587,fork,reuseaddr SYSTEM:'cat' >/dev/null 2>&1 &    # SMTP-like sink
socat UDP-LISTEN:5004,fork,reuseaddr SYSTEM:'cat' >/dev/null 2>&1 &   # RTP echo
