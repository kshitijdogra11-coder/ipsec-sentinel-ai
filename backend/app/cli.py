"""Command-line interface.

  python -m app.cli analyze capture.pcap [--json out.json] [--pdf report.pdf]
  python -m app.cli generate --preset cnsa-suite-b --traffic voip --out lab.pcap
"""
from __future__ import annotations

import argparse
import hashlib
import json

from .analyzer.pipeline import analyze_file
from .testbed import generator


def main():
    ap = argparse.ArgumentParser(prog="ipsec-sentinel")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze")
    a.add_argument("pcap")
    a.add_argument("--json")
    a.add_argument("--pdf")
    a.add_argument("--kind", default="Technical", choices=["Executive", "Technical"])
    g = sub.add_parser("generate")
    g.add_argument("--preset", default="enterprise-default", choices=list(generator.PRESETS))
    g.add_argument("--traffic", default="web", choices=["voip", "whatsapp", "email", "web", "icmp", "video"])
    g.add_argument("--duration", type=float, default=120)
    g.add_argument("--out", required=True)
    args = ap.parse_args()

    if args.cmd == "generate":
        truth = generator.generate_capture(generator.preset(args.preset, traffic=args.traffic, duration=args.duration), args.out)
        print(json.dumps(truth, indent=2, default=str))
        return
    r = analyze_file(args.pcap)
    a_ = r["assessment"]
    print(f"\nCapture  : {r['capture']['filename']}  ({r['capture']['packets']} pkts, {r['capture']['duration_s']} s)")
    print(f"Score    : {a_.get('score')} / 100   grade {a_.get('grade')}   risk {a_.get('risk_level')}")
    for t in r["tunnels"]:
        print(f"\nTunnel {t['id']}  [{t['protocol']}]")
        for k, v in t["identification"].items():
            val = v.get("value")
            print(f"  {k:24s} {str(val):40s} {v.get('confidence', 0):5.0%}  {v.get('method', '')}")
    for ta in a_.get("tunnels", []):
        print("\nFindings:")
        for f in ta["findings"]:
            print(f"  [{f['severity']:8s}] {f['id']}  {f['title']}")
    blob = json.dumps(r, default=str, indent=2)
    if args.json:
        open(args.json, "w").write(blob)
    if args.pdf:
        from .reports.pdf_report import build_report
        sha = hashlib.sha256(blob.encode()).hexdigest()
        open(args.pdf, "wb").write(build_report(args.kind, r, {"id": "cli", "owner": "cli"}, "unsigned (CLI)", sha))
        print(f"\nReport written to {args.pdf}")


if __name__ == "__main__":
    main()
