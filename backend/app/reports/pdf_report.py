"""Executive and Technical PDF report generation (ReportLab)."""
from __future__ import annotations

import io
from datetime import datetime, timezone

from reportlab.graphics.shapes import Circle, Drawing, Rect, String, Wedge
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)
from xml.sax.saxutils import escape

INK = colors.HexColor("#0f172a")
MUTED = colors.HexColor("#64748b")
ACCENT = colors.HexColor("#0891b2")
LINE = colors.HexColor("#e2e8f0")
SEV_COLORS = {"Critical": colors.HexColor("#b91c1c"), "High": colors.HexColor("#ea580c"),
              "Medium": colors.HexColor("#ca8a04"), "Low": colors.HexColor("#2563eb"), "Info": colors.HexColor("#64748b")}
GRADE_COLORS = {"A": "#15803d", "B": "#4d7c0f", "C": "#ca8a04", "D": "#ea580c", "F": "#b91c1c"}

LABELS = {
    "ipsec_protocol": "IPsec protocol", "ike_version": "IKE version", "ip_version": "IP version",
    "nat_traversal": "NAT traversal", "mode": "Operating mode", "encryption": "ESP encryption",
    "integrity": "Integrity / authentication", "key_exchange": "Key exchange", "ike_encryption": "IKE SA encryption",
    "ike_integrity": "IKE SA PRF / integrity", "exchange_mode": "Exchange mode", "authentication": "Peer authentication",
    "pfs": "Perfect Forward Secrecy", "child_lifetime": "Child SA lifetime (s)",
    "security_associations": "Security Associations", "traffic_type": "Traffic inside ESP",
}

ss = getSampleStyleSheet()
H1 = ParagraphStyle("H1", parent=ss["Heading1"], fontSize=18, textColor=INK, spaceAfter=6, spaceBefore=4)
H2 = ParagraphStyle("H2", parent=ss["Heading2"], fontSize=13, textColor=ACCENT, spaceBefore=10, spaceAfter=4)
H3 = ParagraphStyle("H3", parent=ss["Heading3"], fontSize=10.5, textColor=INK, spaceBefore=6, spaceAfter=2)
BODY = ParagraphStyle("B", parent=ss["BodyText"], fontSize=9.2, leading=12.5, textColor=INK)
SMALL = ParagraphStyle("S", parent=BODY, fontSize=7.8, leading=10, textColor=MUTED)
CELL = ParagraphStyle("C", parent=BODY, fontSize=7.8, leading=9.6)
CELLB = ParagraphStyle("CB", parent=CELL, fontName="Helvetica-Bold")


def P(t, st=BODY):
    return Paragraph(escape(str(t)), st)


def _table(rows, widths, header=True, zebra=True):
    data = [[c if not isinstance(c, str) else Paragraph(escape(c), CELLB if (header and i == 0) else CELL)
             for c in r] for i, r in enumerate(rows)]
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [("GRID", (0, 0), (-1, -1), 0.3, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9"))]
    if zebra:
        for i in range(1 + header, len(rows), 2):
            style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#fafafa")))
    t.setStyle(TableStyle(style))
    return t


def _gauge(score, grade, risk_level):
    d = Drawing(170, 110)
    d.add(Wedge(85, 20, 70, 0, 180, fillColor=colors.HexColor("#e2e8f0"), strokeColor=None))
    s = max(0, min(100, score or 0))
    col = colors.HexColor(GRADE_COLORS.get(grade, "#64748b"))
    d.add(Wedge(85, 20, 70, 180 - 180 * s / 100, 180, fillColor=col, strokeColor=None))
    d.add(Circle(85, 20, 48, fillColor=colors.white, strokeColor=None))
    d.add(String(85, 34, f"{s:.0f}", fontSize=26, fontName="Helvetica-Bold", textAnchor="middle", fillColor=INK))
    d.add(String(85, 20, "/ 100", fontSize=8, textAnchor="middle", fillColor=MUTED))
    d.add(String(85, 2, f"Grade {grade} · {risk_level} risk", fontSize=9, fontName="Helvetica-Bold",
                 textAnchor="middle", fillColor=col))
    return d


def _bars(cats: dict):
    w, rowh = 440, 16
    d = Drawing(w, rowh * len(cats) + 6)
    for i, (k, v) in enumerate(cats.items()):
        y = (len(cats) - 1 - i) * rowh + 3
        d.add(String(0, y + 3, k, fontSize=7.5, fillColor=INK))
        d.add(Rect(170, y, 230, 10, fillColor=colors.HexColor("#f1f5f9"), strokeColor=None))
        col = "#15803d" if v >= 85 else "#ca8a04" if v >= 60 else "#b91c1c"
        d.add(Rect(170, y, 230 * v / 100, 10, fillColor=colors.HexColor(col), strokeColor=None))
        d.add(String(406, y + 2, f"{v:.0f}", fontSize=7.5, fillColor=INK))
    return d


def _matrix(tm, findings):
    sev = {f["id"]: f["severity"] for f in findings}
    cell = 62
    d = Drawing(cell * 5 + 60, cell * 5 + 40)
    heat = ["#dcfce7", "#fef9c3", "#fed7aa", "#fecaca", "#fca5a5"]
    for imp in range(5):
        for lik in range(5):
            x, y = 40 + lik * cell, 25 + imp * cell
            lvl = min(4, (imp + lik) // 2)
            d.add(Rect(x, y, cell - 2, cell - 2, fillColor=colors.HexColor(heat[lvl]), strokeColor=colors.white))
            ids = tm["grid"][imp][lik]
            for k, fid in enumerate(ids[:4]):
                d.add(String(x + 4, y + cell - 14 - k * 11, fid, fontSize=7, fontName="Helvetica-Bold",
                             fillColor=SEV_COLORS.get(sev.get(fid, "Info"), INK)))
            if len(ids) > 4:
                d.add(String(x + 4, y + 4, f"+{len(ids) - 4}", fontSize=7, fillColor=INK))
    for i in range(5):
        d.add(String(40 + i * cell + cell / 2 - 3, 12, str(i + 1), fontSize=8, fillColor=MUTED))
        d.add(String(28, 25 + i * cell + cell / 2 - 3, str(i + 1), fontSize=8, fillColor=MUTED))
    d.add(String(40 + cell * 2.5, 0, "Likelihood →", fontSize=8, textAnchor="middle", fillColor=INK))
    d.add(String(2, 25 + cell * 5 + 4, "Impact ↑", fontSize=8, fillColor=INK))
    return d


class _Doc:
    def __init__(self, kind, analysis_meta, signature, result_sha):
        self.kind, self.meta, self.sig, self.sha = kind, analysis_meta, signature, result_sha

    def on_page(self, canvas, doc):
        canvas.saveState()
        canvas.setFillColor(ACCENT)
        canvas.rect(0, A4[1] - 8 * mm, A4[0], 8 * mm, stroke=0, fill=1)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 8.5)
        canvas.drawString(15 * mm, A4[1] - 5.4 * mm, f"IPsec Sentinel AI — {self.kind} Report")
        canvas.drawRightString(A4[0] - 15 * mm, A4[1] - 5.4 * mm, "CONFIDENTIAL — Security Assessment")
        canvas.setFillColor(MUTED)
        canvas.setFont("Helvetica", 6.5)
        canvas.drawString(15 * mm, 8 * mm, f"Report ID {self.meta['id']} · result SHA-256 {self.sha[:32]}…")
        canvas.drawString(15 * mm, 5 * mm, f"HMAC-SHA256 signature {self.sig}")
        canvas.drawRightString(A4[0] - 15 * mm, 8 * mm, f"Page {doc.page}")
        canvas.restoreState()


def _cover(story, kind, r, meta):
    a = r["assessment"]
    cap = r["capture"]
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(f"{kind} Security Assessment Report", H1))
    story.append(P(f"IPsec VPN deployment analysis · generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}", SMALL))
    story.append(Spacer(1, 4 * mm))
    sha = cap["sha256"]
    info = _table([
        ["Capture", cap["filename"]], ["SHA-256 (evidence)", sha[:32] + " " + sha[32:]],
        ["Packets / duration", f"{cap['packets']:,} packets · {cap['duration_s']} s"],
        ["Tunnels identified", str(len(r["tunnels"]))], ["Analyst", meta.get("owner", "-")],
        ["AI model", f"{r['model'].get('version', '-')} ({r['model'].get('status')})"],
    ], [40 * mm, 125 * mm], header=False)
    g = _gauge(a.get("score") or 0, a.get("grade", "?"), a.get("risk_level", "?"))
    story.append(Table([[g, info]], colWidths=[62 * mm, 120 * mm], style=[("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))


def build_report(kind: str, result: dict, meta: dict, signature: str, result_sha: str) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=14 * mm,
                            bottomMargin=14 * mm, title=f"IPsec Sentinel {kind} Report", author="IPsec Sentinel AI",
                            subject=result["capture"]["filename"])
    story: list = []
    a = result["assessment"]
    _cover(story, kind, result, meta)
    if a.get("score") is None:
        story.append(P(a.get("summary", "No IPsec traffic found.")))
        d = _Doc(kind, meta, signature, result_sha)
        doc.build(story, onFirstPage=d.on_page, onLaterPages=d.on_page)
        return buf.getvalue()
    ta = next(x for x in a["tunnels"] if x["score"] == a["score"])
    tun = next(t for t in result["tunnels"] if t["id"] == ta["tunnel"])
    story.append(Paragraph("Executive Summary", H2))
    story.append(P(a["summary"]))
    sc = ta["severity_counts"]
    story.append(Spacer(1, 3 * mm))
    kpi = [["Security score", "Risk score", "AI confidence", "Critical", "High", "Medium", "Low"],
           [f"{ta['score']}", f"{ta['risk_score']} ({ta['risk_level']})", f"{ta['ai_confidence']['overall']:.0%}",
            str(sc["Critical"]), str(sc["High"]), str(sc["Medium"]), str(sc["Low"])]]
    story.append(_table(kpi, [28 * mm, 32 * mm, 26 * mm, 18 * mm, 18 * mm, 18 * mm, 18 * mm], zebra=False))
    story.append(Paragraph("Security posture by category", H2))
    story.append(_bars(ta["category_scores"]))

    ident = tun["identification"]
    story.append(Paragraph("Protocol identification (AI + protocol dissection)", H2))
    rows = [["Attribute", "Identified value", "Confidence", "Method"]]
    for k, v in ident.items():
        if isinstance(v, dict) and "value" in v:
            val = v["value"]
            val = "Yes" if val is True else "No" if val is False else ("undetermined" if val is None else val)
            rows.append([LABELS.get(k, k.replace("_", " ").title()), str(val), f"{v['confidence']:.0%}", v["method"]])
    story.append(_table(rows, [34 * mm, 58 * mm, 20 * mm, 68 * mm]))

    story.append(Paragraph("Key findings", H2))
    fl = [f for f in ta["findings"] if f["severity"] != "Info"]
    rows = [["ID", "Severity", "Finding", "Recommendation"]]
    for f in (fl if kind == "Technical" else fl[:8]):
        rows.append([f["id"], f["severity"], f["title"], f["recommendation"]])
    if len(rows) == 1:
        rows.append(["-", "-", "No significant weaknesses found", "Maintain current configuration and monitoring"])
    t = _table(rows, [16 * mm, 17 * mm, 58 * mm, 89 * mm])
    for i, f in enumerate(fl[: len(rows) - 1], start=1):
        t.setStyle(TableStyle([("TEXTCOLOR", (1, i), (1, i), SEV_COLORS[f["severity"]])]))
    story.append(t)

    story.append(KeepTogether([Paragraph("Threat matrix (likelihood × impact)", H2), _matrix(ta["threat_matrix"], ta["findings"])]))

    if kind == "Executive":
        story.append(Paragraph("Compliance overview", H2))
        comp = ta["compliance"]
        by: dict[str, list] = {}
        for c in comp:
            by.setdefault(c["framework"], []).append(c["status"])
        rows = [["Framework", "Pass", "Fail", "Unknown"]] + [[k, str(v.count("pass")), str(v.count("fail")),
                                                              str(v.count("unknown"))] for k, v in by.items()]
        story.append(_table(rows, [70 * mm, 30 * mm, 30 * mm, 30 * mm]))
    else:
        story.append(PageBreak())
        story.append(Paragraph("Technical detail", H1))
        ike = tun["ike"]
        story.append(Paragraph("IKE negotiation", H2))
        if ike.get("present"):
            neg = ike["negotiated"]
            story.append(_table([
                ["Parameter", "Value"], ["Version / exchange", f"IKEv{ike['version']} · {ike['exchange_mode']}"],
                ["Initiator → Responder", f"{ike['initiator']} → {ike['responder']}"],
                ["Encryption", f"{neg.get('encr')} {neg.get('key_len') or ''}"], ["PRF", str(neg.get("prf"))],
                ["Integrity", str(neg.get("integ") or "AEAD")], ["DH group", f"{neg.get('dh_id')} ({neg.get('dh')})"],
                ["Authentication", str(ike.get("auth_method", {}).get("value"))],
                ["Vendor IDs", ", ".join(ike.get("vendor_ids", [])) or "-"],
                ["Notifies", ", ".join(ike.get("notifies", [])) or "-"],
                ["Exchanges", ", ".join(f"{k}×{v}" for k, v in ike.get("exchanges", {}).items())],
                ["Offered proposals", str(len(ike.get("offered_proposals", [])))],
            ], [45 * mm, 135 * mm]))
            story.append(Paragraph("Message timeline", H3))
            rows = [["t (s)", "Exchange", "Dir", "Len", "Encrypted", "Payloads"]]
            for m in ike["timeline"][:30]:
                rows.append([f"{m['t']:.3f}", m["exchange"], m["dir"], str(m["length"]), "yes" if m["encrypted"] else "no",
                             ", ".join(m["payloads"])])
            story.append(_table(rows, [16 * mm, 30 * mm, 12 * mm, 12 * mm, 16 * mm, 94 * mm]))
        else:
            story.append(P("No IKE negotiation present in the capture."))
        story.append(Paragraph("Security Associations", H2))
        rows = [["SPI", "Direction", "Packets", "Bytes", "Seq range", "Dup", "Reorder", "Active (s)"]]
        for s in tun["sas"][:40]:
            rows.append([s["spi"], f"{s['src']} → {s['dst']}", str(s["packets"]), f"{s['bytes']:,}",
                         f"{s['seq_first']}–{s['seq_last']}", str(s["duplicates"]), str(s["reordered"]),
                         f"{s['first_seen']}–{s['last_seen']}"])
        story.append(_table(rows, [20 * mm, 50 * mm, 14 * mm, 20 * mm, 22 * mm, 10 * mm, 14 * mm, 30 * mm]))
        story.append(P(f"Replay analysis: {tun['replay']['verdict']} (duplicates={tun['replay']['duplicates']}, "
                       f"reordered={tun['replay']['reordered']}).", SMALL))
        story.append(Paragraph("Traffic analysis & metadata inference", H2))
        tp = tun["traffic"]["prediction"]
        story.append(P(f"Predicted application class: {tp['label']} ({tp['confidence']:.0%}). Distribution: "
                       + ", ".join(f"{k} {v:.0%}" for k, v in tp.get("distribution", {}).items())))
        st = tun["stats"]
        story.append(P(f"{st['packets']:,} data-plane packets, {st['bytes']:,} bytes, average {st['avg_packet']} B, "
                       f"throughput {st['throughput_bps'] / 1000:.1f} kbit/s.", SMALL))
        rows = [["ID", "Exposure", "Level", "Detail", "Mitigation"]]
        for e in ta["metadata_exposure"]:
            rows.append([e["id"], e["title"], e["level"], e["detail"], e["mitigation"]])
        story.append(_table(rows, [13 * mm, 36 * mm, 14 * mm, 62 * mm, 55 * mm]))
        story.append(Paragraph("Compliance checks", H2))
        rows = [["Framework", "Control", "Status", "Observed"]]
        for c in ta["compliance"]:
            rows.append([c["framework"], c["control"], c["status"].upper(), c["observed"]])
        story.append(_table(rows, [34 * mm, 62 * mm, 20 * mm, 64 * mm]))
        story.append(Paragraph("Detailed findings", H2))
        for f in ta["findings"]:
            story.append(KeepTogether([
                Paragraph(f"<font color='{SEV_COLORS[f['severity']].hexval().replace('0x', '#')}'><b>[{f['severity']}]</b></font> "
                          f"{escape(f['id'])} — {escape(f['title'])}", H3),
                P(f"Evidence: {f['evidence']}", CELL), P(f"Recommendation: {f['recommendation']}", CELL),
                P(f"Likelihood {f['likelihood']}/5 · Impact {f['impact']}/5 · STRIDE: {f.get('stride') or '-'} · "
                  f"ATT&CK: {f.get('mitre_attack') or '-'} · Ref: {f.get('references') or '-'}", SMALL),
            ]))
        story.append(Paragraph("AI engine", H2))
        conf = ta["ai_confidence"]
        story.append(P(f"Model version {result['model'].get('version')} · integrity {result['model'].get('status')} · "
                       f"SHA-256 {str(result['model'].get('sha256', ''))[:32]}… · overall confidence "
                       f"{conf['overall']:.0%}. Attributes read from cleartext protocol fields are reported with 99% "
                       "confidence; AI-inferred attributes carry the classifier's calibrated class probability.", SMALL))
    story.append(Spacer(1, 6 * mm))
    story.append(P("Integrity: this report is bound to the analysis result by the SHA-256 digest and HMAC-SHA256 "
                   "signature printed in the footer; verify via GET /api/v1/reports/verify.", SMALL))
    d = _Doc(kind, meta, signature, result_sha)
    doc.build(story, onFirstPage=d.on_page, onLaterPages=d.on_page)
    return buf.getvalue()
