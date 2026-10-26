"""A1 landscape scientific poster from actual evaluation and UI evidence."""
import json
from pathlib import Path
from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor, white
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import Paragraph
from reportlab.lib.utils import ImageReader

NAVY = HexColor("#102239")
INK = HexColor("#20364c")
TEAL = HexColor("#087d89")
MUTED = HexColor("#516579")
PALE = HexColor("#edf5f7")


def main(output="output/pdf/sentinelwifi_A1.pdf"):
    target = Path(output)
    target.parent.mkdir(parents=True, exist_ok=True)
    metric_path = Path("reports/evaluation.json")
    metadata = json.loads(metric_path.read_text(encoding="utf-8")) if metric_path.exists() else None
    evidence = Path("reports/screenshots/overview.jpg")
    draft = metadata is None or not evidence.exists()
    width, height = 841*mm, 594*mm
    pdf = canvas.Canvas(str(target), pagesize=(width, height), pageCompression=1)
    pdf.setTitle("SentinelWiFi - Machine Learning-Based Wireless Intrusion Detection System")
    pdf.setAuthor("Student details pending")

    def text(body, x, y, w, size=22, color=INK, bold=False, leading=None):
        paragraph = Paragraph(body, ParagraphStyle("poster", fontName="Helvetica-Bold" if bold else "Helvetica", fontSize=size,
                              leading=leading or size*1.38, textColor=color, spaceAfter=0))
        _, h = paragraph.wrap(w, height)
        if y-h < 40:
            raise ValueError(f"Poster overflow: {body[:60]}")
        paragraph.drawOn(pdf, x, y-h)
        return y-h-18

    def section(title, x, y, w):
        pdf.setFillColor(TEAL)
        pdf.rect(x, y-9, 6, 30, fill=1, stroke=0)
        return text(title, x+20, y+20, w-20, 27, NAVY, True)-8

    def image(path, x, y, w, h):
        reader = ImageReader(str(path))
        iw, ih = reader.getSize()
        scale = min(w/iw, h/ih)
        actual_w, actual_h = iw*scale, ih*scale
        pdf.drawImage(reader, x+(w-actual_w)/2, y-actual_h, actual_w, actual_h, mask="auto")
        return y-actual_h-20

    margin, gap = 60, 40
    colw = (width-2*margin-2*gap)/3
    xs = [margin+i*(colw+gap) for i in range(3)]
    pdf.setFillColor(white)
    pdf.rect(0, 0, width, height, fill=1, stroke=0)
    pdf.setFillColor(NAVY)
    pdf.rect(0, height-250, width, 250, fill=1, stroke=0)
    text("SENTINELWIFI  /  PASSIVE WIRELESS SECURITY RESEARCH", margin, height-24, width-120, 18, HexColor("#67dde0"), True)
    text("Machine Learning-Based Wireless<br/>Intrusion Detection System", margin, height-64, width-120, 51, white, True, 59)
    text("Detection of Deauthentication Flood Attacks Using Random Forest", margin, height-194, width-120, 27, HexColor("#a9dce2"))
    text("Student: [Name]    |    Registration: [Number]    |    Institution: [Institution]    |    Lecturer: [Name]", margin, height-267, width-120, 20, MUTED)
    top = height-335

    # Column one: problem, methodology and reproducibility.
    x, y = xs[0], top
    y = section("01  Introduction & problem", x, y, colw)
    y = text("Wi-Fi management messages control connection state. Concentrated deauthentication traffic can disrupt availability. Passive monitoring can expose abnormal frame rates without decrypting user payloads or transmitting attack traffic.", x, y, colw)
    y -= 12
    y = section("02  Objectives", x, y, colw)
    y = text("Identify IEEE 802.11 frames; extract meaningful rolling features; classify normal and malicious observations; detect floods; persist explainable alerts; evaluate on held-out labels.", x, y, colw)
    y -= 12
    y = section("03  Methodology", x, y, colw)
    y = text("<b>Data:</b> The WPA3 Dataset, Deauth subset (MIT). 122,306 publisher-labeled packets: 116,799 Normal and 5,507 Deauth. AWID3 access has been requested.<br/><br/><b>Processing:</b> Stream CSV chunks through the same metadata and rolling-feature representation used for PCAP inference. Group by observed transmitter/BSSID; never train on MAC identifiers.<br/><br/><b>Evaluation:</b> Purged 60-second blocks; fixed seed-42 grouped holdout; train-only imputation. 3,484 training and 2,802 test windows. One recording, not independent sessions.", x, y, colw)
    y -= 12
    y = section("04  Detection features", x, y, colw)
    y = text("18 extracted measurements; <b>16 verified classifier inputs</b>: frame/deauth rates, subtypes, retry ratios, destination diversity, mean size, signal coverage and reason codes. RSSI mean/variability remain analysis-only because antenna selection differs.<br/><br/>Default rule: <b>10 deauth/s over 5 seconds</b>; 30-second cooldown. Tune for the environment.", x, y, colw)

    # Column two: clear vector architecture and real screenshot.
    x, y = xs[1], top
    y = section("05  System architecture", x, y, colw)
    boxes = [("Wireless PCAP / authorized live capture", "Scapy: raw 802.11 metadata"),
             ("Rolling windows & canonical features", "5-second window / 1-second step"),
             ("Complementary detection engine", "Rate rule + compatible Random Forest"),
             ("SQLite alerts & observations", "Evidence, source, severity and status"),
             ("Streamlit dashboard & exports", "Monitor, investigate and report")]
    for i, (title, subtitle) in enumerate(boxes):
        pdf.setFillColor(PALE)
        pdf.setStrokeColor(HexColor("#c9dce2"))
        pdf.roundRect(x, y-78, colw, 78, 9, fill=1, stroke=1)
        text(title, x+18, y-12, colw-36, 22, NAVY, True)
        text(subtitle, x+18, y-43, colw-36, 18, MUTED)
        y -= 78
        if i != len(boxes)-1:
            pdf.setStrokeColor(TEAL)
            pdf.setLineWidth(2)
            pdf.line(x+colw/2, y, x+colw/2, y-20)
            pdf.line(x+colw/2, y-20, x+colw/2-6, y-14)
            pdf.line(x+colw/2, y-20, x+colw/2+6, y-14)
            y -= 26
    y = text("<b>Separate training path:</b> Labeled packet CSV → same features → purged train/test split → evaluation → saved pipeline. Training labels never enter inference.", x, y-18, colw, 20)
    y -= 8
    y = section("06  Working implementation", x, y, colw)
    if evidence.exists():
        y = image(evidence, x, y, colw, 325)
        y = text("Actual Streamlit application with persisted packet-derived evidence. Replay is synthetic software-test traffic; measured model results use genuine publisher-labeled packets.", x, y, colw, 18, MUTED)
    else:
        y = text("DRAFT: actual implementation screenshot pending. Run the application and capture reports/screenshots/overview.jpg.", x, y, colw, 22, MUTED)
    y = section("07  Conclusion", x, y-8, colw)
    y = text("The prototype connects real packet parsing, rolling detection, automatic SQLite incidents and an operational dashboard. Offline replay permits repeatable demonstrations without radio hardware. No WIPS enforcement is claimed.", x, y, colw, 21)

    # Column three: actual metrics and honest limitations.
    x, y = xs[2], top
    y = section("08  Measured ML results", x, y, colw)
    if metadata:
        metrics = metadata["metrics"]
        for i, (key, label) in enumerate([("accuracy", "Accuracy"), ("precision", "Precision"), ("recall", "Recall"), ("f1", "F1-score")]):
            xx = x+(i % 2)*(colw/2)
            yy = y-(i//2)*95
            text(f"{metrics[key]:.2%}", xx, yy, colw/2-20, 38, TEAL, True)
            text(label, xx, yy-51, colw/2-20, 20, MUTED)
        y -= 185
        y = text("<b>Held-out confusion matrix</b><br/>Rows: actual; columns: predicted. Normal then Malicious.", x, y, colw, 21)
        if Path("reports/confusion_matrix.png").exists():
            y = image("reports/confusion_matrix.png", x, y+5, colw, 285)
        cm = metrics["confusion_matrix"]
        y = text(f"{cm[0][1]} false positives; {cm[1][0]} false negatives in this holdout. False positives consume investigation time; missed attacks hide threats. These results do not establish performance on other networks.", x, y, colw, 21)
    else:
        y = text("DRAFT: genuine labeled evaluation pending. No accuracy, matrix or model performance is invented.", x, y, colw)
    y = section("09  Limitations & future work", x, y-8, colw)
    repeats = metadata.get("duplicate_test_features_seen_in_training", 0) if metadata else 0
    y = text(f"<b>Evaluation:</b> Single recording; overlapping within-block observations. {repeats:,} test feature rows repeat training values, reducing independence.<br/><br/><b>Wireless:</b> MAC spoofing, packet loss, protected frame visibility and radio noise. Linux live capture needs monitor-mode hardware; not tested on this Windows host.<br/><br/><b>Next:</b> Independent captures, approved AWID3 comparison, false-positive tuning and approved AP integration. No packet injection.", x, y, colw, 20)
    y = section("10  References & disclosure", x, y-8, colw)
    y = text("[1] HSNG (2024), The WPA3 Dataset. github.com/hsngccu/WPA3-dataset, MIT. Revision e07113327e20.<br/>[2] Chatzoglou et al. (2021), AWID3. IEEE Access 9. DOI: 10.1109/ACCESS.2021.3061609.<br/>[3] Scapy Dot11 and Scikit-learn documentation.<br/><br/>OpenAI Codex assisted implementation, tests and documentation. Student review and demonstration remain required.", x, y, colw, 17, MUTED)

    pdf.setStrokeColor(HexColor("#cedce2"))
    pdf.line(margin, 53, width-margin, 53)
    pdf.setFillColor(MUTED)
    pdf.setFont("Helvetica", 15)
    pdf.drawString(margin, 25, "SENTINELWIFI  |  PASSIVE INSPECTION ONLY  |  A1 LANDSCAPE 841 x 594 mm" + ("  |  DRAFT: missing evidence/results" if draft else "  |  Student identity fields pending"))
    pdf.showPage()
    pdf.save()
    print(target.resolve())


if __name__ == "__main__":
    main()
