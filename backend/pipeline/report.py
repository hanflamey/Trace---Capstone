from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (PageBreak, Paragraph, SimpleDocTemplate, Spacer,
                                Table, TableStyle)

# TRACE palette, matching the dashboard.
ACCENT = colors.HexColor("#0088CC")
DARK   = colors.HexColor("#111820")
RED    = colors.HexColor("#FF4455")
AMBER  = colors.HexColor("#FFB020")
GREEN  = colors.HexColor("#22DD88")
LIGHT  = colors.HexColor("#F4F8FB")
BORDER = colors.HexColor("#CCCCCC")

SEVERITY_COLORS = {
    "CRITICAL": RED,
    "HIGH":     AMBER,
    "MEDIUM":   GREEN,
    "INFO":     colors.HexColor("#00C8FF"),
}


def _build_styles():
    """
    Create the paragraph styles used throughout the report.

    Defined once and passed down so every section renders consistently.
    """
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("TraceTitle", parent=styles["Title"],
                              textColor=ACCENT, fontSize=24, spaceAfter=4))
    styles.add(ParagraphStyle("TraceSubtitle", parent=styles["Normal"],
                              textColor=colors.grey, fontSize=9, spaceAfter=16))
    styles.add(ParagraphStyle("SectionHeading", parent=styles["Heading2"],
                              textColor=DARK, fontSize=13,
                              spaceBefore=14, spaceAfter=6))
    styles.add(ParagraphStyle("BodyText2", parent=styles["Normal"],
                              fontSize=9.5, leading=14))
    styles.add(ParagraphStyle("TableCell", parent=styles["Normal"],
                              fontSize=7.5, leading=10))
    styles.add(ParagraphStyle("MonoCell", parent=styles["Normal"],
                              fontSize=7, leading=9, fontName="Courier"))
    return styles


def _table_style(extra_commands=None):
    """
    Return the shared visual style applied to every table in the report.

    `extra_commands` adds table-specific styling (such as per-row severity
    colouring) on top of the shared base.
    """
    base = [
        ("BACKGROUND",     (0, 0), (-1, 0), DARK),
        ("TEXTCOLOR",      (0, 0), (-1, 0), colors.white),
        ("FONTNAME",       (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",       (0, 0), (-1, 0), 7.5),
        ("GRID",           (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN",         (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
        ("TOPPADDING",     (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 3),
    ]
    return TableStyle(base + (extra_commands or []))


def _executive_summary(findings, metadata, styles):
    """
    Build the opening paragraph describing the scope and outcome of the run.

    Explains both AI passes explicitly, including how many entries reached the
    second pass only because threat intelligence flagged them - that number
    shows the value of checking every hash rather than only AI-flagged ones.
    """
    critical = sum(1 for finding in findings if finding["severity"] == "CRITICAL")
    high = sum(1 for finding in findings if finding["severity"] == "HIGH")

    artifact_list = ", ".join(
        f"{count} {name}" for name, count in metadata.get("artifacts", {}).items()
    )
    executed = metadata.get("correlation", {}).get("execution_confirmed", 0)
    intel_only = metadata.get("intel_only_reviews", 0)

    text = (
        f"TRACE analysed <b>{metadata['total_entries']}</b> artifact entries "
        f"({artifact_list}). All <b>{metadata.get('hashes_checked', 0)}</b> unique "
        f"file hashes were checked against VirusTotal, MetaDefender and "
        f"AlienVault OTX.<br/><br/>"
        f"The local AI model flagged <b>{metadata.get('pass1_flagged', 0)}</b> "
        f"entries on metadata alone. A total of "
        f"<b>{metadata.get('pass2_reviewed', 0)}</b> entries then received a "
        f"full evidence review, of which <b>{intel_only}</b> were included "
        f"solely because threat intelligence reported detections the initial "
        f"assessment did not catch.<br/><br/>"
        f"<b>{metadata['flagged_count']}</b> findings were reported, of which "
        f"<b>{critical}</b> are CRITICAL and <b>{high}</b> are HIGH severity "
        f"and warrant immediate analyst review. Cross-artifact correlation "
        f"confirmed actual execution for <b>{executed}</b> unique executables. "
        f"Analysis completed in {metadata['processing_seconds']:.1f} seconds."
    )
    return Paragraph(text, styles["BodyText2"])


def _findings_table(findings, styles):
    """
    Build the main findings table, one row per flagged executable.

    Severity is colour-coded, and the reasoning column carries the AI's final
    justification so the report explains itself without a separate appendix.
    """
    table_rows = [["#", "Name", "Path", "Score", "Severity", "Ran",
                   "ATT&CK", "Reasoning"]]

    for number, finding in enumerate(findings, start=1):
        techniques = ", ".join(technique["id"]
                               for technique in finding.get("mitre", [])) or "-"
        table_rows.append([
            str(number),
            Paragraph(finding["name"], styles["TableCell"]),
            Paragraph(finding["full_path"], styles["MonoCell"]),
            f"{finding['risk_score']:.1f}",
            finding["severity"],
            "YES" if finding["execution_confirmed"] else "-",
            Paragraph(techniques, styles["TableCell"]),
            Paragraph(finding.get("justification", ""), styles["TableCell"]),
        ])

    severity_styling = [
        ("TEXTCOLOR", (4, index), (4, index),
         SEVERITY_COLORS.get(finding["severity"], colors.black))
        for index, finding in enumerate(findings, start=1)
    ] + [
        ("FONTNAME", (4, 1), (4, -1), "Helvetica-Bold"),
        ("ALIGN", (3, 0), (5, -1), "CENTER"),
    ]

    table = Table(table_rows, repeatRows=1,
                  colWidths=[0.22 * inch, 0.95 * inch, 1.5 * inch, 0.4 * inch,
                             0.6 * inch, 0.35 * inch, 0.7 * inch, 2.28 * inch])
    table.setStyle(_table_style(severity_styling))
    return table


def _execution_evidence(findings, styles):
    """
    Build the section showing what cross-artifact correlation established.

    Only includes findings corroborated by more than one artifact or with
    proven execution, since those are the ones where correlation added value.
    """
    corroborated = [
        finding for finding in findings
        if finding["execution_confirmed"] or len(finding["seen_in_sources"]) > 1
    ]

    if not corroborated:
        return [Paragraph(
            "No finding was corroborated across multiple artifacts. Upload "
            "Amcache, Prefetch and ShimCache together to enable cross-artifact "
            "execution correlation.", styles["BodyText2"])]

    table_rows = [["File", "Seen in", "Execution proven", "Run count"]]
    for finding in corroborated:
        table_rows.append([
            Paragraph(finding["name"], styles["TableCell"]),
            Paragraph(", ".join(finding["seen_in_sources"]) or "-",
                      styles["TableCell"]),
            "YES" if finding["execution_confirmed"] else "-",
            str(finding["run_count"] or "-"),
        ])

    table = Table(table_rows, repeatRows=1,
                  colWidths=[1.9 * inch, 2.4 * inch, 1.1 * inch, 0.9 * inch])
    table.setStyle(_table_style([("ALIGN", (2, 0), (3, -1), "CENTER")]))

    return [
        Paragraph(
            "Amcache proves a file was present. Prefetch and ShimCache prove "
            "it ran. The entries below were confirmed by more than one "
            "artifact.", styles["BodyText2"]),
        Spacer(1, 0.12 * inch),
        table,
    ]


def _ioc_table(findings, styles):
    """
    Build the indicators-of-compromise table.

    Lists only findings that carry a SHA-1, since those are the ones an analyst
    can share with other tools or use for blocking.
    """
    with_hashes = [finding for finding in findings if finding["sha1"]]

    if not with_hashes:
        return [Paragraph(
            "No file-hash indicators were associated with these findings. "
            "Only Amcache records file hashes.", styles["BodyText2"])]

    table_rows = [["File", "SHA-1", "VirusTotal", "Malware family"]]
    for finding in with_hashes:
        if finding.get("vt_checked") and finding.get("vt_total_engines"):
            detections = (f"{finding['vt_detections']}/"
                          f"{finding['vt_total_engines']}")
        else:
            detections = "-"

        table_rows.append([
            Paragraph(finding["name"], styles["TableCell"]),
            Paragraph(finding["sha1"], styles["MonoCell"]),
            detections,
            Paragraph(finding.get("vt_malware_family", "") or "-",
                      styles["TableCell"]),
        ])

    table = Table(table_rows, repeatRows=1,
                  colWidths=[1.4 * inch, 2.9 * inch, 0.8 * inch, 1.9 * inch])
    table.setStyle(_table_style([("ALIGN", (2, 0), (2, -1), "CENTER")]))
    return [table]


def _custody_table(metadata, styles):
    """
    Build the chain-of-custody table.

    Records case identity, what was analysed, how much of it reached each
    analysis stage, and how many invalid ATT&CK IDs were rejected - the last
    of which makes the MITRE validation layer auditable.
    """
    table_rows = [
        ["Field", "Value"],
        ["Case ID",            metadata.get("case_id", "-")],
        ["Examiner",           metadata.get("examiner", "-")],
        ["Acquisition method", metadata.get("acquisition",
                                            "Offline (dead) acquisition")],
        ["Image hash (MD5)",   metadata.get("md5", "<record at acquisition>")],
        ["Image hash (SHA-1)", metadata.get("sha1_image", "<record at acquisition>")],
        ["Artifacts analysed", ", ".join(
            f"{name} ({count} entries)"
            for name, count in metadata.get("artifacts", {}).items()) or "-"],
        ["Timestamps normalised to", "UTC (ISO-8601)"],
        ["Entries parsed",     str(metadata.get("total_entries", "-"))],
        ["Hashes checked",     str(metadata.get("hashes_checked", 0))],
        ["Flagged by AI pass 1", str(metadata.get("pass1_flagged", 0))],
        ["Given full evidence review", str(metadata.get("pass2_reviewed", 0))],
        ["Reviewed on threat intel alone",
         str(metadata.get("intel_only_reviews", 0))],
        ["Invalid ATT&CK IDs rejected",
         str(metadata.get("mitre_validation", {}).get("rejected_count", 0))],
        ["Report generated (UTC)", metadata.get("generated_utc", "-")],
        ["Report ID",          metadata.get("report_id", "-")],
    ]

    table = Table(table_rows, colWidths=[2.2 * inch, 4.8 * inch])
    table.setStyle(_table_style([
        ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("VALIGN",   (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return table


# Plain-English description of the pipeline, printed in every report so the
# methodology travels with the findings.
METHODOLOGY_TEXT = """
<b>1. Parsing.</b> CSV exports produced by Eric Zimmerman's forensic parsers
(AmcacheParser, PECmd, AppCompatCacheParser) are read by a dedicated parser
per artifact.<br/><br/>

<b>2. Normalisation.</b> Every timestamp is converted to UTC at parse time so
the execution timeline is consistent across all three sources.<br/><br/>

<b>3. Correlation.</b> Entries are indexed by executable name across all
artifacts. Amcache proves a file was present; Prefetch and ShimCache prove it
ran. This evidence is gathered before any scoring so it can inform the
analysis rather than merely adjust it afterwards.<br/><br/>

<b>4. Threat intelligence.</b> Every unique SHA-1 is checked against
VirusTotal, MetaDefender and AlienVault OTX. All hashes are checked, not only
those the AI found interesting - antivirus telemetry is factual evidence and
must not be gated behind a language model's first impression.<br/><br/>

<b>5. AI assessment (two passes).</b> A local LLM running entirely on the
analyst workstation first reviews each entry's metadata alone. Every entry that
either the model flagged, or that threat intelligence reported detections for,
then receives a second review with the antivirus results and execution evidence
supplied. The model produces the final score and reasoning. No artifact data
leaves the host.<br/><br/>

<b>6. MITRE ATT&amp;CK.</b> The model selects techniques from a fixed list of
execution-observable techniques supplied in its prompt, and every returned
technique ID is validated against the official ATT&amp;CK catalogue before it
can appear in this report.<br/><br/>

<b>7. Scoring.</b> The final score is the model's, with one safety rail: any
hash confirmed malicious by five or more independent antivirus engines can
never score below 8.0, regardless of the model's conclusion.
"""


def generate_report(findings, metadata, output_path):
    """
    Build the complete PDF report at `output_path`.

    `findings` must already be sorted by risk score. Returns the output path.
    """
    metadata.setdefault(
        "generated_utc",
        datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )

    styles = _build_styles()
    document = SimpleDocTemplate(
        output_path, pagesize=letter,
        topMargin=0.7 * inch, bottomMargin=0.7 * inch,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
        title="TRACE Forensic Report",
    )

    story = []

    # --- header ---------------------------------------------------------
    story.append(Paragraph("TRACE", styles["TraceTitle"]))
    story.append(Paragraph(
        "Threat Reconnaissance &amp; Artifact Correlation Engine &mdash; "
        "Forensic Triage Report", styles["TraceSubtitle"]))

    # --- 1. executive summary -------------------------------------------
    story.append(Paragraph("1. Executive Summary", styles["SectionHeading"]))
    story.append(_executive_summary(findings, metadata, styles))

    # --- 2. findings ----------------------------------------------------
    story.append(Paragraph("2. Findings", styles["SectionHeading"]))
    if findings:
        story.append(_findings_table(findings, styles))
    else:
        story.append(Paragraph("No suspicious entries were detected.",
                               styles["BodyText2"]))

    # --- 3. execution evidence ------------------------------------------
    story.append(PageBreak())
    story.append(Paragraph("3. Execution Evidence (Cross-Artifact Correlation)",
                           styles["SectionHeading"]))
    story.extend(_execution_evidence(findings, styles))

    # --- 4. indicators of compromise ------------------------------------
    story.append(Spacer(1, 0.25 * inch))
    story.append(Paragraph("4. Indicators of Compromise",
                           styles["SectionHeading"]))
    story.extend(_ioc_table(findings, styles))

    # --- 5. chain of custody --------------------------------------------
    story.append(PageBreak())
    story.append(Paragraph("5. Chain of Custody &amp; Acquisition",
                           styles["SectionHeading"]))
    story.append(_custody_table(metadata, styles))

    # --- 6. methodology -------------------------------------------------
    story.append(Spacer(1, 0.25 * inch))
    story.append(Paragraph("6. Methodology", styles["SectionHeading"]))
    story.append(Paragraph(METHODOLOGY_TEXT, styles["BodyText2"]))

    story.append(Spacer(1, 0.3 * inch))
    story.append(Paragraph(
        "<i>For authorised forensic use only. Acquisition and analysis "
        "performed in line with NIST SP 800-86. Amcache evidences program "
        "presence; execution is corroborated with Prefetch and ShimCache "
        "where available.</i>", styles["TraceSubtitle"]))

    document.build(story)
    return output_path
